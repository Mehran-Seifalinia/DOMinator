from asyncio import Queue, gather, run
from aiohttp import ClientSession, ClientTimeout, ClientError
from json import dump
from time import time
from extractors.html_parser import ScriptExtractor
from extractors.event_handler_extractor import extract
from scanners.static_analyzer import analyze as static_analyze
from scanners.dynamic_analyzer import analyze as dynamic_analyze
from scanners.priority_manager import rank
from utils.logger import get_logger
from argparse import ArgumentParser
from sys import exit
from csv import DictWriter

# Set up logger
logger = get_logger(__name__)

# Parse command-line arguments
def parse_args():
    parser = ArgumentParser(description="DOM XSS Scanner Tool")
    parser.add_argument('-u', '--url', help='Target URL(s)', nargs='+')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of threads for parallel processing')
    parser.add_argument('-f', '--force', action='store_true', help='Force continue even if site is not reachable')
    parser.add_argument('-o', '--output', type=str, help='Output file for saving results')
    parser.add_argument('-l', '--level', type=int, choices=[1, 2, 3, 4], default=2, help='Set analysis level')
    parser.add_argument('-to', '--timeout', type=int, default=10, help='Set timeout (in seconds) for HTTP requests')
    parser.add_argument('-L', '--list-url', type=str, help='Path to a file containing a list of URLs to test')
    parser.add_argument('-r', '--report-format', type=str, choices=['json', 'html', 'csv'], default='json', help='Choose report format')
    parser.add_argument('-p', '--proxy', type=str, help='Set a proxy for HTTP requests')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-b', '--blacklist', type=str, help='Comma-separated list of URLs to exclude from scanning')
    parser.add_argument('--no-external', action='store_true', help='Do not fetch and analyze external JS files')
    parser.add_argument('--hd', '--headless', action='store_true', dest='headless', help='Enable headless browser mode')
    parser.add_argument('--user-agent', type=str, help='Set a custom User-Agent')
    parser.add_argument('--cookie', type=str, help='Send custom cookies')
    parser.add_argument('--max-depth', type=int, default=5, help='Set maximum crawling depth')
    parser.add_argument('--auto-update', action='store_true', help='Automatically check and download the latest payloads')
    return parser.parse_args()

# Validate timeout
def validate_timeout(timeout):
    if timeout <= 0:
        raise ValueError(f"Invalid timeout value: {timeout}. Timeout must be a positive integer.")
    return timeout

# Fetch URL content asynchronously
async def get_url_async(session, url, force, timeout):
    try:
        async with session.get(url, timeout=ClientTimeout(total=timeout)) as response:
            response.raise_for_status()
            return await response.text()
    except ClientError as e:
        if force:
            logger.warning(f"Unable to reach {url}, but continuing due to --force.")
            return {"error": "timeout", "url": url, "message": str(e)}
        else:
            raise e

# Scan URL
async def scan_url_async(url, level, results_queue, timeout, proxy, verbose, blacklist, no_external, headless, user_agent, cookie, max_depth, auto_update, report_format, session):
    try:
        # Check blacklist
        if blacklist and any(bl_url in url for bl_url in blacklist.split(',')):
            logger.info(f"Skipping blacklisted URL: {url}")
            return

        start_time = time()
        logger.info(f"Extracting data from {url}...")

        event_handlers = await extract(session, url, timeout)  # Removed the check for None

        logger.info(f"Running static analysis for {url}...")
        static_results = static_analyze(url, level)

        logger.info(f"Running dynamic analysis for {url}...")
        try:
            dynamic_results = dynamic_analyze(url)
        except Exception as e:
            logger.warning(f"Dynamic analysis failed for {url}: {e}")
            dynamic_results = {"error": str(e)}

        logger.info(f"Prioritizing vulnerabilities for {url}...")
        priority_results = rank(static_results, dynamic_results)

        elapsed_time = time() - start_time
        logger.info(f"Analysis completed for {url} in {elapsed_time:.2f} seconds")

        result = {
            "url": url,
            "status": "Completed",
            "elapsed_time": elapsed_time,
            "static_results": static_results,
            "dynamic_results": dynamic_results,
            "priority_results": priority_results
        }
        await results_queue.put(result)

    except Exception as e:
        logger.error(f"Error while scanning {url}: {e}")
        await results_queue.put({"url": url, "status": "Error", "error_message": str(e)})

# Write results to CSV
def write_results_to_csv(results, output_file):
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = DictWriter(f, fieldnames=['url', 'status', 'elapsed_time', 'static_results', 'dynamic_results', 'priority_results'])
        writer.writeheader()
        writer.writerows(results)

# Main function
async def main():
    args = parse_args()

    if not args.url and not args.list_url:
        print("Error: No URL(s) or list URL provided. Please specify one.")
        exit(1)

    if args.url and args.list_url:
        print("Error: Cannot use both --url and --list-url at the same time.")
        exit(1)

    if args.list_url:
        try:
            with open(args.list_url, 'r') as f:
                args.url = [line.strip() for line in f.readlines()]
        except FileNotFoundError:
            exit(f"Error: File {args.list_url} not found.")

    if not args.url:
        exit("Error: No URL(s) provided.")

    args.timeout = validate_timeout(args.timeout)

    results_queue = Queue()

    async with ClientSession() as session:
        tasks = [scan_url_async(url, args.level, results_queue, args.timeout, args.proxy, args.verbose, args.blacklist, args.no_external, args.headless, args.user_agent, args.cookie, args.max_depth, args.auto_update, args.report_format, session) for url in args.url]
        await gather(*tasks)

    results = []
    while not results_queue.empty():
        results.append(await results_queue.get())

    if args.report_format == 'csv' and args.output:
        write_results_to_csv(results, args.output)
    elif args.report_format == 'json' and args.output:
        with open(args.output, 'w') as f:
            dump(results, f, indent=4)

if __name__ == "__main__":
    run(main())
