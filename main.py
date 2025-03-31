from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from json import dump
from time import time
from requests import get, RequestException
from extractors.html_parser import ScriptExtractor
from extractors.event_handler_extractor import extract
from scanners.static_analyzer import analyze as static_analyze
from scanners.dynamic_analyzer import analyze as dynamic_analyze
from scanners.priority_manager import rank
from utils.logger import get_logger
from argparse import ArgumentParser
from sys import exit

# Set up logger
logger = get_logger(__name__)

# Parse command-line arguments
def parse_args():
    parser = ArgumentParser(description="DOM XSS Scanner Tool")
    parser.add_argument('-u', '--url', help='Target URL(s)', nargs='+')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of threads for parallel processing')
    parser.add_argument('-f', '--force', action='store_true', help='Force continue even if site is not reachable')
    parser.add_argument('-o', '--output', type=str, help='Output file for saving results')
    parser.add_argument('-l', '--level', type=int, choices=[1, 2, 3, 4], default=2, help='Set analysis level or filter results based on vulnerability risk level')
    parser.add_argument('-to', '--timeout', type=int, default=10, help='Set timeout (in seconds) for HTTP requests')
    parser.add_argument('-L', '--list-url', type=str, help='Path to a file containing a list of URLs to test')
    parser.add_argument('-r', '--report-format', type=str, choices=['json', 'html'], default='json', help='Choose the format of the report')
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

# Validate URL format
def validate_url(url):
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f"Invalid URL format: {url}")
    return url

# Validate threads
def validate_threads(threads):
    if threads < 1:
        raise ValueError(f"Invalid thread count: {threads}. Must be a positive integer.")
    return threads

# Validate timeout
def validate_timeout(timeout):
    if timeout <= 0:
        raise ValueError(f"Invalid timeout value: {timeout}. Timeout must be a positive integer.")
    return timeout

# Fetch URL content
def get_url(url, force, timeout):
    try:
        response = get(url, timeout=timeout)
        response.raise_for_status()
        return response.text
    except RequestException as e:
        if force:
            logger.warning(f"Unable to reach {url}, but continuing due to --force.")
            return None
        else:
            raise e

# Scan URL
def scan_url(url, level, results_queue, timeout, proxy, verbose, blacklist, no_external, headless, user_agent, cookie, max_depth, auto_update, report_format):
    try:
        start_time = time()
        logger.info(f"Extracting data from {url}...")
        event_handlers = extract(url)
        
        logger.info(f"Running static analysis for {url}...")
        static_analyze(url, level)
        
        logger.info(f"Running dynamic analysis for {url}...")
        dynamic_analyze(url)
        
        logger.info(f"Prioritizing vulnerabilities for {url}...")
        rank(url)
        
        elapsed_time = time() - start_time
        logger.info(f"Analysis completed for {url} in {elapsed_time:.2f} seconds")
        
        result = {"url": url, "status": "Completed", "elapsed_time": elapsed_time}
        results_queue.put(result if report_format == 'json' else f"<h1>Results for {url}</h1><p>Status: Completed</p><p>Elapsed Time: {elapsed_time:.2f}s</p>")
    except Exception as e:
        logger.error(f"Error while scanning {url}: {e}")
        results_queue.put({"url": url, "status": "Error", "error_message": str(e)})

# Main function
def main():
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
    
    args.threads = validate_threads(args.threads)
    args.timeout = validate_timeout(args.timeout)
    
    results_queue = Queue()
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_url, url, args.level, results_queue, args.timeout, args.proxy, args.verbose, args.blacklist, args.no_external, args.headless, args.user_agent, args.cookie, args.max_depth, args.auto_update, args.report_format): url for url in args.url}
        
        for future in as_completed(futures):
            url = futures[future]
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error in thread for URL {url}: {e}")
    
    results = []
    while not results_queue.empty():
        results.append(results_queue.get())
    
    if args.output:
        with open(args.output, 'w') as f:
            dump(results, f, indent=4)

if __name__ == "__main__":
    main()
