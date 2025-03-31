from argparse import ArgumentParser
from threading import Thread
from sys import exit
from json import dump
from extractors.html_parser import ScriptExtractor
from extractors.event_handler_extractor import extract
from scanners.static_analyzer import analyze as static_analyze
from scanners.dynamic_analyzer import analyze as dynamic_analyze
from scanners.priority_manager import rank
from utils.logger import get_logger
from concurrent.futures import ThreadPoolExecutor
from requests import get, RequestException
from time import time
from queue import Queue

# Set up logger
logger = get_logger(__name__)

# Parse command-line arguments
def parse_args():
    parser = ArgumentParser(description="DOM XSS Scanner Tool")
    parser.add_argument('-u', '--url', help='Target URL(s)', nargs='+', required=False)
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of threads for parallel processing')
    parser.add_argument('-f', '--force', action='store_true', help='Force continue even if site is not reachable')
    parser.add_argument('-o', '--output', type=str, help='Output file for saving results')
    parser.add_argument('-l', '--level', type=int, choices=[1, 2, 3, 4], default=2, help='Set analysis level or filter results based on vulnerability risk level (1: Low, 2: Medium, 3: High, 4: Critical)')
    parser.add_argument('-to', '--timeout', type=int, default=10, help='Set timeout (in seconds) for HTTP requests')
    parser.add_argument('-i', '--input-file', type=str, help='Path to a file containing a list of URLs to test')
    parser.add_argument('-r', '--report-format', type=str, choices=['json', 'html'], default='json', help='Choose the format of the report (json or html)')
    parser.add_argument('-p', '--proxy', type=str, help='Set a proxy for HTTP requests (format: http://proxy:port)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-b', '--blacklist', type=str, help='Comma-separated list of URLs to exclude from scanning', dest='blacklist')
    parser.add_argument('--no-external', action='store_true', help='Do not fetch and analyze external JS files (for faster scan)')
    parser.add_argument('--hd', '--headless', action='store_true', help='Enable headless browser mode (e.g., Chromium) for dynamic interaction testing')
    parser.add_argument('--user-agent', type=str, help='Set a custom User-Agent (e.g., simulate mobile for specific XSS detection)')
    parser.add_argument('--cookie', type=str, help='Send custom cookies (e.g., for scanning login-protected pages)')
    parser.add_argument('--max-depth', type=int, default=5, help='Set maximum crawling depth (to prevent infinite scanning)')
    parser.add_argument('--auto-update', action='store_true', help='Automatically check and download the latest payloads from the repository')
    return parser.parse_args()

# Validate URL format
def validate_url(url):
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f"Invalid URL format: {url}")
    return url

# Validate threads (must be positive)
def validate_threads(threads):
    if threads < 1:
        raise ValueError(f"Invalid thread count: {threads}. Must be a positive integer.")
    return threads

# Validate timeout (must be positive)
def validate_timeout(timeout):
    if timeout <= 0:
        raise ValueError(f"Invalid timeout value: {timeout}. Timeout must be a positive integer.")
    return timeout

# Fetch the URL content with timeout for safety
def get_url(url, force, timeout):
    try:
        response = get(url, timeout=timeout)  # Timeout from user input
        response.raise_for_status()
        return response.text
    except RequestException as e:
        if force:
            logger.warning(f"Unable to reach {url}, but continuing due to --force.")
            return None
        else:
            raise e

# Scan URL: Static and dynamic analysis, prioritization, and result logging
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

        # Collect result in the requested report format
        result = {
            "url": url,
            "status": "Completed",
            "elapsed_time": elapsed_time
        }

        if report_format == 'json':
            results_queue.put(result)
        elif report_format == 'html':
            # Convert result to HTML format if needed
            html_result = f"<h1>Results for {url}</h1><p>Status: Completed</p><p>Elapsed Time: {elapsed_time:.2f}s</p>"
            results_queue.put(html_result)

    except Exception as e:
        logger.error(f"Error while scanning {url}: {e}")
        results_queue.put({
            "url": url,
            "status": "Error",
            "error_message": str(e)
        })

# Main function
def main():
    # Parse command-line arguments
    args = parse_args()

    # Check for conflicting arguments: --url and --input-file
    if args.url and args.input_file:
        print("Error: Both --url and --input-file are provided. Please specify only one.")
        exit(1)

    # If input file is provided, read URLs from the file
    if args.input_file:
        try:
            with open(args.input_file, 'r') as f:
                args.url = [line.strip() for line in f.readlines()]
        except FileNotFoundError:
            print(f"Error: File {args.input_file} not found.")
            exit(1)

    # Validate URLs and arguments
    if not args.url:
        print("No URLs provided.")
        exit(1)

    args.threads = validate_threads(args.threads)
    args.timeout = validate_timeout(args.timeout)

    # Create a queue for thread-safe result collection
    results_queue = Queue()

    # Use ThreadPoolExecutor for parallel processing
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Validate URLs before processing
        for url in args.url:
            try:
                validate_url(url)
            except ValueError as e:
                logger.error(f"Skipping invalid URL: {url} - {e}")
                continue

        # Submit tasks for each URL to the executor
        futures = [executor.submit(scan_url, url, args.level, results_queue, args.timeout, args.proxy, args.verbose, args.blacklist, args.no_external, args.hd, args.user_agent, args.cookie, args.max_depth, args.auto_update, args.report_format) for url in args.url]

        # Ensure all threads complete
        for future in futures:
            try:
                future.result()  # Ensure any exceptions are raised
            except Exception as e:
                logger.error(f"Error in thread: {e}")

        # Shutdown the executor
        executor.shutdown()

    # Collect results from the queue
    results = []
    while not results_queue.empty():
        results.append(results_queue.get())

    # Output results to file if specified
    if args.output:
        with open(args.output, 'w') as f:
            dump(results, f, indent=4)

# Run the main function
if __name__ == "__main__":
    main()
