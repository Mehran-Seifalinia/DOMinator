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
    parser.add_argument('urls', help='Target URL(s)', nargs='+')
    parser.add_argument('--threads', type=int, default=1, help='Number of threads for parallel processing')
    parser.add_argument('--force', action='store_true', help='Force continue even if site is not reachable')
    parser.add_argument('--output', type=str, help='Output file for saving results')
    parser.add_argument('--level', type=str, choices=['critical', 'high', 'medium', 'low'], default='high', help='Set analysis level')
    return parser.parse_args()

# Validate URL format
def validate_url(url):
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f"Invalid URL format: {url}")
    return url

# Fetch the URL content with timeout for safety
def get_url(url, force):
    try:
        response = get(url, timeout=10)  # 10 seconds timeout
        response.raise_for_status()
        return response.text
    except RequestException as e:
        if force:
            logger.warning(f"Unable to reach {url}, but continuing due to --force.")
            return None
        else:
            raise e

# Scan URL: Static and dynamic analysis, prioritization, and result logging
def scan_url(url, level, results_queue):
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

        results_queue.put({
            "url": url,
            "status": "Completed",
            "elapsed_time": elapsed_time
        })

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

    # Check if URLs are provided
    if not args.urls:
        print("No URLs provided.")
        exit(1)

    # Create a queue for thread-safe result collection
    results_queue = Queue()

    # Use ThreadPoolExecutor for parallel processing
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Validate URLs before processing
        for url in args.urls:
            try:
                validate_url(url)
            except ValueError as e:
                logger.error(f"Skipping invalid URL: {url} - {e}")
                continue

        # Submit tasks for each URL to the executor
        futures = [executor.submit(scan_url, url, args.level, results_queue) for url in args.urls]

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
