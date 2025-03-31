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
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests import get, RequestException
from time import time

logger = get_logger(__name__)

def parse_args():
    parser = ArgumentParser(description="DOM XSS Scanner Tool")
    parser.add_argument('urls', help='Target URL(s)', nargs='+')
    parser.add_argument('--threads', type=int, default=1, help='Number of threads for parallel processing')
    parser.add_argument('--force', action='store_true', help='Force continue even if site is not reachable')
    parser.add_argument('--output', type=str, help='Output file for saving results')
    parser.add_argument('--level', type=str, choices=['critical', 'high', 'medium', 'low'], default='high', help='Set analysis level')
    return parser.parse_args()

def validate_url(url):
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f"Invalid URL format: {url}")
    return url

def get_url(url, force):
    try:
        response = get(url)
        response.raise_for_status()
        return response.text
    except RequestException as e:
        if force:
            logger.warning(f"Unable to reach {url}, but continuing due to --force.")
            return None
        else:
            raise e

def scan_url(url, level, results):
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

        results.append({
            "url": url,
            "status": "Completed",
            "elapsed_time": elapsed_time
        })

    except Exception as e:
        logger.error(f"Error while scanning {url}: {e}")
        results.append({
            "url": url,
            "status": "Error",
            "error_message": str(e)
        })

def main():
    args = parse_args()

    if not args.urls:
        print("No URLs provided.")
        exit(1)

    results = []

    # Validate URLs before processing
    valid_urls = []
    for url in args.urls:
        try:
            validate_url(url)
            valid_urls.append(url)
        except ValueError as e:
            logger.error(f"Skipping invalid URL: {url} - {e}")

    if not valid_urls:
        logger.error("No valid URLs to process.")
        exit(1)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_url, url, args.level, results): url for url in valid_urls}

        for future in as_completed(futures):
            url = futures[future]
            try:
                future.result()  # Ensure any exceptions are raised
            except Exception as e:
                logger.error(f"Error in thread for {url}: {e}")
                results.append({"url": url, "status": "Error", "error_message": str(e)})

        executor.shutdown()  # Ensure all threads finish properly

    if args.output:
        with open(args.output, 'w') as f:
            dump(results, f, indent=4)

if __name__ == "__main__":
    main()
