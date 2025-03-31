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
    parser.add_argument('-u', '--url', help='Target URL(s)', nargs='+')  # URLs to scan
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of threads for parallel processing')  # Thread count
    parser.add_argument('-f', '--force', action='store_true', help='Force continue even if site is not reachable')  # Force continue on unreachable site
    parser.add_argument('-o', '--output', type=str, help='Output file for saving results')  # Output file for results
    parser.add_argument('-l', '--level', type=int, choices=[1, 2, 3, 4], default=2, help='Set analysis level or filter results based on vulnerability risk level')  # Analysis level
    parser.add_argument('-to', '--timeout', type=int, default=10, help='Set timeout (in seconds) for HTTP requests')  # Timeout setting
    parser.add_argument('-i', '--input-file', type=str, help='Path to a file containing a list of URLs to test')  # Input file for URLs
    parser.add_argument('-r', '--report-format', type=str, choices=['json', 'html'], default='json', help='Choose the format of the report')  # Report format (json or html)
    parser.add_argument('-p', '--proxy', type=str, help='Set a proxy for HTTP requests')  # Proxy setting
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')  # Enable verbose logging
    parser.add_argument('-b', '--blacklist', type=str, help='Comma-separated list of URLs to exclude from scanning')  # Blacklist URLs
    parser.add_argument('--no-external', action='store_true', help='Do not fetch and analyze external JS files')  # Exclude external JS files
    parser.add_argument('--hd', '--headless', action='store_true', dest='headless', help='Enable headless browser mode')  # Enable headless mode for browser analysis
    parser.add_argument('--user-agent', type=str, help='Set a custom User-Agent')  # Custom user-agent
    parser.add_argument('--cookie', type=str, help='Send custom cookies')  # Custom cookies
    parser.add_argument('--max-depth', type=int, default=5, help='Set maximum crawling depth')  # Max crawl depth
    parser.add_argument('--auto-update', action='store_true', help='Automatically check and download the latest payloads')  # Auto update payloads
    
    args = parser.parse_args()

    # Convert 'blacklist' argument to a list if provided
    if args.blacklist:
        args.blacklist = args.blacklist.split(',')  # Split the comma-separated URLs into a list

    return args

# Validate URL format
def validate_url(url):
    if not url.startswith(('http://', 'https://')):  # Check if the URL starts with http:// or https://
        raise ValueError(f"Invalid URL format: {url}")
    return url

# Validate threads
def validate_threads(threads):
    if threads < 1:  # Ensure the number of threads is a positive integer
        raise ValueError(f"Invalid thread count: {threads}. Must be a positive integer.")
    return threads

# Validate timeout
def validate_timeout(timeout):
    if timeout <= 0:  # Ensure timeout is a positive integer
        raise ValueError(f"Invalid timeout value: {timeout}. Timeout must be a positive integer.")
    return timeout

# Fetch URL content
def get_url(url, force, timeout):
    try:
        response = get(url, timeout=timeout)  # Send HTTP request to the URL
        response.raise_for_status()  # Raise exception for non-200 HTTP status codes
        return response.text  # Return the response text (HTML content)
    except RequestException as e:
        if force:
            logger.warning(f"Unable to reach {url}, but continuing due to --force.")  # Log warning if force is enabled
            return None
        else:
            raise e  # Raise exception if force is not enabled

# Scan URL
def scan_url(url, level, results_queue, timeout, proxy, verbose, blacklist, no_external, headless, user_agent, cookie, max_depth, auto_update, report_format):
    try:
        start_time = time()  # Start timer for the scan
        logger.info(f"Extracting data from {url}...")  # Log URL extraction
        event_handlers = extract(url)  # Extract event handlers from the URL
        
        logger.info(f"Running static analysis for {url}...")  # Log static analysis
        static_analyze(url, level)  # Run static analysis
        
        logger.info(f"Running dynamic analysis for {url}...")  # Log dynamic analysis
        dynamic_analyze(url)  # Run dynamic analysis
        
        logger.info(f"Prioritizing vulnerabilities for {url}...")  # Log prioritization of vulnerabilities
        rank(url)  # Rank vulnerabilities
        
        elapsed_time = time() - start_time  # Calculate elapsed time for the scan
        logger.info(f"Analysis completed for {url} in {elapsed_time:.2f} seconds")  # Log completion of analysis
        
        result = {"url": url, "status": "Completed", "elapsed_time": elapsed_time}
        # Put the result into the queue based on the chosen report format (JSON or HTML)
        results_queue.put(result if report_format == 'json' else f"<h1>Results for {url}</h1><p>Status: Completed</p><p>Elapsed Time: {elapsed_time:.2f}s</p>")
    except Exception as e:
        logger.error(f"Error while scanning {url}: {e}")  # Log any errors encountered during the scan
        results_queue.put({"url": url, "status": "Error", "error_message": str(e)})  # Log error status in results queue

# Main function
def main():
    args = parse_args()  # Parse command-line arguments
    
    if not args.url and not args.input_file:  # Ensure either --url or --input-file is provided
        exit("Error: Either --url or --input-file must be specified.")
    
    if args.url and args.input_file:  # Ensure both --url and --input-file are not provided simultaneously
        exit("Error: Both --url and --input-file are provided. Please specify only one.")
    
    if args.input_file:  # If input file is provided, read URLs from the file
        try:
            with open(args.input_file, 'r') as f:
                args.url = [line.strip() for line in f.readlines()]  # Read URLs from file
        except FileNotFoundError:
            exit(f"Error: File {args.input_file} not found.")  # Handle file not found error
    
    if not args.url:  # Ensure that URLs are provided
        exit("No URLs provided.")
    
    args.threads = validate_threads(args.threads)  # Validate thread count
    args.timeout = validate_timeout(args.timeout)  # Validate timeout value
    
    results_queue = Queue()  # Initialize results queue
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:  # Initialize thread pool with specified number of threads
        for url in args.url:
            try:
                validate_url(url)  # Validate each URL
            except ValueError as e:
                logger.error(f"Skipping invalid URL: {url} - {e}")  # Log invalid URLs and skip them
                continue
        
        # Submit URL scanning tasks to thread pool
        futures = [executor.submit(scan_url, url, args.level, results_queue, args.timeout, args.proxy, args.verbose, args.blacklist, args.no_external, args.headless, args.user_agent, args.cookie, args.max_depth, args.auto_update, args.report_format) for url in args.url]
        
        # Wait for all threads to complete
        for future in futures:
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error in thread: {e}")  # Log thread errors
    
    # Collect results from the queue
    results = []
    while not results_queue.empty():
        results.append(results_queue.get())
    
    # Save results to output file if specified
    if args.output:
        with open(args.output, 'w') as f:
            dump(results, f, indent=4)

if __name__ == "__main__":
    main()  # Run the main function
