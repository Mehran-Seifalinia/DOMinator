import argparse
import threading
import sys
import json
from concurrent.futures import ThreadPoolExecutor
from extractors import html_parser, external_fetcher, event_handler_extractor
from scanners import static_analyzer, dynamic_analyzer, priority_manager
from utils.logger import Logger


def parse_args():
    parser = argparse.ArgumentParser(description="DOM XSS Scanner Tool")
    parser.add_argument('urls', help='Target URL(s)', nargs='+')
    parser.add_argument('--threads', type=int, default=1, help='Number of threads for parallel processing')
    parser.add_argument('--force', action='store_true', help='Force continue even if site is not reachable')
    parser.add_argument('--output', type=str, help='Output file for saving results')
    parser.add_argument('--level', type=str, choices=['critical', 'high', 'medium', 'low'], default='high', help='Set analysis level')
    return parser.parse_args()

def scan_url(url, level):
    logger = Logger()
    
    try:
        # Extraction phase
        logger.log(f"Extracting data from {url}...")
        html_parser.extract(url)
        external_fetcher.fetch(url)
        event_handler_extractor.extract(url)
        
        # Static analysis phase
        logger.log(f"Running static analysis for {url}...")
        static_analyzer.analyze(url, level)
        
        # Dynamic analysis phase (Playwright)
        logger.log(f"Running dynamic analysis for {url}...")
        dynamic_analyzer.analyze(url)
        
        # Prioritization and reporting
        logger.log(f"Prioritizing vulnerabilities for {url}...")
        priority_manager.rank(url)
        
        logger.log(f"Analysis completed for {url}")
    except Exception as e:
        logger.log(f"Error while scanning {url}: {e}")
    
def main():
    args = parse_args()

    # Validate URLs
    if not args.urls:
        print("No URLs provided.")
        sys.exit(1)

    # Multi-threaded scanning setup using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_url, url, args.level) for url in args.urls]
        for future in futures:
            future.result()

if __name__ == "__main__":
    main()
