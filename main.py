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

logger = get_logger(__name__)

def parse_args():
    parser = ArgumentParser(description="DOM XSS Scanner Tool")
    parser.add_argument('urls', help='Target URL(s)', nargs='+')
    parser.add_argument('--threads', type=int, default=1, help='Number of threads for parallel processing')
    parser.add_argument('--force', action='store_true', help='Force continue even if site is not reachable')
    parser.add_argument('--output', type=str, help='Output file for saving results')
    parser.add_argument('--level', type=str, choices=['critical', 'high', 'medium', 'low'], default='high', help='Set analysis level')
    return parser.parse_args()

def scan_url(url, level):
    try:
        logger.info(f"Extracting data from {url}...")
        event_handlers = extract(url)
        
        logger.info(f"Running static analysis for {url}...")
        static_analyze(url, level)
        
        logger.info(f"Running dynamic analysis for {url}...")
        dynamic_analyze(url)
        
        logger.info(f"Prioritizing vulnerabilities for {url}...")
        rank(url)
        
        logger.info(f"Analysis completed for {url}")
    except Exception as e:
        logger.error(f"Error while scanning {url}: {e}")

def main():
    args = parse_args()

    if not args.urls:
        print("No URLs provided.")
        exit(1)

    threads = []
    for url in args.urls:
        if len(threads) >= args.threads:
            threads[0].join()
            threads = threads[1:]

        thread = Thread(target=scan_url, args=(url, args.level))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    if args.output:
        with open(args.output, 'w') as f:
            dump({"message": "Results saved"}, f)

if __name__ == "__main__":
    main()
