#!/usr/bin/python3
"""
DOMinator - A DOM XSS Scanner Tool
Main entry point for the application that coordinates scanning and analysis.
"""

from asyncio import Queue, gather, run
from aiohttp import ClientSession, ClientTimeout, ClientError
from json import dump, dumps
from time import time
from extractors.event_handler_extractor import EventHandlerExtractor
from scanners.static_analyzer import StaticAnalyzer
from scanners.dynamic_analyzer import DynamicAnalyzer
from scanners.priority_manager import rank
from utils.logger import get_logger
from argparse import ArgumentParser
from sys import exit
from csv import DictWriter
from typing import List, Dict, Any, Optional

# Set up logger
logger = get_logger(__name__)

def parse_args() -> ArgumentParser:
    """
    Parse command line arguments for the scanner.
    
    Returns:
        ArgumentParser: Parsed command line arguments
    """
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

def validate_timeout(timeout: int) -> int:
    """
    Validate the timeout value.
    
    Args:
        timeout (int): Timeout value in seconds
        
    Returns:
        int: Validated timeout value
        
    Raises:
        ValueError: If timeout is not positive
    """
    if timeout <= 0:
        raise ValueError(f"Invalid timeout value: {timeout}. Timeout must be a positive integer.")
    return timeout

async def fetch_html(url: str, session: ClientSession, timeout: int) -> Optional[str]:
    """
    Fetch HTML content from a URL.
    
    Args:
        url (str): Target URL
        session (ClientSession): aiohttp client session
        timeout (int): Request timeout in seconds
        
    Returns:
        Optional[str]: HTML content if successful, None otherwise
    """
    try:
        async with session.get(url, timeout=timeout) as response:
            if response.status == 200:
                return await response.text()
            logger.error(f"Failed to fetch {url}: HTTP {response.status}")
            return None
    except ClientError as e:
        logger.error(f"Error fetching {url}: {str(e)}")
        return None

async def scan_url_async(
    url: str,
    level: int,
    results_queue: Queue,
    timeout: int,
    proxy: Optional[str],
    verbose: bool,
    blacklist: Optional[str],
    no_external: bool,
    headless: bool,
    user_agent: Optional[str],
    cookie: Optional[str],
    max_depth: int,
    auto_update: bool,
    report_format: str,
    session: ClientSession
) -> None:
    """
    Scan a single URL for DOM XSS vulnerabilities.
    
    Args:
        url (str): Target URL
        level (int): Analysis level
        results_queue (Queue): Queue for storing results
        timeout (int): Request timeout
        proxy (Optional[str]): Proxy configuration
        verbose (bool): Enable verbose output
        blacklist (Optional[str]): Blacklisted URLs
        no_external (bool): Skip external resources
        headless (bool): Use headless browser
        user_agent (Optional[str]): Custom user agent
        cookie (Optional[str]): Custom cookies
        max_depth (int): Maximum crawling depth
        auto_update (bool): Auto-update payloads
        report_format (str): Output format
        session (ClientSession): aiohttp client session
    """
    try:
        if blacklist and any(bl_url in url for bl_url in blacklist.split(',')):
            logger.info(f"Skipping blacklisted URL: {url}")
            return

        start_time = time()
        logger.info(f"Extracting data from {url}...")

        html_content = await fetch_html(url, session, timeout)
        if not html_content:
            logger.error(f"Failed to fetch HTML from {url}")
            return

        analyzer = DynamicAnalyzer(html_content, external_urls=[])
        dynamic_results = await analyzer.run_analysis()

        logger.info(f"Running static analysis for {url}...")
        static_results = StaticAnalyzer.static_analyze(url, level)

        extractor = EventHandlerExtractor(html_content)
        event_handlers_result = await extractor.extract(session, url, timeout)

        logger.info(f"Prioritizing vulnerabilities for {url}...")
        priority_results = rank(static_results, dynamic_results)

        elapsed_time = time() - start_time
        logger.info(f"Analysis completed for {url} in {elapsed_time:.2f} seconds")

        result = {
            "url": url,
            "status": "Completed",
            "elapsed_time": elapsed_time,
            "event_handlers": event_handlers_result.data if event_handlers_result.success else {"error": event_handlers_result.message},
            "static_results": static_results,
            "dynamic_results": dynamic_results,
            "priority_results": priority_results
        }

        await results_queue.put(result)

    except Exception as e:
        logger.error(f"Error while scanning {url}: {e}")
        await results_queue.put({
            "url": url,
            "status": "Error",
            "error_message": str(e)
        })

def write_results_to_csv(results: List[Dict[str, Any]], output_file: str) -> None:
    """
    Write scan results to a CSV file.
    
    Args:
        results (List[Dict[str, Any]]): Scan results
        output_file (str): Output file path
    """
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = DictWriter(f, fieldnames=[
            'url', 'status', 'elapsed_time',
            'event_handlers', 'static_results',
            'dynamic_results', 'priority_results'
        ])
        writer.writeheader()
        for result in results:
            writer.writerow({
                "url": result["url"],
                "status": result["status"],
                "elapsed_time": result.get("elapsed_time", 0),
                "event_handlers": dumps(result.get("event_handlers", {})),
                "static_results": dumps(result.get("static_results", {})),
                "dynamic_results": dumps(result.get("dynamic_results", {})),
                "priority_results": dumps(result.get("priority_results", {}))
            })

async def main() -> None:
    """
    Main entry point for the application.
    """
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
        tasks = [
            scan_url_async(
                url, args.level, results_queue, args.timeout,
                args.proxy, args.verbose, args.blacklist,
                args.no_external, args.headless,
                args.user_agent, args.cookie,
                args.max_depth, args.auto_update,
                args.report_format, session
            )
            for url in args.url
        ]
        await gather(*tasks)

    results = []
    while not results_queue.empty():
        results.append(await results_queue.get())

    if args.report_format == 'csv' and args.output:
        write_results_to_csv(results, args.output)
    elif args.report_format == 'json' and args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            dump(results, f, indent=4)

if __name__ == "__main__":
    run(main())
