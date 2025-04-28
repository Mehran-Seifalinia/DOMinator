#!/usr/bin/python3
"""
DOMinator - A DOM XSS Scanner Tool
Main entry point for the application that coordinates scanning and analysis.
"""

from asyncio import Queue, gather, run, Semaphore
from aiohttp import ClientSession, ClientTimeout, ClientError
from json import dump, dumps
from time import time
from bs4 import BeautifulSoup
from extractors.event_handler_extractor import EventHandlerExtractor
from scanners.static_analyzer import StaticAnalyzer
from scanners.dynamic_analyzer import DynamicAnalyzer
from scanners.priority_manager import PriorityManager, RiskLevel, ExploitComplexity, AttackVector
from utils.logger import get_logger
from utils.analysis_result import AnalysisResult, Occurrence
from argparse import ArgumentParser
from sys import exit
from csv import DictWriter
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

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

async def fetch_html(url: str, session: ClientSession, timeout: int, headers: Optional[Dict[str, str]] = None) -> Optional[str]:
    """
    Fetch HTML content from a URL.
    
    Args:
        url (str): Target URL
        session (ClientSession): aiohttp client session
        timeout (int): Request timeout in seconds
        headers (Optional[Dict[str, str]]): Optional request headers
        
    Returns:
        Optional[str]: HTML content if successful, None otherwise
    """
    try:
        async with session.get(url, timeout=timeout, headers=headers) as response:
            if response.status == 200:
                return await response.text()
            logger.error(f"Failed to fetch {url}: HTTP {response.status}")
            return None
    except ClientError as e:
        logger.error(f"Error fetching {url}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching {url}: {str(e)}")
        return None

async def extract_external_scripts(html_content: str, base_url: str) -> List[str]:
    """
    Extract external JavaScript URLs from HTML content.
    
    Args:
        html_content (str): HTML content to analyze
        base_url (str): Base URL for resolving relative paths
        
    Returns:
        List[str]: List of external JavaScript URLs
    """
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        external_scripts = []
        
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src:
                # Handle relative URLs
                if src.startswith("//"):
                    src = f"https:{src}"
                elif src.startswith("/"):
                    src = f"{base_url.rstrip('/')}{src}"
                elif not src.startswith(("http://", "https://")):
                    src = f"{base_url.rstrip('/')}/{src.lstrip('/')}"
                external_scripts.append(src)
                
        logger.info(f"Extracted {len(external_scripts)} external JavaScript URLs")
        return external_scripts
    except Exception as e:
        logger.error(f"Error extracting external scripts: {e}")
        return []

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
    """
    try:
        if blacklist and any(bl_url in url for bl_url in blacklist.split(',')):
            logger.info(f"Skipping blacklisted URL: {url}")
            return

        start_time = time()
        logger.info(f"Starting analysis of {url}...")

        # Prepare headers
        headers = {}
        if user_agent:
            headers['User-Agent'] = user_agent
        if cookie:
            headers['Cookie'] = cookie

        html_content = await fetch_html(url, session, timeout, headers)
        if not html_content:
            logger.error(f"Failed to fetch HTML from {url}")
            await results_queue.put({
                "url": url,
                "status": "Error",
                "error_message": "Failed to fetch HTML content"
            })
            return
        
        # Extract external scripts
        external_urls = []
        if not no_external:
            external_urls = await extract_external_scripts(html_content, url)
            logger.info(f"Found {len(external_urls)} external JavaScript files")

        # Create analysis result
        result = AnalysisResult()
        result.url = url
        result.start_time = start_time

        # Run static analysis
        logger.info(f"Running static analysis for {url}...")
        static_analyzer = StaticAnalyzer(html_content)
        static_result = static_analyzer.analyze()
        result.merge_static_results(static_result)

        # Run dynamic analysis
        logger.info(f"Running dynamic analysis for {url}...")
        dynamic_analyzer = DynamicAnalyzer(
            html_content, 
            external_urls=external_urls,
            headless=headless,
            user_agent=user_agent
        )
        dynamic_result = await dynamic_analyzer.run_analysis()
        result.merge_dynamic_results(dynamic_result)

        # Extract and analyze event handlers
        logger.info(f"Analyzing event handlers for {url}...")
        extractor = EventHandlerExtractor(html_content)
        event_handlers_result = await extractor.extract(session, url, timeout)
        result.merge_event_handlers(event_handlers_result)

        # Calculate final risk score and priority
        logger.info(f"Calculating risk scores for {url}...")
        priority_manager = PriorityManager()
        
        methods = []
        if result.has_dangerous_method('eval'):
            methods.append(RiskLevel.EVAL)
        if result.has_dangerous_method('document.write'):
            methods.append(RiskLevel.DOCUMENT_WRITE)
        if result.has_dangerous_method('innerHTML'):
            methods.append(RiskLevel.INNER_HTML)
            
        priority_score, severity = priority_manager.calculate_optimized_priority(
            methods=methods,
            complexity=ExploitComplexity.MEDIUM,
            attack_vector=AttackVector.URL if result.has_url_based_sink() else None,
            event_handlers=result.event_handlers,
            dom_results=result.dynamic_results
        )

        result.set_priority_score(priority_score)
        result.set_severity(severity)
        result.end_time = time()
        result.set_completed()

        await results_queue.put(result.to_dict())
        logger.info(f"Analysis completed for {url} in {result.elapsed_time:.2f} seconds")

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
    """
    fieldnames = [
        'url', 'status', 'elapsed_time', 'severity', 'priority_score',
        'static_vulnerabilities', 'dynamic_vulnerabilities', 'event_handlers',
        'external_scripts', 'error_message'
    ]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            row = {
                "url": result["url"],
                "status": result["status"],
                "elapsed_time": result.get("elapsed_time", 0),
                "severity": result.get("severity", "Unknown"),
                "priority_score": result.get("priority_score", 0),
                "static_vulnerabilities": dumps(result.get("static_results", {})),
                "dynamic_vulnerabilities": dumps(result.get("dynamic_results", {})),
                "event_handlers": dumps(result.get("event_handlers", {})),
                "external_scripts": dumps(result.get("external_scripts", [])),
                "error_message": result.get("error_message", "")
            }
            writer.writerow(row)

async def write_results_to_html(results: List[Dict[str, Any]], output_file: str) -> None:
    """
    Write scan results to an HTML file with improved formatting and visualization.
    """
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DOMinator Scan Results</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #34495e;
            --accent-color: #3498db;
            --success-color: #2ecc71;
            --warning-color: #f1c40f;
            --danger-color: #e74c3c;
            --light-color: #ecf0f1;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: var(--light-color);
            color: var(--primary-color);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        h1 {
            color: var(--primary-color);
            text-align: center;
            margin-bottom: 30px;
        }
        
        .result-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .card-header {
            background: var(--secondary-color);
            color: white;
            padding: 15px;
            font-size: 18px;
        }
        
        .card-body {
            padding: 20px;
        }
        
        .status-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
        }
        
        .status-completed { background-color: var(--success-color); color: white; }
        .status-error { background-color: var(--danger-color); color: white; }
        
        .severity-high { color: var(--danger-color); }
        .severity-medium { color: var(--warning-color); }
        .severity-low { color: var(--accent-color); }
        
        .details-section {
            margin-top: 15px;
            border-top: 1px solid #eee;
            padding-top: 15px;
        }
        
        .vulnerability-list {
            list-style: none;
            padding: 0;
        }
        
        .vulnerability-item {
            padding: 10px;
            border-left: 4px solid var(--accent-color);
            background: #f8f9fa;
            margin-bottom: 10px;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-item {
            background: white;
            padding: 15px;
            border-radius: 4px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>DOMinator Scan Results</h1>
        <div class="stats">
            <div class="stat-item">
                <h3>Total URLs Scanned</h3>
                <p>{{TOTAL_URLS}}</p>
            </div>
            <div class="stat-item">
                <h3>Vulnerabilities Found</h3>
                <p>{{TOTAL_VULNS}}</p>
            </div>
            <div class="stat-item">
                <h3>Average Scan Time</h3>
                <p>{{AVG_SCAN_TIME}}s</p>
            </div>
        </div>
        <div class="results">
            {{RESULTS}}
        </div>
    </div>
</body>
</html>"""
    
    total_urls = len(results)
    total_vulns = sum(
        len(r.get("static_results", [])) + 
        len(r.get("dynamic_results", [])) + 
        len(r.get("event_handlers", [])) 
        for r in results if r.get("status") == "Completed"
    )
    avg_scan_time = sum(
        r.get("elapsed_time", 0) 
        for r in results if r.get("status") == "Completed"
    ) / max(1, len([r for r in results if r.get("status") == "Completed"]))
    
    results_html = ""
    for result in results:
        status_class = "status-completed" if result.get("status") == "Completed" else "status-error"
        severity = result.get("severity", "Unknown")
        severity_class = f"severity-{severity.lower()}" if severity in ["High", "Medium", "Low"] else ""
        
        result_html = f"""
        <div class="result-card">
            <div class="card-header">
                <span class="status-badge {status_class}">{result.get("status", "Unknown")}</span>
                {result.get("url", "N/A")}
            </div>
            <div class="card-body">
                <div class="stats">
                    <div class="stat-item">
                        <strong>Scan Time:</strong> {result.get("elapsed_time", 0):.2f}s
                    </div>
                    <div class="stat-item">
                        <strong>Severity:</strong> <span class="{severity_class}">{severity}</span>
                    </div>
                    <div class="stat-item">
                        <strong>Priority Score:</strong> {result.get("priority_score", 0)}
                    </div>
                </div>
                
                <div class="details-section">
                    <h3>Vulnerabilities</h3>
                    <ul class="vulnerability-list">
        """
        
        # Add static vulnerabilities
        for vuln in result.get("static_results", []):
            result_html += f"""
                <li class="vulnerability-item">
                    <strong>Static:</strong> {vuln.get("pattern", "N/A")}
                    <br>
                    <small>Context: {vuln.get("context", "N/A")}</small>
                </li>
            """
            
        # Add dynamic vulnerabilities
        for vuln in result.get("dynamic_results", []):
            result_html += f"""
                <li class="vulnerability-item">
                    <strong>Dynamic:</strong> {vuln.get("pattern", "N/A")}
                    <br>
                    <small>Context: {vuln.get("context", "N/A")}</small>
                </li>
            """
            
        # Add event handlers
        for handler_type, handlers in result.get("event_handlers", {}).items():
            for handler in handlers:
                result_html += f"""
                    <li class="vulnerability-item">
                        <strong>Event Handler ({handler_type}):</strong> {handler.get("handler", "N/A")}
                        <br>
                        <small>Element: {handler.get("tag", "N/A")}</small>
                    </li>
                """
                
        result_html += """
                    </ul>
                </div>
            </div>
        </div>
        """
        
        results_html += result_html
    
    full_html = html_template.replace("{{RESULTS}}", results_html)
    full_html = full_html.replace("{{TOTAL_URLS}}", str(total_urls))
    full_html = full_html.replace("{{TOTAL_VULNS}}", str(total_vulns))
    full_html = full_html.replace("{{AVG_SCAN_TIME}}", f"{avg_scan_time:.2f}")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(full_html)

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
                args.url = [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            exit(f"Error: File {args.list_url} not found.")

    if not args.url:
        exit("Error: No URL(s) provided.")

    args.timeout = validate_timeout(args.timeout)
    results_queue = Queue()
    
    # Limit concurrent threads
    semaphore = Semaphore(args.threads)
    
    async def limited_scan_url(url):
        async with semaphore:
            await scan_url_async(
                url, args.level, results_queue, args.timeout,
                args.proxy, args.verbose, args.blacklist,
                args.no_external, args.headless,
                args.user_agent, args.cookie,
                args.max_depth, args.auto_update,
                args.report_format, session
            )

    # Configure client session
    timeout = ClientTimeout(total=args.timeout)
    session_kwargs = {"timeout": timeout}
    if args.proxy:
        session_kwargs["proxy"] = args.proxy

    async with ClientSession(**session_kwargs) as session:
        tasks = [limited_scan_url(url) for url in args.url]
        await gather(*tasks)

    results = []
    while not results_queue.empty():
        results.append(await results_queue.get())

    if args.output:
        output_path = Path(args.output)
        if not output_path.parent.exists():
            output_path.parent.mkdir(parents=True)
            
        if args.report_format == 'csv':
            write_results_to_csv(results, args.output)
            print(f"Results written to {args.output} in CSV format")
        elif args.report_format == 'json':
            with open(args.output, 'w', encoding='utf-8') as f:
                dump(results, f, indent=4)
            print(f"Results written to {args.output} in JSON format")
        elif args.report_format == 'html':
            await write_results_to_html(results, args.output)
            print(f"Results written to {args.output} in HTML format")
    else:
        print("No output file specified. Results not saved.")

if __name__ == "__main__":
    run(main())
