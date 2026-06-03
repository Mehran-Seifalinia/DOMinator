#!/usr/bin/python3
"""
DOMinator - A DOM XSS Scanner Tool
Main entry point for the application that coordinates scanning and analysis.
"""

from asyncio import Queue, Semaphore, gather, run
from aiohttp import ClientSession, ClientTimeout, ClientError
from json import dump, dumps
from time import time
from bs4 import BeautifulSoup
from scanners.static_analyzer import StaticAnalyzer
from scanners.dynamic_analyzer import DynamicAnalyzer
from scanners.priority_manager import PriorityManager, RiskLevel, ExploitComplexity, AttackVector
from utils.logger import get_logger
from utils.analysis_result import AnalysisResult
from utils.payloads import get_default_payloads
from urllib.parse import urlparse
from argparse import ArgumentParser
from sys import exit
from csv import DictWriter
from collections import deque
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin
from html import escape  # For sanitizing in reports

# Set up logger
logger = get_logger(__name__)

# Maximum allowed HTML size in bytes to prevent memory issues
MAX_HTML_SIZE = 10 * 1024 * 1024  # 10 MB

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
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress all info logs, show only final report')
    parser.add_argument('-b', '--blacklist', type=str, help='Comma-separated list of URLs to exclude from scanning')
    parser.add_argument('--no-external', action='store_true', help='Do not fetch and analyze external JS files')
    parser.add_argument('--visible', action='store_true', help='Show browser window (non-headless mode)')
    parser.add_argument('--user-agent', type=str, help='Set a custom User-Agent')
    parser.add_argument('--cookie', type=str, help='Send custom cookies')
    parser.add_argument('--max-depth', type=int, default=1, help='Set maximum crawling depth (currently basic implementation)')
    parser.add_argument('--auto-update', action='store_true', help='Automatically check and download the latest payloads (placeholder)')
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
    Fetch HTML content from a URL with size limit.
    
    Args:
        url (str): Target URL
        session (ClientSession): aiohttp client session
        timeout (int): Request timeout in seconds
        headers (Optional[Dict[str, str]]): Optional request headers
        
    Returns:
        Optional[str]: HTML content if successful and within size limit, None otherwise
    """
    try:
        async with session.get(url, timeout=timeout, headers=headers) as response:
            if response.status == 200:
                content = await response.text()
                if len(content) > MAX_HTML_SIZE:
                    logger.error(f"HTML content from {url} exceeds maximum size ({MAX_HTML_SIZE} bytes).")
                    return None
                return content
            logger.error(f"Failed to fetch {url}: HTTP {response.status}")
            return None
    except ClientError as e:
        logger.error(f"Error fetching {url}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching {url}: {str(e)}")
        return None

async def extract_external_scripts(html_content: str, base_url: str) -> Set[str]:
    """
    Extract external JavaScript URLs from HTML content.
    
    Args:
        html_content (str): HTML content to analyze
        base_url (str): Base URL for resolving relative paths
        
    Returns:
        Set[str]: Set of unique external JavaScript URLs
    """
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        external_scripts = set()
        
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src:
                # Handle relative URLs
                if src.startswith("//"):
                    src = f"https:{src}"
                elif not src.startswith(("http://", "https://")):
                    src = urljoin(base_url, src)
                external_scripts.add(src)
        if len(external_scripts) > 0:
            logger.debug(f"Extracted {len(external_scripts)} unique external JavaScript URLs")
        return external_scripts
    except Exception as e:
        logger.error(f"Error extracting external scripts: {str(e)}")
        return set()

async def crawl_links(html_content: str, base_url: str, max_depth: int, visited: Set[str], session: ClientSession, timeout: int, headers: Dict[str, str], depth: int = 0) -> List[Tuple[str, str]]:
    """
    Basic iterative crawler to find additional URLs up to max_depth using BFS.
    """
    if max_depth <= 1:
        return []
    
    queue = deque()
    queue.append((base_url, html_content, depth))
    all_pages = []
    
    while queue:
        current_url, current_html, current_depth = queue.popleft()
        
        if current_depth >= max_depth:
            continue
        
        try:
            soup = BeautifulSoup(current_html, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link.get("href")
                if href:
                    full_url = urljoin(current_url, href)
                    if full_url in visited:
                        continue
                    visited.add(full_url)
                    child_html = await fetch_html(full_url, session, timeout, headers)
                    if child_html is not None and len(child_html) > 0:
                        all_pages.append((full_url, child_html))
                        queue.append((full_url, child_html, current_depth + 1))
        except Exception as e:
            logger.error(f"Error during crawling: {str(e)}")
    
    return all_pages

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
    session: ClientSession,
    shared_browser = None
) -> None:
    """
    Scan a single URL for DOM XSS vulnerabilities, with optional crawling.
    
    Args:
        url (str): Target URL
        level (int): Analysis level
        results_queue (Queue): Queue to put results
        timeout (int): Request timeout
        proxy (Optional[str]): Proxy
        verbose (bool): Verbose logging
        blacklist (Optional[str]): Blacklist URLs
        no_external (bool): Skip external JS
        headless (bool): Headless browser
        user_agent (Optional[str]): User-Agent
        cookie (Optional[str]): Cookies
        max_depth (int): Crawl depth
        auto_update (bool): Auto-update payloads (placeholder)
        session (ClientSession): aiohttp session
    """
    try:        
        if blacklist:
            blacklist_urls = [bl.strip() for bl in blacklist.split(',')]
            parsed_target = urlparse(url)
            target_key = f"{parsed_target.netloc}{parsed_target.path}".rstrip('/')
            for bl in blacklist_urls:
                parsed_bl = urlparse(bl)
                bl_key = f"{parsed_bl.netloc}{parsed_bl.path}".rstrip('/')
                if target_key == bl_key:
                    logger.info(f"Skipping blacklisted URL: {url}")
                    return

        if auto_update:
            logger.info("Auto-update payloads: Placeholder - implement fetching latest patterns.")

        logger.info(f"🔍 DOMinator started scanning: {url}")

        # Prepare headers
        headers = {}
        if user_agent:
            headers['User-Agent'] = user_agent
        if cookie:
            headers['Cookie'] = cookie

        html_content = await fetch_html(url, session, timeout, headers)
        if not html_content:
            logger.error(f"Failed to fetch HTML from {url}")
            result = AnalysisResult()
            result.url = url
            result.set_error("Failed to fetch HTML content")
            await results_queue.put(result.to_dict())
            return
        
        # ========== CRAWLING AND PER-PAGE ANALYSIS ==========
        visited = set([url])
        pages_to_scan = [(url, html_content)]  # list of (page_url, page_html)

        if max_depth > 1:
            crawled_pages = await crawl_links(html_content, url, max_depth, visited, session, timeout, headers)
            pages_to_scan.extend(crawled_pages)
            logger.info(f"Crawled total {len(pages_to_scan)} pages from {url}")

        logger.info(f"📄 Found {len(pages_to_scan)} page(s) to analyze (depth={max_depth})")

        # Analyze each page separately
        for page_url, page_html in pages_to_scan:
            try:
                logger.info(f"🔄 Analyzing: {page_url}")
                page_start_time = time()
                result = AnalysisResult()
                result.url = page_url
                result.start_time = datetime.fromtimestamp(page_start_time)

                # Extract external scripts for this page
                external_urls = set()
                if not no_external:
                    external_urls = await extract_external_scripts(page_html, page_url)
                    if verbose:
                        logger.info(f"Found {len(external_urls)} external JS for {page_url}")

                # Static analysis
                if verbose:
                    logger.info(f"Running static analysis for {page_url} at level {level}...")
                static_analyzer = StaticAnalyzer(page_html, level=level)
                static_result = static_analyzer.analyze()
                result.merge_static_results(static_result)

                # Dynamic analysis
                if verbose:
                    logger.info(f"Running dynamic analysis for {page_url} at level {level}...")
                sink_patterns = [occ.get('pattern', '') for occ in result.static_occurrences]
                dynamic_analyzer = DynamicAnalyzer(
                    html_content=page_html,
                    url=page_url,
                    external_urls=list(external_urls),
                    headless=headless,
                    user_agent=user_agent,
                    payloads=get_default_payloads(),
                    sink_types=sink_patterns,
                    dom_sources=result.dom_sources,
                    timeout=timeout,
                    browser=shared_browser,
                    level=level,
                    proxy=proxy,
                    cookies=cookie
                )
                dynamic_result = await dynamic_analyzer.run_analysis()
                result.merge_dynamic_results(dynamic_result)

                # Risk calculation
                if verbose:
                    logger.info(f"Calculating risk scores for {page_url}...")
                priority_manager = PriorityManager()
                methods = []
                static_patterns = [occ['pattern'] for occ in result.static_occurrences]
                if any('eval' in p.lower() for p in static_patterns):
                    methods.append(RiskLevel.EVAL)
                if any('document.write' in p.lower() for p in static_patterns):
                    methods.append(RiskLevel.DOCUMENT_WRITE)
                if any('innerhtml' in p.lower() for p in static_patterns):
                    methods.append(RiskLevel.INNER_HTML)

                priority_score, severity = priority_manager.calculate_optimized_priority(
                    methods=methods if methods else [RiskLevel.LOCATION],
                    complexity=ExploitComplexity.MEDIUM,
                    attack_vector=AttackVector.URL,
                    event_handlers=[handler.handler for handlers in result.event_handlers.values() for handler in handlers],
                    dom_results=[occ['pattern'] for occ in result.dynamic_occurrences]
                )

                result.set_priority_score(priority_score)
                result.set_severity(severity)
                result.end_time = datetime.now()
                result.set_completed()

                await results_queue.put(result.to_dict())
                logger.debug(f"Analysis completed for {page_url} in {result.elapsed_time:.2f} seconds")

            except Exception as e:
                logger.error(f"Error analyzing {page_url}: {str(e)}")
                result = AnalysisResult()
                result.url = page_url
                result.set_error(str(e))
                await results_queue.put(result.to_dict())
                continue

    except Exception as e:
        logger.error(f"Error while scanning {url}: {str(e)}")
        result = AnalysisResult()
        result.url = url
        result.set_error(str(e))
        await results_queue.put(result.to_dict())

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
            event_handlers_dict = result.get("event_handlers", {})
            total_handlers = sum(len(handlers) for handlers in event_handlers_dict.values())
            
            row = {
                "url": result.get("url", "N/A"),
                "status": result.get("status", "Unknown"),
                "elapsed_time": result.get("elapsed_time", 0),
                "severity": result.get("severity", "Unknown"),
                "priority_score": result.get("priority_score", 0),
                "static_vulnerabilities": dumps(result.get("static_occurrences", [])),
                "dynamic_vulnerabilities": dumps(result.get("dynamic_occurrences", [])),
                "event_handlers": total_handlers,
                "external_scripts": dumps(result.get("external_script_risks", [])),
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
        
        .chart-container {
            margin-top: 20px;
            padding: 20px;
            background: white;
            border-radius: 8px;
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
        <div class="chart-container">
            <canvas id="vulnerabilityChart"></canvas>
        </div>
        <div class="results">
            {{RESULTS}}
        </div>
    </div>
    <script>
        const ctx = document.getElementById('vulnerabilityChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Vulnerabilities by Severity',
                    data: {{SEVERITY_DATA}},
                    backgroundColor: [
                        'rgba(231, 76, 60, 0.8)',
                        'rgba(241, 196, 15, 0.8)',
                        'rgba(52, 152, 219, 0.8)'
                    ]
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>"""
    
    total_urls = len(results)
    total_vulns = sum(
        len(r.get("static_occurrences", [])) + 
        len(r.get("dynamic_occurrences", [])) + 
        sum(len(handlers) for handlers in r.get("event_handlers", {}).values())
        for r in results if r.get("status") == "completed"
    )
    avg_scan_time = sum(
        r.get("elapsed_time", 0) 
        for r in results if r.get("status") == "completed"
    ) / max(1, len([r for r in results if r.get("status") == "completed"]))
    
    # Calculate severity statistics (include Critical as High)
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for result in results:
        if result.get("status") == "completed":
            severity = result.get("severity", "").lower()
            if severity in ["high", "critical"]:
                severity_counts["high"] += 1
            elif severity == "medium":
                severity_counts["medium"] += 1
            elif severity == "low":
                severity_counts["low"] += 1
    
    severity_data = [severity_counts["high"], severity_counts["medium"], severity_counts["low"]]
    
    results_html = ""
    for result in results:
        status_class = "status-completed" if result.get("status") == "completed" else "status-error"
        severity = result.get("severity", "Unknown")
        severity_class = f"severity-{severity.lower()}" if severity in ["High", "Medium", "Low", "Critical"] else ""
        
        result_html = f"""
        <div class="result-card">
            <div class="card-header">
                <span class="status-badge {status_class}">{result.get("status", "Unknown")}</span>
                {escape(result.get("url", "N/A"))}
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
        
        # Add static vulnerabilities with escape
        for vuln in result.get("static_occurrences", []):
            result_html += f"""
                <li class="vulnerability-item">
                    <strong>Static:</strong> {escape(vuln.get("pattern", "N/A"))}
                    <br>
                    <small>Context: {escape(vuln.get("context", "N/A"))}</small>
                </li>
            """
            
        # Add dynamic vulnerabilities with escape
        for vuln in result.get("dynamic_occurrences", []):
            result_html += f"""
                <li class="vulnerability-item">
                    <strong>Dynamic:</strong> {escape(vuln.get("pattern", "N/A"))}
                    <br>
                    <small>Context: {escape(vuln.get("context", "N/A"))}</small>
                </li>
            """
            
        # Add event handlers with escape
        for handler_type, handlers in result.get("event_handlers", {}).items():
            for handler in handlers:
                result_html += f"""
                    <li class="vulnerability-item">
                        <strong>Event Handler ({escape(handler_type)}):</strong> {escape(handler.get("handler", "N/A"))}
                        <br>
                        <small>Element: {escape(handler.get("tag", "N/A"))}</small>
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
    full_html = full_html.replace("{{SEVERITY_DATA}}", str(severity_data))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(full_html)

def print_console_report(results: List[Dict[str, Any]]) -> None:
    """
    Print a human-readable summary of scan results to the console,
    including vulnerabilities, severity, and basic exploit hints.
    """
    def get_exploit_hint(pattern: str, context: str = "") -> str:
        pattern_lower = pattern.lower()
        if "eval" in pattern_lower:
            return "Try injecting code in URL fragment/hash: #javascript:alert(1)"
        elif "document.write" in pattern_lower:
            return "Payload example: <img src=x onerror=alert(1)>"
        elif "innerhtml" in pattern_lower:
            return "Use event vector: <img src=x onerror=alert(1)>"
        elif "settimeout" in pattern_lower or "setinterval" in pattern_lower:
            return "If first argument is controllable, inject function call"
        elif "location" in pattern_lower or "window.location" in pattern_lower:
            return "Check if location is set from URL hash/parameter"
        elif "onclick" in pattern_lower or "onerror" in pattern_lower:
            return "Test with javascript:alert(1) or &quot; onmouseover=alert(1)"
        else:
            return "Inspect context for injection point; try <script>alert(1)</script>"

    def is_false_positive(occ: Dict) -> bool:
        pattern = occ.get("pattern", "")
        ctx = occ.get("context", "")
        if "self.__next_f" in pattern or "self.__next_f" in ctx:
            return True
        return False

    print("\n" + "=" * 80)
    print("   DOMinator - Vulnerability Report")
    print("=" * 80)

    for idx, res in enumerate(results, 1):
        url = res.get("url", "N/A")
        status = res.get("status", "pending")
        severity = res.get("severity", "Unknown")
        score = res.get("priority_score", 0)
        elapsed = res.get("elapsed_time", 0)

        # Don't show severity if it's Informative and no vulns
        total_vulns = len(res.get("static_occurrences", [])) + len(res.get("dynamic_occurrences", [])) + \
                      sum(len(v) for v in res.get("event_handlers", {}).values())
        if severity == "Informative" and total_vulns == 0:
            severity_str = ""
        else:
            emoji_map = {"Critical": "🔥", "High": "🔴", "Medium": "🟡", "Low": "🟢", "Informative": "ℹ️"}
            emoji = emoji_map.get(severity, "⚪")
            severity_str = f" | Severity: {emoji} {severity}"

        print(f"\n[{idx}] URL: {url}")
        print(f"    Status: {status}{severity_str} | Time: {elapsed:.2f}s")

        if status == "error":
            print(f"    ❌ Error: {res.get('error_message', 'No details')}")
            continue

        static = [occ for occ in res.get("static_occurrences", []) if not is_false_positive(occ)]
        dynamic = [occ for occ in res.get("dynamic_occurrences", []) if not is_false_positive(occ)]
        event_handlers = res.get("event_handlers", {})
        external = res.get("external_script_risks", [])

        total = len(static) + len(dynamic) + sum(len(v) for v in event_handlers.values()) + len(external)
        if total == 0:
            print("    ✅ No DOM XSS vulnerabilities detected.")
            continue

        print(f"    ⚠️ Found {total} potential issue(s):")

        for occ in static:
            if is_false_positive(occ):
                continue
            pattern = occ.get("pattern", "?")
            line = occ.get("line", "N/A")
            src = occ.get("source", "static")
            hint = get_exploit_hint(pattern).split('.')[0]
            print(f"      [{src.upper()}] {pattern} (line {line})")
            print(f"         💡 {hint}")

        for occ in dynamic:
            if is_false_positive(occ):
                continue
            pattern = occ.get("pattern", "?")
            line = occ.get("line", "N/A")
            src = occ.get("source", "dynamic")
            hint = get_exploit_hint(pattern).split('.')[0]
            print(f"      [{src.upper()}] {pattern} (line {line})")
            print(f"         💡 {hint}")

        for occ in external:
            if is_false_positive(occ):
                continue
            pattern = occ.get("pattern", "?")
            line = occ.get("line", "N/A")
            hint = get_exploit_hint(pattern).split('.')[0]
            print(f"      [EXTERNAL] {pattern} (line {line})")
            print(f"         💡 {hint}")

        for etype, handlers in event_handlers.items():
            for h in handlers:
                tag = h.get("tag", "?")
                attr = h.get("attribute", "?")
                code = h.get("handler", "")
                line = h.get("line", "N/A")
                hint = get_exploit_hint(attr).split('.')[0]
                print(f"      [EVENT] {tag}[{attr}] = \"{code[:50]}{'...' if len(code)>50 else ''}\" (line {line})")
                print(f"         💡 {hint}")

    print("\n" + "=" * 80)

async def main() -> None:
    """
    Main entry point for the application.
    """
    args = parse_args()
    headless_mode = not args.visible
    from logging import WARNING, DEBUG, INFO, getLogger, root
    from utils.logger import set_console_level
    if args.quiet:
        set_console_level(WARNING)
        root.setLevel(WARNING)
        for name in root.manager.loggerDict:
            getLogger(name).setLevel(WARNING)
    elif args.verbose:
        set_console_level(DEBUG)
        root.setLevel(DEBUG)
        for name in root.manager.loggerDict:
            getLogger(name).setLevel(DEBUG)
    else:
        set_console_level(INFO)
        root.setLevel(INFO)
        for name in root.manager.loggerDict:
            getLogger(name).setLevel(INFO)

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
    
    semaphore = Semaphore(args.threads)

    timeout = ClientTimeout(total=args.timeout)
    session_kwargs = {"timeout": timeout}
    if args.proxy:
        session_kwargs["proxy"] = args.proxy

    async with ClientSession(**session_kwargs) as session:
        from playwright.async_api import async_playwright
        playwright = await async_playwright().start()
        shared_browser = await playwright.chromium.launch(
            headless=headless_mode,
            args=['--no-sandbox'] if not headless_mode else ['--sandbox']
        )
        try:
            async def limited_scan_url(url):
                async with semaphore:
                    await scan_url_async(
                        url, args.level, results_queue, args.timeout,
                        args.proxy, args.verbose, args.blacklist,
                        args.no_external, headless_mode,
                        args.user_agent, args.cookie,
                        args.max_depth, args.auto_update,
                        session, shared_browser=shared_browser
                    )
            tasks = [limited_scan_url(url) for url in args.url]
            await gather(*tasks)
        finally:
            await shared_browser.close()
            await playwright.stop()

    results = []
    while not results_queue.empty():
        results.append(await results_queue.get())

    print_console_report(results)

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
        print("\n💡 Tip: Use -o <filename> to save results to a file.")

if __name__ == "__main__":
    run(main())
