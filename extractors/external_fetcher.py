"""
External Fetcher Module
Fetches and analyzes external JavaScript files for potential DOM XSS vulnerabilities.
"""

from sys import argv
from asyncio import Lock, Semaphore, gather, run
from typing import List, Optional, Dict, Any
from aiohttp import ClientSession, ClientTimeout
from re import findall, compile
from urllib.parse import urlparse
from tenacity import retry, stop_after_attempt, wait_exponential
from utils.logger import get_logger

logger = get_logger(__name__)

# Maximum allowed content size in bytes to prevent memory/CPU issues
MAX_CONTENT_SIZE = 1024 * 1024  # 1 MB

# Default User-Agent for requests
DEFAULT_USER_AGENT = "DOMinator/1.0 (Security Scanner)"

# Compile regex patterns once for better performance
# Note: These patterns are approximate and may produce false positives in strings or comments.
# For more accurate analysis, consider using a JS parser like esprima in future versions.
PATTERNS = {
    'event_listeners': compile(r'(?<!["\'`])\.addEventListener\(["\'](\w+)["\'](?<!["\'`])'),
    'risky_functions': compile(r'(?<!["\'`])\b(eval|setTimeout|setInterval|Function|document\.write)\b(?!["\'`])'),
    'sources': compile(r'(?<!["\'`])\b(getElementById|querySelector|getElementsByClassName|getElementsByTagName|getElementsByName|getAttribute|location\.(search|hash|pathname)|document\.(cookie|referrer)|window\.name|localStorage\.getItem|sessionStorage\.getItem|URLSearchParams)\b(?!["\'`])'),
    'sinks': compile(r'(?<!["\'`])\b(innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval|Function)\b(?!["\'`])'),
    'risky_events': compile(r'(?<!["\'`])\bon\w+\b(?!["\'`])')
}

class ScriptAnalysisResult:
    """
    A class to store the results of script analysis.
    
    This class holds information about event listeners, risky functions,
    sources, and sinks found in a JavaScript file.
    """
    
    def __init__(self, url: str, event_listeners: List[str], risky_functions: List[str], sources: List[str], sinks: List[str]) -> None:
        """
        Initialize ScriptAnalysisResult with analysis data.
        
        Args:
            url (str): URL of the analyzed script
            event_listeners (List[str]): List of event listeners found
            risky_functions (List[str]): List of risky functions found
            sources (List[str]): List of potential sources found
            sinks (List[str]): List of potential sinks found
        """
        self.url = url
        self.event_listeners = event_listeners
        self.risky_functions = risky_functions
        self.sources = sources
        self.sinks = sinks

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the analysis result to a dictionary.
        
        Returns:
            Dict[str, Any]: Dictionary representation of the analysis result
        """
        return {
            "url": self.url,
            "event_listeners": self.event_listeners,
            "risky_functions": self.risky_functions,
            "sources": self.sources,
            "sinks": self.sinks
        }

    def merge(self, other: 'ScriptAnalysisResult') -> None:
        """
        Merge another analysis result into this one.
        
        Args:
            other (ScriptAnalysisResult): Another analysis result to merge
        """
        self.event_listeners = list(set(self.event_listeners + other.event_listeners))
        self.risky_functions = list(set(self.risky_functions + other.risky_functions))
        self.sources = list(set(self.sources + other.sources))
        self.sinks = list(set(self.sinks + other.sinks))

class ExternalFetcher:
    """
    A class for fetching and analyzing external JavaScript files.
    """
    
    def __init__(self, urls: List[str], proxy: Optional[str] = None, timeout: int = 10, max_concurrent_requests: int = 5) -> None:
        """
        Initialize ExternalFetcher with configuration parameters.
        
        Args:
            urls (List[str]): List of URLs to fetch
            proxy (Optional[str]): Proxy configuration
            timeout (int): Request timeout in seconds
            max_concurrent_requests (int): Maximum number of concurrent requests
        
        Raises:
            ValueError: If invalid URLs or proxy are provided
        """
        self.urls: List[str] = self._validate_urls(list(set(urls)))  # Remove duplicates and validate
        self.proxy: Optional[str] = self._validate_proxy(proxy)
        self.timeout: int = timeout
        self.semaphore = Semaphore(max_concurrent_requests)
        self.analysis_results: Dict[str, ScriptAnalysisResult] = {}  # URL -> Result mapping
        self._lock = Lock()  # For thread-safe result updates

    def _validate_urls(self, urls: List[str]) -> List[str]:
        """Validate and filter valid URLs."""
        valid_urls = []
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.scheme in ('http', 'https') and parsed.netloc:
                    valid_urls.append(url)
                else:
                    logger.warning(f"Invalid URL skipped: {url}")
            except Exception:
                logger.warning(f"Invalid URL skipped: {url}")
        if not valid_urls:
            raise ValueError("No valid URLs provided.")
        return valid_urls

    def _validate_proxy(self, proxy: Optional[str]) -> Optional[str]:
        """Validate proxy format."""
        if proxy:
            try:
                parsed = urlparse(proxy)
                if parsed.scheme in ('http', 'https', 'socks5') and parsed.netloc:
                    return proxy
                else:
                    raise ValueError(f"Invalid proxy format: {proxy}")
            except Exception:
                raise ValueError(f"Invalid proxy: {proxy}")
        return None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def fetch_script(self, session: ClientSession, url: str) -> Optional[str]:
        """
        Fetch a script from a URL with retry mechanism.
        
        Args:
            session (ClientSession): aiohttp session
            url (str): URL to fetch
            
        Returns:
            Optional[str]: Script content if successful
        """
        async with self.semaphore:  # Limit concurrent requests
            try:
                headers = {'User-Agent': DEFAULT_USER_AGENT}
                async with session.get(
                    url,
                    timeout=ClientTimeout(total=self.timeout, connect=5, sock_read=self.timeout),
                    proxy=self.proxy,
                    headers=headers
                ) as response:
                    if response.status == 200 and 'javascript' in response.content_type.lower():
                        content = await response.text()
                        if len(content) > MAX_CONTENT_SIZE:
                            logger.warning(f"Content too large for {url}, skipping analysis.")
                            return None
                        return content
                    logger.warning(f"Failed to fetch {url}: HTTP {response.status} or invalid content type.")
            except Exception as e:
                logger.error(f"Error fetching {url}: {str(e)}")
                raise  # For retry
            return None

    async def analyze_script(self, content: str, url: str) -> Optional[ScriptAnalysisResult]:
        """
        Analyze a script for potential vulnerabilities.
        
        Args:
            content (str): Script content to analyze
            url (str): URL of the script
            
        Returns:
            Optional[ScriptAnalysisResult]: Analysis result if successful
            
        Note: Analysis uses regex patterns which may have false positives.
        """
        try:
            if ".min.js" in url:
                logger.warning(f"Skipping minified script: {url}")
                return None

            # Find all matches using compiled patterns
            event_listeners = findall(PATTERNS['event_listeners'], content)
            risky_events = findall(PATTERNS['risky_events'], content)
            event_listeners.extend(risky_events)

            analysis = ScriptAnalysisResult(
                url=url,
                event_listeners=list(set(event_listeners)),
                risky_functions=list(set(findall(PATTERNS['risky_functions'], content))),
                sources=list(set(findall(PATTERNS['sources'], content))),
                sinks=list(set(findall(PATTERNS['sinks'], content)))
            )

            async with self._lock:
                if url in self.analysis_results:
                    self.analysis_results[url].merge(analysis)
                else:
                    self.analysis_results[url] = analysis

            logger.info(f"Analysis completed for {url}")
            return analysis

        except Exception as e:
            logger.error(f"Error analyzing script from {url}: {str(e)}")
            return None

    async def fetch_and_process_scripts(self) -> List[ScriptAnalysisResult]:
        """
        Fetch and process all scripts in parallel.
        
        Returns:
            List[ScriptAnalysisResult]: List of analysis results
        """
        try:
            async with ClientSession() as session:
                fetch_tasks = [self.fetch_script(session, url) for url in self.urls]
                scripts = await gather(*fetch_tasks, return_exceptions=True)

                analysis_tasks = []
                for url, result in zip(self.urls, scripts):
                    if isinstance(result, Exception):
                        logger.error(f"Fetch failed for {url}: {str(result)}")
                        continue
                    if result:
                        analysis_tasks.append(self.analyze_script(result, url))
                
                if analysis_tasks:
                    analysis_results = await gather(*analysis_tasks, return_exceptions=True)
                    for res in analysis_results:
                        if isinstance(res, Exception):
                            logger.error(f"Analysis error: {str(res)}")

            return list(self.analysis_results.values())

        except Exception as e:
            logger.error(f"Error in fetch_and_process_scripts: {str(e)}")
            return list(self.analysis_results.values())  # Return any results we have

    def get_analysis_results(self) -> List[ScriptAnalysisResult]:
        """Get all analysis results."""
        return list(self.analysis_results.values())

    def get_result_for_url(self, url: str) -> Optional[ScriptAnalysisResult]:
        """
        Get analysis result for a specific URL.
        
        Args:
            url (str): URL to get results for
            
        Returns:
            Optional[ScriptAnalysisResult]: Analysis result if found
        """
        return self.analysis_results.get(url)

def main() -> None:
    """
    Main entry point for the script.
    
    This function handles command line arguments and initializes the fetcher.
    """
    from argparse import ArgumentParser

    parser = ArgumentParser(description="External JS Fetcher and Analyzer")
    parser.add_argument("urls", nargs="+", help="URLs to fetch and analyze")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--max-concurrent", type=int, default=5, help="Max concurrent requests")

    args = parser.parse_args()

    try:
        fetcher = ExternalFetcher(
            urls=args.urls,
            proxy=args.proxy,
            timeout=args.timeout,
            max_concurrent_requests=args.max_concurrent
        )
        run(fetcher.fetch_and_process_scripts())
    except Exception as e:
        logger.error(f"Error in main function: {str(e)}")

if __name__ == "__main__":
    main()
