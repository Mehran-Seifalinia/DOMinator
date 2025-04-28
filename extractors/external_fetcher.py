"""
External Fetcher Module
Fetches and analyzes external JavaScript files for potential DOM XSS vulnerabilities.
"""

from sys import argv
from asyncio import Lock, gather, run, Semaphore
from utils.logger import get_logger
from typing import List, Union, Optional, Dict, Any, Set
from aiohttp import ClientSession, ClientTimeout
from re import findall, Pattern, compile
from scanners.static_analyzer import StaticAnalyzer

logger = get_logger(__name__)

# Compile regex patterns once for better performance
PATTERNS = {
    'event_listeners': compile(r'\.addEventListener\(["\'](\w+)["\']'),
    'risky_functions': compile(r'\b(eval|setTimeout|setInterval|Function|document\.write)\b'),
    'sources': compile(r'\b(getElementById|querySelector|getElementsByClassName|getElementsByTagName|getElementsByName|getAttribute|location\.(search|hash|pathname)|document\.(cookie|referrer)|window\.name|localStorage\.getItem|sessionStorage\.getItem|URLSearchParams)\b'),
    'sinks': compile(r'\b(innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval|Function)\b'),
    'risky_events': compile(r'\bon\w+\b')
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
        """
        self.urls: List[str] = list(set(urls))  # Remove duplicates
        self.proxy: Optional[str] = proxy
        self.timeout: int = timeout
        self.semaphore = Semaphore(max_concurrent_requests)
        self.analysis_results: Dict[str, ScriptAnalysisResult] = {}  # URL -> Result mapping
        self._lock = Lock()  # For thread-safe result updates

    async def fetch_script(self, session: ClientSession, url: str) -> Optional[str]:
        """Fetch a script from a URL."""
        async with self.semaphore:  # Limit concurrent requests
            try:
                async with session.get(
                    url,
                    timeout=self.timeout,
                    proxy=self.proxy if self.proxy else None
                ) as response:
                    if response.status == 200:
                        return await response.text()
                    logger.error(f"Failed to fetch {url}: HTTP {response.status}")
            except Exception as e:
                logger.error(f"Error fetching {url}: {e}")
            return None

    async def analyze_script(self, content: str, url: str) -> Optional[ScriptAnalysisResult]:
        """
        Analyze a script for potential vulnerabilities.
        
        Args:
            content (str): Script content to analyze
            url (str): URL of the script
            
        Returns:
            Optional[ScriptAnalysisResult]: Analysis result if successful
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
            logger.error(f"Error analyzing script from {url}: {e}")
            return None

    async def fetch_and_process_scripts(self) -> List[ScriptAnalysisResult]:
        """
        Fetch and process all scripts in parallel.
        
        Returns:
            List[ScriptAnalysisResult]: List of analysis results
        """
        try:
            async with ClientSession(timeout=ClientTimeout(total=self.timeout)) as session:
                fetch_tasks = [self.fetch_script(session, url) for url in self.urls]
                scripts = await gather(*fetch_tasks)

                analysis_tasks = []
                for url, content in zip(self.urls, scripts):
                    if content:
                        analysis_tasks.append(self.analyze_script(content, url))
                
                if analysis_tasks:
                    await gather(*analysis_tasks)

            return list(self.analysis_results.values())

        except Exception as e:
            logger.error(f"Error in fetch_and_process_scripts: {e}")
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
    try:
        if len(argv) <= 1:
            print("Please provide at least one URL as an argument.")
            exit(1)

        urls: List[str] = argv[1:]
        proxy: Optional[str] = None
        timeout: int = 10
        max_concurrent_requests: int = 5
        fetcher = ExternalFetcher(urls, proxy=proxy, timeout=timeout, max_concurrent_requests=max_concurrent_requests)

        run(fetcher.fetch_and_process_scripts())
    except Exception as e:
        logger.error(f"Error in main function: {e}")

if __name__ == "__main__":
    main()
