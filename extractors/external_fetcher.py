"""
External Fetcher Module
Fetches and analyzes external JavaScript files for potential DOM XSS vulnerabilities.
"""

from sys import argv
from asyncio import Lock, gather, run, Semaphore
from utils.logger import get_logger
from typing import List, Union, Optional, Dict, Any
from aiohttp import ClientSession, ClientTimeout
from re import findall
from scanners.static_analyzer import StaticAnalyzer

logger = get_logger(__name__)

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

class ExternalFetcher:
    """
    A class for fetching and analyzing external JavaScript files.
    
    This class provides methods to fetch external scripts and analyze them
    for potential DOM XSS vulnerabilities.
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
        self.analysis_results: List[ScriptAnalysisResult] = []  # Store analysis results

    async def fetch_script(self, session: ClientSession, url: str) -> Optional[str]:
        """
        Fetch a script from a URL.
        
        Args:
            session (ClientSession): aiohttp client session
            url (str): URL to fetch
            
        Returns:
            Optional[str]: Script content if successful, None otherwise
        """
        try:
            if self.proxy:
                logger.info(f"Using proxy: {self.proxy}")
                async with session.get(url, timeout=self.timeout, proxy=self.proxy) as response:
                    if response.status == 200:
                        return await response.text()
                    else:
                        logger.error(f"Failed to fetch {url}: HTTP {response.status}")
            else:
                async with session.get(url, timeout=self.timeout) as response:
                    if response.status == 200:
                        return await response.text()
                    else:
                        logger.error(f"Failed to fetch {url}: HTTP {response.status}")
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
        return None

    async def process_script(self, content: str, url: str) -> Optional[ScriptAnalysisResult]:
        """
        Process a script and analyze it for potential vulnerabilities.
        
        Args:
            content (str): Script content to analyze
            url (str): URL of the script
            
        Returns:
            Optional[ScriptAnalysisResult]: Analysis result if successful, None otherwise
        """
        try:
            logger.info(f"Processing script from {url}")

            if ".min.js" in url:
                logger.warning(f"Skipping minified script: {url}")
                return None

            # Detect event listeners
            event_listeners = findall(r'\.addEventListener\(["\'](\w+)["\']', content)
            
            # Detect risky functions (sinks)
            risky_sinks_patterns = [
                r'\beval\b',
                r'\bsetTimeout\b',
                r'\bsetInterval\b',
                r'\bFunction\b',
                r'\bdocument\.write\b',
                r'\binnerHTML\s*=',
                r'\bouterHTML\s*=',
                r'\bdocument\.createElement\b'
            ]
            risky_sinks_regex = '|'.join(risky_sinks_patterns)
            risky_sinks = findall(risky_sinks_regex, content)

            # Detect risky sources (user input access)
            source_patterns = [
                r'\bgetElementById\b',
                r'\bgetElementsByClassName\b',
                r'\bgetElementsByTagName\b',
                r'\bgetElementsByName\b',
                r'\bgetAttribute\b',
                r'\blocation\.search\b',
                r'\blocation\.hash\b',
                r'\blocation\.pathname\b',
                r'\bdocument\.cookie\b',
                r'\bdocument\.referrer\b',
                r'\bwindow\.name\b',
                r'\blocalStorage\.getItem\b',
                r'\bsessionStorage\.getItem\b',
                r'\bURLSearchParams\b'
            ]
            sources_regex = '|'.join(source_patterns)
            sources = findall(sources_regex, content)

            # Additional events that are considered risky
            risky_events = findall(r'\bon\w+\b', content)
            event_listeners += risky_events

            script_analysis = ScriptAnalysisResult(
                url=url,
                event_listeners=list(set(event_listeners)),
                risky_functions=risky_sinks,
                sources=list(set(sources)),
                sinks=risky_sinks
            )

            logger.info(f"Analysis result: {script_analysis.to_dict()}")
            return script_analysis

        except Exception as e:
            logger.error(f"Error processing script from {url}: {e}")
            return None

    async def send_to_static_analyzer(self, script_content: str, url: str) -> None:
        """
        Analyze JavaScript content for potential vulnerabilities.
        
        Args:
            script_content (str): JavaScript content to analyze
            url (str): URL of the script
        """
        try:
            # Analyze for event listeners
            event_listeners = findall(r'\.addEventListener\(["\'](\w+)["\']', script_content)
            
            # Analyze for risky functions
            risky_functions = findall(r'\b(eval|setTimeout|setInterval|Function|document\.write)\b', script_content)
            
            # Analyze for potential sources
            sources = findall(r'\b(getElementById|querySelector|location|cookie)\b', script_content)
            
            # Analyze for potential sinks
            sinks = findall(r'\b(innerHTML|outerHTML|document\.write|eval)\b', script_content)
            
            analysis_result = ScriptAnalysisResult(
                url=url,
                event_listeners=list(set(event_listeners)),
                risky_functions=list(set(risky_functions)),
                sources=list(set(sources)),
                sinks=list(set(sinks))
            )
            
            self.analysis_results.append(analysis_result)
            logger.info(f"Static analysis completed for {url}")
            
        except Exception as e:
            logger.error(f"Error in static analysis of script from {url}: {e}")

    async def fetch_and_process_scripts(self) -> List[ScriptAnalysisResult]:
        """
        Fetch and process all scripts in parallel.
        
        Returns:
            List[ScriptAnalysisResult]: List of analysis results for all processed scripts
        """
        try:
            async with ClientSession(timeout=ClientTimeout(total=self.timeout)) as session:
                tasks = [self.fetch_script(session, url) for url in self.urls]
                scripts = await gather(*tasks)

                for url, script_content in zip(self.urls, scripts):
                    if script_content:
                        await self.send_to_static_analyzer(script_content, url)
                    else:
                        logger.error(f"No script content fetched for {url}")
            
            return self.analysis_results
        
        except Exception as e:
            logger.error(f"Error in fetch_and_process_scripts: {e}")
            return []

    def get_analysis_results(self) -> List[ScriptAnalysisResult]:
        """
        Get all analysis results.
        
        Returns:
            List[ScriptAnalysisResult]: List of all script analysis results
        """
        return self.analysis_results

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
