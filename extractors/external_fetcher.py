from sys import argv
from asyncio import Lock, gather, run, Semaphore
from utils.logger import get_logger
from typing import List, Union, Optional
from aiohttp import ClientSession, ClientTimeout
from re import findall
from scanners.static_analyzer import StaticAnalyzer

# Set up logging (use get_logger instead of basicConfig)
logger = get_logger()

class ScriptAnalysisResult:
    def __init__(self, url: str, event_listeners: List[str], risky_functions: List[str]):
        self.url = url
        self.event_listeners = event_listeners
        self.risky_functions = risky_functions

    def to_dict(self):
        return {
            "url": self.url,
            "event_listeners": self.event_listeners,
            "risky_functions": self.risky_functions
        }

class ExternalFetcher:
    def __init__(self, urls: List[str], proxy: Optional[str] = None, timeout: int = 10, max_concurrent_requests: int = 5):
        self.urls: List[str] = list(set(urls))  # Remove duplicates
        self.proxy: Optional[str] = proxy
        self.timeout: int = timeout
        self.semaphore = Semaphore(max_concurrent_requests)  # Limit concurrent requests

    async def fetch_script(self, session, url: str) -> Optional[str]:
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
        return None  # Explicitly return None if fetch fails

    async def process_script(self, content: str, url: str) -> Optional[ScriptAnalysisResult]:
        try:
            logger.info(f"Processing script from {url}")

            if ".min.js" in url:
                logger.warning(f"Skipping minified script: {url}")
                return None

            # Detect event listeners
            event_listeners = findall(r'\.addEventListener\(["\'](\w+)["\']', content)
            # Detect risky functions
            risky_functions = findall(r'\b(eval|setTimeout|setInterval|document\.write|Function|document\.createElement|innerHTML|setInterval|setTimeout)\b', content)
            # Check if risky functions are tied to user input
            user_input_related = findall(r'\.getElementById\(["\']([^"\']+)["\']\)', content)  # Add more as needed
            risky_functions += user_input_related  # Add user input related functions to the list

            # Additional events that are considered risky
            risky_events = findall(r'\bon\w+\b', content)
            event_listeners += risky_events

            # Filter duplicates by converting to set and back to list
            script_analysis = ScriptAnalysisResult(
                url=url,
                event_listeners=list(set(event_listeners)),
                risky_functions=list(set(risky_functions))
            )

            logger.info(f"Analysis result: {script_analysis.to_dict()}")
            return script_analysis

        except Exception as e:
            logger.error(f"Error processing script from {url}: {e}")
            return None

    async def send_to_static_analyzer(self, script_analysis: ScriptAnalysisResult) -> None:
        # Assuming StaticAnalyzer exists and works as expected
        static_analyzer = StaticAnalyzer(script_analysis.to_dict())
        static_analyzer.analyze()

    async def fetch_and_process_scripts(self) -> None:
        try:
            async with ClientSession(timeout=ClientTimeout(total=self.timeout)) as session:
                tasks = [self.fetch_script(session, url) for url in self.urls]
                scripts = await gather(*tasks)

                for url, script_content in zip(self.urls, scripts):
                    if script_content:
                        script_analysis = await self.process_script(script_content, url)
                        if script_analysis:
                            await self.send_to_static_analyzer(script_analysis)
                    else:
                        logger.error(f"No script content fetched for {url}")
        
        except Exception as e:
            logger.error(f"Error in fetch_and_process_scripts: {e}")

def main() -> None:
    try:
        if len(argv) <= 1:
            print("Please provide at least one URL as an argument.")
            exit(1)

        urls: List[str] = argv[1:]
        proxy: Optional[str] = None
        timeout: int = 10
        max_concurrent_requests: int = 5  # Adjust the concurrency limit as needed
        fetcher = ExternalFetcher(urls, proxy=proxy, timeout=timeout, max_concurrent_requests=max_concurrent_requests)

        run(fetcher.fetch_and_process_scripts())
    except Exception as e:
        logger.error(f"Error in main function: {e}")

if __name__ == "__main__":
    main()
