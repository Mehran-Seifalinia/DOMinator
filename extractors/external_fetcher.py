from sys import argv
from asyncio import Lock, gather, run
from utils.logger import get_logger
from typing import List, Union, Optional

# Set up logging (use get_logger instead of basicConfig)
logger = get_logger()

class ExternalFetcher:
    def __init__(self, urls: List[str], proxy: Optional[str] = None, timeout: int = 10):
        """
        Initializes the ExternalFetcher class with a list of URLs,
        an optional proxy URL, and a timeout setting for requests.
        """
        self.urls: List[str] = urls
        self.proxy: Optional[str] = proxy
        self.timeout: int = timeout

    async def fetch_script(self, session, url: str) -> Optional[str]:
        """Fetches script content from a given URL."""
        try:
            async with session.get(url, timeout=self.timeout, proxy=self.proxy) as response:
                if response.status == 200:
                    return await response.text()
                logger.error(f"Failed to fetch {url}: HTTP {response.status}")
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
        return None

    async def process_script(self, content: str, url: str) -> Optional[dict]:
        """Processes the JavaScript content to extract event listeners and potential security risks."""
        try:
            logger.info(f"Processing script from {url}")

            # Skip minified scripts
            if ".min.js" in url:
                logger.warning(f"Skipping minified script: {url}")
                return None

            # Extract event listeners (e.g., `element.addEventListener("click", function() {...})`)
            event_listeners = findall(r'\.addEventListener\(["\'](\w+)["\']', content)

            # Check for risky functions such as eval(), setTimeout(), setInterval(), document.write()
            risky_functions = findall(r'\b(eval|setTimeout|setInterval|document\.write)\b', content)

            # Store the results
            script_analysis = {
                "url": url,
                "event_listeners": list(set(event_listeners)),
                "risky_functions": list(set(risky_functions))
            }

            logger.info(f"Analysis result: {script_analysis}")
            return script_analysis

        except Exception as e:
            logger.error(f"Error processing script from {url}: {e}")
            return None

    async def fetch_and_process_scripts(self) -> None:
        """Fetches and processes scripts."""
        try:
            async with ClientSession() as session:
                tasks = [self.fetch_script(session, url) for url in self.urls]
                scripts = await gather(*tasks)

                for url, script_content in zip(self.urls, scripts):
                    if script_content:
                        await self.process_script(script_content, url)
                    else:
                        logger.error(f"No script content fetched for {url}")
        
        except Exception as e:
            logger.error(f"Error in fetch_and_process_scripts: {e}")

if __name__ == "__main__":
    urls: List[str] = argv[1:] if len(argv) > 1 else [
        "https://example.com/script1.js",
        "https://example.com/script2.js"
    ]
    proxy: Optional[str] = None  # Optional proxy URL
    timeout: int = 10  # Default timeout in seconds
    fetcher = ExternalFetcher(urls, proxy=proxy, timeout=timeout)

    async def main() -> None:
        try:
            await fetcher.fetch_and_process_scripts()
        except Exception as e:
            logger.error(f"Error in main function: {e}")
    
    run(main())
