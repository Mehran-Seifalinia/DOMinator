from sys import argv
from asyncio import Lock, gather, run
from utils.logger import get_logger
from typing import List, Union, Optional
from aiohttp import ClientSession, ClientTimeout
from re import findall

# Set up logging (use get_logger instead of basicConfig)
logger = get_logger()

class ExternalFetcher:
    def __init__(self, urls: List[str], proxy: Optional[str] = None, timeout: int = 10):
        self.urls: List[str] = urls
        self.proxy: Optional[str] = proxy
        self.timeout: int = timeout

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

    async def process_script(self, content: str, url: str) -> Optional[dict]:
        try:
            logger.info(f"Processing script from {url}")

            if ".min.js" in url:
                logger.warning(f"Skipping minified script: {url}")
                return None

            event_listeners = findall(r'\.addEventListener\(["\'](\w+)["\']', content)
            risky_functions = findall(r'\b(eval|setTimeout|setInterval|document\.write)\b', content)

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
        try:
            async with ClientSession(timeout=ClientTimeout(total=self.timeout)) as session:
                tasks = [self.fetch_script(session, url) for url in self.urls]
                scripts = await gather(*tasks)

                for url, script_content in zip(self.urls, scripts):
                    if script_content:
                        await self.process_script(script_content, url)
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
        fetcher = ExternalFetcher(urls, proxy=proxy, timeout=timeout)

        run(fetcher.fetch_and_process_scripts())
    except Exception as e:
        logger.error(f"Error in main function: {e}")

if __name__ == "__main__":
    main()
