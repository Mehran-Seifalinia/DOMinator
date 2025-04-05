from typing import List, Optional
from aiohttp import ClientSession, ClientTimeout
from asyncio import Semaphore
from re import findall
from utils.logger import get_logger
from scanners.static_analyzer import StaticAnalyzer

logger = get_logger()

class ExternalFetcher:
    def __init__(
        self, 
        urls: List[str], 
        proxy: Optional[str] = None, 
        timeout: int = 10, 
        max_concurrent_requests: int = 5
    ):
        self.urls = list(set(urls))  # remove duplicates
        self.proxy = proxy
        self.timeout = timeout
        self.semaphore = Semaphore(max_concurrent_requests)

    async def fetch_script(self, session: ClientSession, url: str) -> Optional[str]:
        try:
            if self.proxy:
                logger.info(f"Using proxy: {self.proxy}")
                async with session.get(url, timeout=self.timeout, proxy=self.proxy) as resp:
                    if resp.status == 200:
                        return await resp.text()
            else:
                async with session.get(url, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        return await resp.text()
            logger.warning(f"Failed to fetch {url}, status code: {resp.status}")
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
        return None

    async def process_script(self, content: str, url: str) -> None:
        try:
            logger.info(f"Analyzing script from: {url}")

            if ".min.js" in url:
                logger.info(f"Skipping minified script: {url}")
                return

            # Event listeners
            event_listeners = findall(r'\.addEventListener\(["\'](\w+)["\']', content)
            inline_events = findall(r'\bon\w+\s*=', content)
            all_events = list(set(event_listeners + inline_events))

            # Risky sinks
            risky_sinks = findall(r'\b(eval|setTimeout|setInterval|Function|document\.write|innerHTML|document\.createElement)\b', content)

            # User input sources (like DOM accessors)
            sources = findall(r'\b(getElementById|getElementsByClassName|getElementsByName|getAttribute|location\.search|document\.cookie)\b', content)

            logger.debug(f"Found {len(all_events)} events, {len(risky_sinks)} sinks, {len(sources)} sources")

            static_analyzer = StaticAnalyzer({
                "url": url,
                "events": all_events,
                "sinks": risky_sinks,
                "sources": sources,
                "raw": content
            })
            result = static_analyzer.analyze()
            logger.info(f"Static analysis for {url} completed.")
        except Exception as e:
            logger.error(f"Error processing script from {url}: {e}")

    async def run(self) -> None:
        try:
            async with ClientSession(timeout=ClientTimeout(total=self.timeout)) as session:
                for url in self.urls:
                    async with self.semaphore:
                        script_content = await self.fetch_script(session, url)
                        if script_content:
                            await self.process_script(script_content, url)
                        else:
                            logger.warning(f"No content fetched for {url}, skipping.")
        except Exception as e:
            logger.critical(f"Unhandled error in fetcher run: {e}")
