from asyncio import run, gather
from aiohttp import ClientSession
from extractors.html_parser import ScriptExtractor
from utils.logger import get_logger

logger = get_logger(__name__)

class EventHandlerExtractor:
    def __init__(self, html: str):
        try:
            self.extractor = ScriptExtractor(html)
            logger.info("Successfully initialized ScriptExtractor.")
        except ValueError as e:
            logger.error(f"Invalid HTML content: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during initialization: {e}")
            raise

    def extract_event_handlers(self) -> dict:
        try:
            event_handlers = self.extractor.extract_event_handlers()

            if not isinstance(event_handlers, dict):
                raise TypeError(f"Expected dict, got {type(event_handlers)}")

            if event_handlers:
                logger.info(f"Event handlers extracted: {event_handlers}")
            else:
                logger.info("No event handlers found.")

            return event_handlers
        except Exception as e:
            logger.error(f"Error extracting event handlers: {e}")
            return {}

async def fetch_html(session: ClientSession, url: str, timeout: int) -> str:
    try:
        async with session.get(url, timeout=timeout) as response:
            response.raise_for_status()
            logger.info(f"Successfully fetched HTML for {url}")
            return await response.text()
    except Exception as e:
        logger.error(f"Failed to fetch HTML for {url}: {e}")
        return ""

async def extract(session: ClientSession, url: str, timeout: int) -> dict:
    try:
        html = await fetch_html(session, url, timeout)
        if not html:
            return {}
        extractor = EventHandlerExtractor(html)
        return extractor.extract_event_handlers()
    except Exception as e:
        logger.error(f"Error during extraction process: {e}")
        return {}

async def run_extraction(urls: list, timeout: int):
    async with ClientSession() as session:
        tasks = [extract(session, url, timeout) for url in urls]
        results = await gather(*tasks)
        return results

def main(urls: list, timeout: int = 10):
    return run(run_extraction(urls, timeout))

if __name__ == "__main__":
    urls = ["http://example.com", "http://example2.com"]
    event_handlers = main(urls, timeout=10)
    print(event_handlers)
