from asyncio import run, gather
from aiohttp import ClientSession
from extractors.html_parser import ScriptExtractor
from utils.logger import get_logger

logger = get_logger(__name__)

class EventHandlerExtractor:
    def __init__(self, html: str, proxy: str = None, user_agent: str = None):
        try:
            # Initialize ScriptExtractor with optional proxy and user_agent
            self.extractor = ScriptExtractor(html, proxy=proxy, user_agent=user_agent)
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

            if event_handlers:  # No need to check type as ScriptExtractor always returns a dict
                logger.info(f"Event handlers extracted: {event_handlers}")
            else:
                logger.info("No event handlers found.")

            return event_handlers
        except Exception as e:
            logger.error(f"Error extracting event handlers: {e}")
            return {"error": "Extraction failed"}

async def fetch_html(session: ClientSession, url: str, timeout: int, proxy: str = None, user_agent: str = None) -> str:
    try:
        headers = {'User-Agent': user_agent} if user_agent else {}
        async with session.get(url, timeout=timeout, proxy=proxy, headers=headers) as response:
            response.raise_for_status()
            html = await response.text()
            if not html.strip():
                logger.error(f"Empty HTML response for {url}")
                return {"error": "Empty HTML response"}
            logger.info(f"Successfully fetched HTML for {url}")
            return html
    except Exception as e:
        logger.error(f"Failed to fetch HTML for {url}: {e}")
        return {"error": "Failed to fetch HTML"}

async def extract(session: ClientSession, url: str, timeout: int, proxy: str = None, user_agent: str = None) -> dict:
    try:
        html = await fetch_html(session, url, timeout, proxy, user_agent)
        if isinstance(html, dict):  # Handle if an error occurs
            return html
        extractor = EventHandlerExtractor(html, proxy, user_agent)
        return extractor.extract_event_handlers()
    except Exception as e:
        logger.error(f"Error during extraction process: {e}")
        return {"error": "Extraction failed"}

async def run_extraction(urls: list, timeout: int, proxy: str = None, user_agent: str = None):
    async with ClientSession() as session:
        tasks = [extract(session, url, timeout, proxy, user_agent) for url in urls]
        results = await gather(*tasks)
        return results

def main(urls: list, timeout: int = 10, proxy: str = None, user_agent: str = None):
    return run(run_extraction(urls, timeout, proxy, user_agent))

if __name__ == "__main__":
    urls = ["http://example.com", "http://example2.com"]
    proxy = None  # Or provide a proxy string if needed
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    event_handlers = main(urls, timeout=10, proxy=proxy, user_agent=user_agent)
    print(event_handlers)
