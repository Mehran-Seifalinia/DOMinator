from requests import get
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

def fetch_html(url: str) -> str:
    try:
        response = get(url)
        response.raise_for_status()
        logger.info(f"Successfully fetched HTML for {url}")
        return response.text
    except Exception as e:
        logger.error(f"Failed to fetch HTML for {url}, Status Code: {response.status_code if hasattr(response, 'status_code') else 'Unknown'} - {e}")
        raise

def extract(url: str) -> dict:
    try:
        html = fetch_html(url)
        extractor = EventHandlerExtractor(html)
        return extractor.extract_event_handlers()
    except Exception as e:
        logger.error(f"Error during extraction process: {e}")
        return {}

if __name__ == "__main__":
    url = "http://example.com"
    event_handlers = extract(url)
    print(event_handlers)
