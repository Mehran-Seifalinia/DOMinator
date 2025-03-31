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
    response = get(url)
    if response.status_code == 200:
        return response.text
    else:
        raise Exception(f"Failed to fetch HTML for {url}")

def extract(url: str) -> dict:
    html = fetch_html(url)
    extractor = EventHandlerExtractor(html)
    return extractor.extract_event_handlers()

if __name__ == "__main__":
    html_content = "<html><body><div onclick='alert(\"Hello\");'></div></body></html>"
    event_extractor = EventHandlerExtractor(html_content)
    event_handlers = event_extractor.extract_event_handlers()
    print(event_handlers)
