import requests
from extractors.html_parser import ScriptExtractor
from utils.logger import get_logger

logger = get_logger(__name__)

class EventHandlerExtractor:
    def __init__(self, html: str):
        """
        This class is designed to extract event handlers from the provided HTML content.
        
        :param html: The HTML content from which event handlers will be extracted.
        :raises ValueError: If the HTML content is invalid or if ScriptExtractor initialization fails.
        """
        try:
            # Initialize the ScriptExtractor with the provided HTML content
            self.extractor = ScriptExtractor(html)
            logger.info("Successfully initialized ScriptExtractor.")
        except ValueError as e:
            logger.error(f"Invalid HTML content: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during initialization: {e}")
            raise

    def extract_event_handlers(self) -> dict:
        """
        Extracts event handlers from the given HTML content.
        
        :returns: A dictionary of event handlers found in the HTML content.
                  Returns an empty dictionary if no event handlers are found.
        :raises Exception: If an error occurs during extraction.
        """
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
    """
    Fetch the HTML content from the given URL.

    :param url: The target URL.
    :returns: The HTML content of the page.
    :raises Exception: If the page cannot be fetched.
    """
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        raise Exception(f"Failed to fetch HTML for {url}")

def extract(url: str) -> dict:
    """
    Extract event handlers from the HTML content of the given URL.
    
    :param url: The target URL.
    :returns: A dictionary of event handlers.
    """
    html = fetch_html(url)  # Fetch the HTML content from the URL
    extractor = EventHandlerExtractor(html)
    return extractor.extract_event_handlers()

# Example usage (this will only run if the file is executed as a script)
if __name__ == "__main__":
    html_content = "<html><body><div onclick='alert(\"Hello\");'></div></body></html>"
    event_extractor = EventHandlerExtractor(html_content)
    event_handlers = event_extractor.extract_event_handlers()
    print(event_handlers)
