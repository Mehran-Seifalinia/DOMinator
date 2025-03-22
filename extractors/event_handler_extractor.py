import logging
from .html_Parser import ScriptExtractor

# Setting up logging for debugging and tracking
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EventHandlerExtractor:
    def __init__(self, html: str):
        """Initializes the extractor with the provided HTML content."""
        try:
            self.extractor = ScriptExtractor(html)
            logger.info("Successfully initialized ScriptExtractor.")
        except ValueError as e:
            logger.error(f"Error initializing ScriptExtractor: {e}")
            raise

    def extract_event_handlers(self):
        """Extracts event handlers from the given HTML content."""
        try:
            event_handlers = self.extractor.extract_event_handlers()
            if event_handlers:
                logger.info(f"Event handlers extracted: {event_handlers}")
            else:
                logger.info("No event handlers found.")
            return event_handlers
        except Exception as e:
            logger.error(f"Error extracting event handlers: {e}")
            return {}

# Example usage (this will not run if the file is imported as a module)
if __name__ == "__main__":
    html_content = "<html><body><div onclick='alert(\"Hello\");'></div></body></html>"
    event_extractor = EventHandlerExtractor(html_content)
    event_handlers = event_extractor.extract_event_handlers()
    print(event_handlers)
