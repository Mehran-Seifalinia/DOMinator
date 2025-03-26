from logging import basicConfig, getLogger, INFO
from html_parser import ScriptExtractor  # Assuming this is the custom library for script extraction

# Setting up logging for debugging and tracking
basicConfig(level=INFO)
logger = getLogger(__name__)

class EventHandlerExtractor:
    def __init__(self, html: str):
        """Initializes the extractor with the provided HTML content.
        
        Args:
            html (str): The HTML content from which event handlers will be extracted.
        
        Raises:
            ValueError: If the HTML content is invalid or ScriptExtractor initialization fails.
        """
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
        """Extracts event handlers from the given HTML content.
        
        Returns:
            dict: A dictionary of event handlers found in the HTML content.
                 Returns an empty dictionary if no event handlers are found.
        
        Raises:
            Exception: If an error occurs during extraction.
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

# Example usage (this will not run if the file is imported as a module)
if __name__ == "__main__":
    html_content = "<html><body><div onclick='alert(\"Hello\");'></div></body></html>"
    event_extractor = EventHandlerExtractor(html_content)
    event_handlers = event_extractor.extract_event_handlers()
    print(event_handlers)
