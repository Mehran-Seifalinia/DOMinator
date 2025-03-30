from logger import get_logger  # Use the unified logger from logger.py
from html_parser import ScriptExtractor  # Assuming this is the custom library for script extraction

# Set up the logger
logger = get_logger(__name__)  # Use the configured logger from logger.py

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
            logger.info("Successfully initialized ScriptExtractor.")  # Log successful initialization
        except ValueError as e:
            logger.error(f"Invalid HTML content: {e}")  # Log error if HTML content is invalid
            raise
        except Exception as e:
            logger.error(f"Unexpected error during initialization: {e}")  # Log any other initialization errors
            raise

    def extract_event_handlers(self) -> dict:
        """
        Extracts event handlers from the given HTML content.
        
        :returns: A dictionary of event handlers found in the HTML content.
                  Returns an empty dictionary if no event handlers are found.
        :raises Exception: If an error occurs during extraction.
        """
        try:
            # Extract event handlers using the ScriptExtractor
            event_handlers = self.extractor.extract_event_handlers()
            
            # Validate that the extracted event handlers are in dictionary format
            if not isinstance(event_handlers, dict):
                raise TypeError(f"Expected dict, got {type(event_handlers)}")  # Log error if the format is incorrect
            
            # Log event handlers if found, otherwise log no event handlers found
            if event_handlers:
                logger.info(f"Event handlers extracted: {event_handlers}")
            else:
                logger.info("No event handlers found.")
            
            return event_handlers  # Return the extracted event handlers
        except Exception as e:
            logger.error(f"Error extracting event handlers: {e}")  # Log error during extraction
            return {}  # Return an empty dictionary if extraction fails

# Example usage (this will only run if the file is executed as a script, not if it's imported as a module)
if __name__ == "__main__":
    html_content = "<html><body><div onclick='alert(\"Hello\");'></div></body></html>"
    event_extractor = EventHandlerExtractor(html_content)  # Initialize the extractor with HTML content
    event_handlers = event_extractor.extract_event_handlers()  # Extract event handlers
    print(event_handlers)  # Print the extracted event handlers
