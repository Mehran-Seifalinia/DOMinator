import re
from bs4 import BeautifulSoup
from utils.logger import get_logger
from typing import List, Dict

logger = get_logger(__name__)

# Define event handler attributes to look for in HTML
EVENT_HANDLER_ATTRIBUTES = [
    'onclick', 'onmouseover', 'onmouseout', 'onload', 'onerror', 'onfocus',
    'onblur', 'onsubmit', 'onchange', 'onkeydown', 'onkeyup', 'onkeypress',
    'onresize', 'onunload', 'onabort', 'oninput', 'onselect'
]

class EventHandlerExtractor:
    def __init__(self, html: str):
        if not html or not isinstance(html, str):
            raise ValueError("HTML content must be a non-empty string.")
        
        # Parsing the HTML using BeautifulSoup
        try:
            self.soup = BeautifulSoup(html, "html.parser")
        except Exception as e:
            logger.error(f"Error parsing HTML: {e}")
            raise

    def extract_event_handlers(self) -> List[Dict[str, str]]:
        """Extract event handlers from HTML attributes."""
        event_handlers = []

        for tag in self.soup.find_all(True):  # Find all tags in the HTML
            for attribute in EVENT_HANDLER_ATTRIBUTES:
                if tag.has_attr(attribute):
                    handler = tag[attribute].strip()
                    if handler:
                        # Extracting event handler and storing them in a structured way
                        event_handlers.append({
                            "tag": str(tag.name),
                            "attribute": attribute,
                            "handler": handler
                        })
                    
        if not event_handlers:
            logger.info("No event handlers found.")
        else:
            logger.info(f"Successfully extracted {len(event_handlers)} event handlers.")

        return event_handlers

