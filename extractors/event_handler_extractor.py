import re
import json
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

class EventHandler:
    def __init__(self, tag: str, attribute: str, handler: str):
        self.tag = tag
        self.attribute = attribute
        self.handler = handler

    def __repr__(self):
        return f"<EventHandler tag={self.tag} attribute={self.attribute}>"

class EventHandlerExtractor:
    def __init__(self, html: str):
        if not html or not isinstance(html, str):
            logger.error("Invalid input: HTML must be a non-empty string.")
            raise ValueError("HTML content must be a non-empty string.")
        
        # Parsing the HTML using BeautifulSoup
        try:
            self.soup = BeautifulSoup(html, "html.parser")
        except Exception as e:
            logger.error(f"Error parsing HTML: {e}")
            raise

    def extract_event_handlers(self) -> List[EventHandler]:
        """Extract event handlers from HTML attributes."""
        event_handlers = []

        for tag in self.soup.find_all(True):  # Find all tags in the HTML
            for attribute in tag.attrs:  # Check only existing attributes
                if attribute in EVENT_HANDLER_ATTRIBUTES:
                    handler = tag[attribute].strip()
                    if handler:
                        # Extracting event handler and storing them in a structured way
                        event_handlers.append(EventHandler(tag=str(tag.name), attribute=attribute, handler=handler))
                        logger.debug(f"Extracted handler from tag: {tag.name}, attribute: {attribute}")

        if not event_handlers:
            logger.info("No event handlers found.")
        else:
            logger.info(f"Successfully extracted {len(event_handlers)} event handlers.")
            if len(event_handlers) > 100:
                logger.warning("More than 100 event handlers found.")

        return event_handlers

    def to_json(self, event_handlers: List[EventHandler]) -> str:
        """Convert event handlers to JSON format."""
        return json.dumps([eh.__dict__ for eh in event_handlers], indent=4)

