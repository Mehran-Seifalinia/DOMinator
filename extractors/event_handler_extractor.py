import re
import json
from bs4 import BeautifulSoup, ParserError
from utils.logger import get_logger
from typing import List, Dict

logger = get_logger(__name__)

# Define event handler attributes to look for in HTML
EVENT_HANDLER_ATTRIBUTES = [
    'onload', 'onerror', 'onbeforeunload', 'onunload',
    'onpageshow', 'onpagehide', 'onresize', 'onscroll',
    'onclick', 'ondblclick', 'onmouseover', 'onmouseout',
    'oncontextmenu', 'onkeydown', 'onkeyup', 'onkeypress',
    'onchange', 'oninput', 'oninvalid', 'onselect', 'onsubmit',
    'onreset', 'onfocus', 'onblur', 'onfocusin', 'onfocusout',
    'onabort', 'oncanplay', 'oncanplaythrough', 'ondurationchange',
    'onemptied', 'onended', 'onloadeddata', 'onloadedmetadata',
    'onloadstart', 'onpause', 'onplay', 'onplaying', 'onseeked',
    'onseeking', 'onstalled', 'onsuspend', 'ontimeupdate',
    'onvolumechange', 'onwaiting',
    'ondrag', 'ondragend', 'ondragenter', 'ondragleave',
    'ondragover', 'ondragstart', 'ondrop',
    'oncopy', 'oncut', 'onpaste'
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
        if not html or not isinstance(html, str) or not html.strip():
            logger.error("Invalid input: HTML must be a non-empty string.")
            raise ValueError("HTML content must be a non-empty string.")
        
        try:
            self.soup = BeautifulSoup(html, "html.parser")
        except ParserError as e:
            logger.error(f"Error parsing HTML: {e}")
            raise

    def extract_event_handlers(self) -> List[EventHandler]:
        """Extract event handlers from HTML attributes."""
        event_handlers = []
    
        # Iterate over all tags in the HTML
        for tag in self.soup.find_all(True):  # True means all tags
            for attribute in EVENT_HANDLER_ATTRIBUTES:
                if attribute in tag.attrs:
                    handler = tag[attribute].strip()
                    if handler:
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
        return json.dumps([self.event_handler_to_dict(eh) for eh in event_handlers], indent=4)

    @staticmethod
    def event_handler_to_dict(event_handler: EventHandler) -> Dict:
        """Convert EventHandler object to dictionary."""
        return {
            'tag': event_handler.tag,
            'attribute': event_handler.attribute,
            'handler': event_handler.handler
        }
