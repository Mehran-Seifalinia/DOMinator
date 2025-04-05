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
    'oncopy', 'oncut', 'onpaste',
    # HTML5 Events
    'onreset', 'onsearch', 'onstorage', 'onerror', 'onhashchange',
    'onpopstate', 'onanimationstart', 'onanimationend', 'onanimationiteration',
    'ontransitionend', 'onfullscreenchange', 'onfullscreenerror',
    # Mobile/Touch Events
    'ontouchstart', 'ontouchmove', 'ontouchend', 'ontouchcancel',
    'ongesturestart', 'ongesturechange', 'ongestureend',
    'onorientationchange', 'ondevicemotion', 'ondeviceorientation',
    'onpointerdown', 'onpointermove', 'onpointerup', 'onpointercancel',
    # Form-related events
    'oninput', 'onchange', 'onfocus', 'onblur', 'onselect',
    'onreset', 'onsubmit', 'oninvalid', 'onkeypress', 'onkeyup', 'onkeydown',
    # Audio/Video Events
    'onplay', 'onpause', 'onended', 'onvolumechange', 'onseeked',
    'onwaiting', 'oncanplay', 'oncanplaythrough', 'onloadeddata', 'onloadedmetadata',
    # Clipboard Events
    'oncopy', 'oncut', 'onpaste', 'onbeforecut', 'onbeforecopy',
    # Pointer Events (widely supported in modern browsers)
    'onpointerdown', 'onpointerup', 'onpointermove', 'onpointercancel', 'onpointerenter',
    'onpointerleave', 'onpointerover', 'onpointerout',
    # Drag and Drop events
    'ondragstart', 'ondrag', 'ondragover', 'ondragenter', 'ondragleave',
    'ondrop', 'ondragend', 
    # Media Events
    'onvolumechange', 'onplay', 'onpause', 'onended', 'onseeked', 'onseek', 'ontimeupdate',
    # File API Events
    'onabort', 'onerror', 'onload', 'onloadend', 'onloadstart', 'onprogress', 'ontimeout',
    'onratechange', 'onstalled', 'onsuspend',
    # Fetch and Service Worker Events
    'onfetch', 'oninstall', 'onactivate', 'onmessage', 'onpush', 'onpushsubscriptionchange',
    'onbeforeinstallprompt', 'onunload', 'onbeforeunload', 'onpagehide', 'onpageshow'
]

class EventHandler:
    def __init__(self, tag: str, attribute: str, handler: str):
        if not isinstance(tag, str) or not tag.strip():
            raise ValueError("Tag must be a non-empty string.")
        if not isinstance(attribute, str) or not attribute.strip():
            raise ValueError("Attribute must be a non-empty string.")
        if not isinstance(handler, str) or not handler.strip():
            raise ValueError("Handler must be a non-empty string.")
        self.tag = tag
        self.attribute = attribute
        self.handler = handler


    def __repr__(self) -> str:
        return f"<EventHandler tag={self.tag} attribute={self.attribute}>"

class EventHandlerExtractor:
    def __init__(self, html: str):
        if not html or not isinstance(html, str):
            logger.error("Invalid input: HTML must be a non-empty string.")
            raise ValueError("HTML content must be a non-empty string.")
        
        try:
            self.soup = BeautifulSoup(html, "html.parser")
        except Exception as e:
            logger.error(f"Error parsing HTML: {e}")
            raise ValueError(f"Error parsing HTML: {e}")

    def extract_event_handlers(self) -> List[EventHandler]:
        """Extract event handlers from HTML attributes."""
        event_handlers = []
        
        # Create a set from EVENT_HANDLER_ATTRIBUTES for faster lookups
        handler_attributes = set(EVENT_HANDLER_ATTRIBUTES)
        
        # Iterate over all tags in the HTML
        for tag in self.soup.find_all(True):  # True means all tags
            # Check if any event handler attributes are in the tag
            event_attrs = set(tag.attrs).intersection(handler_attributes)
            for attribute in event_attrs:
                handler = tag[attribute].strip()
                if handler:
                    event_handlers.append(EventHandler(tag=str(tag.name), attribute=attribute, handler=handler))
                    logger.debug(f"Extracted handler from tag: {tag.name}, attribute: {attribute}")
        
        # Log results
        if not event_handlers:
            logger.info("No event handlers found.")
        else:
            logger.info(f"Successfully extracted {len(event_handlers)} event handlers.")
            if len(event_handlers) > 100:
                logger.warning("More than 100 event handlers found.")
                # Optionally log some details for debugging
                logger.debug(f"Extracted handlers: {event_handlers[:5]}...")  # First 5 handlers as a sample
        
        return event_handlers

    def to_json(self, event_handlers: List[EventHandler]) -> str:
        """Convert event handlers to JSON format."""
        if not event_handlers:
            logger.warning("No event handlers to convert to JSON.")
        
        try:
            # Convert event handlers to JSON format
            return json.dumps([self.event_handler_to_dict(eh) for eh in event_handlers], indent=4)
        except (TypeError, ValueError) as e:
            logger.error(f"Error converting event handlers to JSON: {e}")
            raise


    @staticmethod
    def event_handler_to_dict(event_handler: EventHandler) -> Dict:
        """Convert EventHandler object to dictionary."""
        # Ensure all attributes are properly handled (e.g., if None, set to an empty string)
        return {
            'tag': event_handler.tag or '',
            'attribute': event_handler.attribute or '',
            'handler': event_handler.handler or ''
        }

