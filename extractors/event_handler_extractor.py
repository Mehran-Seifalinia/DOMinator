import json
from bs4 import BeautifulSoup
from utils.logger import get_logger
from typing import List, Dict, Optional
from dataclasses import dataclass

logger = get_logger(__name__)

# Define event handler attributes to look for in HTML (removed duplicates)
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
    'onsearch', 'onstorage', 'onhashchange',
    'onpopstate', 'onanimationstart', 'onanimationend', 'onanimationiteration',
    'ontransitionend', 'onfullscreenchange', 'onfullscreenerror',
    # Mobile/Touch Events
    'ontouchstart', 'ontouchmove', 'ontouchend', 'ontouchcancel',
    'ongesturestart', 'ongesturechange', 'ongestureend',
    'onorientationchange', 'ondevicemotion', 'ondeviceorientation',
    'onpointerdown', 'onpointermove', 'onpointerup', 'onpointercancel',
    # Form-related events
    'onreset', 'onsubmit', 'oninvalid', 'onkeypress', 'onkeyup', 'onkeydown',
    # Audio/Video Events
    'onplay', 'onpause', 'onended', 'onvolumechange', 'onseeked',
    'onwaiting', 'oncanplay', 'oncanplaythrough', 'onloadeddata', 'onloadedmetadata',
    # Clipboard Events
    'onbeforecut', 'onbeforecopy',
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

@dataclass
class EventHandler:
    tag: str
    attribute: str
    handler: str
    line: Optional[int] = None
    column: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            'tag': self.tag,
            'attribute': self.attribute,
            'handler': self.handler,
            'line': self.line,
            'column': self.column
        }

class EventHandlerExtractor:
    def __init__(self, html: str):
        """
        Initializes the EventHandlerExtractor with the given HTML content.
        :param html: The HTML content to parse.
        """
        if not html or not isinstance(html, str):
            logger.error("Invalid input: HTML must be a non-empty string.")
            raise ValueError("HTML content must be a non-empty string.")
        
        try:
            self.soup = BeautifulSoup(html, "html.parser")
        except Exception as e:
            logger.error(f"Error parsing HTML: {e}")
            raise ValueError(f"Error parsing HTML: {e}")

    def extract_event_handlers(self) -> Dict[str, List[EventHandler]]:
        """
        Extract event handlers from HTML attributes.
        :return: A dictionary mapping event types to lists of EventHandler objects.
        """
        event_handlers: Dict[str, List[EventHandler]] = {}
        
        # Iterate over all tags in the HTML
        for tag in self.soup.find_all(True):  # True means all tags
            # Get the line number if available
            line = tag.sourceline if hasattr(tag, 'sourceline') else None
            column = tag.sourcepos if hasattr(tag, 'sourcepos') else None
            
            # Check all attributes of the tag
            for attr_name, attr_value in tag.attrs.items():
                if attr_name.startswith('on'):
                    if attr_name not in event_handlers:
                        event_handlers[attr_name] = []
                    
                    handler = EventHandler(
                        tag=str(tag.name),
                        attribute=attr_name,
                        handler=str(attr_value),
                        line=line,
                        column=column
                    )
                    event_handlers[attr_name].append(handler)
                    logger.debug(f"Extracted handler from tag: {tag.name}, attribute: {attr_name}")
        
        # Log results
        if not event_handlers:
            logger.info("No event handlers found.")
        else:
            total_handlers = sum(len(handlers) for handlers in event_handlers.values())
            logger.info(f"Successfully extracted {total_handlers} event handlers.")
            if total_handlers > 100:
                logger.warning("More than 100 event handlers found.")
                # Optionally log some details for debugging
                logger.debug(f"First 5 handlers: {list(event_handlers.items())[:5]}")
        
        return event_handlers

    def to_json(self, event_handlers: Dict[str, List[EventHandler]]) -> str:
        """
        Convert event handlers to JSON format.
        :param event_handlers: Dictionary of event handlers to convert.
        :return: A JSON string representing the event handlers.
        """
        if not event_handlers:
            logger.error("No event handlers to convert to JSON.")
            raise ValueError("No event handlers available for conversion to JSON.")
        
        try:
            # Convert event handlers to JSON format
            json_data = {
                event_type: [handler.to_dict() for handler in handlers]
                for event_type, handlers in event_handlers.items()
            }
            return json.dumps(json_data, indent=4)
        except (TypeError, ValueError) as e:
            logger.error(f"Error converting event handlers to JSON: {e}")
            raise
