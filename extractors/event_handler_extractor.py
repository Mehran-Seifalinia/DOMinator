"""
Event Handler Extractor Module
Extracts and analyzes event handlers from HTML content for DOM XSS detection.
"""

from json import dumps
from bs4 import BeautifulSoup
from utils.logger import get_logger
from typing import List, Dict, Optional, Any
from utils.patterns import EVENT_HANDLER_ATTRIBUTES, get_risk_level
from utils.analysis_result import EventHandler, AnalysisResult

logger = get_logger(__name__)

class EventHandlerExtractor:
    """
    A class for extracting and analyzing event handlers from HTML content.
    
    This class parses HTML content and identifies event handlers that could potentially
    be used in DOM XSS attacks. It provides methods to extract handlers and convert
    them to various formats.
    """
    
    def __init__(self, html: str) -> None:
        """
        Initialize the EventHandlerExtractor with HTML content.
        
        Args:
            html (str): The HTML content to parse
            
        Raises:
            ValueError: If HTML content is invalid or parsing fails
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
        
        Returns:
            Dict[str, List[EventHandler]]: A dictionary mapping event types to lists of EventHandler objects
            
        Note:
            This method scans all HTML tags for event handler attributes and creates
            EventHandler objects for each found handler.
        """
        event_handlers: Dict[str, List[EventHandler]] = {}
        
        for tag in self.soup.find_all(True):
            line = tag.sourceline if hasattr(tag, 'sourceline') else None
            column = tag.sourcepos if hasattr(tag, 'sourcepos') else None
            
            for attr_name, attr_value in tag.attrs.items():
                if attr_name in EVENT_HANDLER_ATTRIBUTES:
                    if attr_name not in event_handlers:
                        event_handlers[attr_name] = []
                    
                    risk_level = get_risk_level(attr_name)
                    handler = EventHandler(
                        tag=str(tag.name),
                        attribute=attr_name,
                        handler=str(attr_value),
                        line=line,
                        column=column,
                        risk_level=risk_level
                    )
                    event_handlers[attr_name].append(handler)
                    logger.debug(f"Extracted handler from tag: {tag.name}, attribute: {attr_name}")
        
        if not event_handlers:
            logger.info("No event handlers found.")
        else:
            total_handlers = sum(len(handlers) for handlers in event_handlers.values())
            logger.info(f"Successfully extracted {total_handlers} event handlers.")
            if total_handlers > 100:
                logger.warning("More than 100 event handlers found.")
                logger.debug(f"First 5 handlers: {list(event_handlers.items())[:5]}")
        
        return event_handlers

    def to_json(self, event_handlers: Dict[str, List[EventHandler]]) -> str:
        """
        Convert event handlers to JSON format.
        
        Args:
            event_handlers (Dict[str, List[EventHandler]]): Dictionary of event handlers to convert
            
        Returns:
            str: A JSON string representing the event handlers
            
        Raises:
            ValueError: If no event handlers are available for conversion
            TypeError: If conversion to JSON fails
        """
        if not event_handlers:
            logger.error("No event handlers to convert to JSON.")
            raise ValueError("No event handlers available for conversion to JSON.")
        
        try:
            json_data = {
                event_type: [handler.to_dict() for handler in handlers]
                for event_type, handlers in event_handlers.items()
            }
            return dumps(json_data, indent=4)
        except (TypeError, ValueError) as e:
            logger.error(f"Error converting event handlers to JSON: {e}")
            raise

    async def extract(self, session: Any, url: str, timeout: int) -> AnalysisResult:
        """
        Extract event handlers from the given URL.
        
        Args:
            session (Any): HTTP session for making requests
            url (str): Target URL to analyze
            timeout (int): Request timeout in seconds
            
        Returns:
            AnalysisResult: Result of the extraction process
            
        Note:
            The session and timeout parameters are reserved for future use
            when implementing remote URL fetching functionality.
        """
        try:
            result = AnalysisResult()
            result.url = url
            
            event_handlers = self.extract_event_handlers()
            for event_type, handlers in event_handlers.items():
                for handler in handlers:
                    result.add_event_handler(event_type, handler)
            
            result.set_completed()
            return result
            
        except Exception as e:
            logger.error(f"Error extracting event handlers from {url}: {e}")
            result = AnalysisResult()
            result.url = url
            result.set_error(str(e))
            return result
