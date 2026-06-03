"""
Event Handler Extractor Module
Extracts and analyzes event handlers from HTML content for DOM XSS detection.
"""

from json import dumps
from typing import List, Dict, Any

from bs4 import BeautifulSoup
from utils.logger import get_logger
from utils.patterns import EVENT_HANDLER_ATTRIBUTES, get_risk_level
from utils.analysis_result import EventHandler, AnalysisResult

logger = get_logger(__name__)

# Maximum allowed HTML size in bytes to prevent memory issues
MAX_HTML_SIZE = 10 * 1024 * 1024  # 10 MB


class EventHandlerExtractor:
    """
    A class for extracting and analyzing event handlers from HTML content.

    This class parses HTML content and identifies event handlers that could potentially
    be used in DOM XSS attacks. It provides methods to extract handlers and convert
    them to various formats.

    Note: Extraction is limited to inline event handler attributes (e.g., onclick).
    Dynamic handlers added via JavaScript (e.g., addEventListener) require separate
    dynamic analysis.
    """

    def __init__(self, html: str, url: str = None) -> None:
        """
        Initialize the EventHandlerExtractor with HTML content.

        Args:
            html (str): The HTML content to parse.
            url (str, optional): The source URL of the HTML. Defaults to None.

        Raises:
            ValueError: If HTML content is invalid, empty, too large, or parsing fails.
        """
        self.url = url
        if not isinstance(html, str) or not html.strip():
            logger.error("Invalid input: HTML must be a non-empty string.")
            raise ValueError("HTML content must be a non-empty string.")

        if len(html.encode('utf-8')) > MAX_HTML_SIZE:
            logger.error(f"HTML content exceeds maximum size ({MAX_HTML_SIZE} bytes).")
            raise ValueError("HTML content is too large.")

        try:
            # Use 'html5lib' for better position tracking (sourceline and sourcepos)
            self.soup = BeautifulSoup(html, "html5lib")
        except Exception as e:
            logger.error(f"Error parsing HTML: {str(e)}")
            raise ValueError(f"Error parsing HTML: {str(e)}")

    def extract_event_handlers(self) -> Dict[str, List[EventHandler]]:
        """
        Extract event handlers from HTML attributes.

        This method scans all HTML tags for event handler attributes and creates
        EventHandler objects for each found handler. Attributes are normalized to
        lowercase for consistent matching. Empty handlers are skipped.

        Returns:
            Dict[str, List[EventHandler]]: A dictionary mapping event types to lists
            of EventHandler objects.
        """
        event_handlers: Dict[str, List[EventHandler]] = {}
        handler_found = False

        for tag in self.soup.find_all(True):
            line = tag.sourceline if hasattr(tag, 'sourceline') else None
            column = tag.sourcepos if hasattr(tag, 'sourcepos') else None

            for attr_name, attr_value in tag.attrs.items():
                # Normalize to lowercase for case-insensitive matching
                attr_name_lower = attr_name.lower()
                if attr_name_lower in EVENT_HANDLER_ATTRIBUTES:
                    # Skip empty handlers
                    if not attr_value.strip():
                        continue

                    if attr_name_lower not in event_handlers:
                        event_handlers[attr_name_lower] = []

                    risk_level = get_risk_level(attr_name_lower)
                    handler = EventHandler(
                        tag=str(tag.name),
                        attribute=attr_name_lower,
                        handler=str(attr_value),
                        line=line if line is not None else None,
                        column=column if column is not None else None,
                        risk_level=risk_level
                    )
                    event_handlers[attr_name_lower].append(handler)

                    # Log each extracted handler (truncate sensitive data)
                    truncated_handler = attr_value[:50] + "..." if len(attr_value) > 50 else attr_value
                    logger.debug(f"Extracted handler - tag: {tag.name}, attr: {attr_name_lower}, handler: {truncated_handler!r}")
                    handler_found = True

        if not handler_found:
            logger.debug("No event handlers found.")

        total_handlers = sum(len(handlers) for handlers in event_handlers.values())
        if total_handlers > 100:
            logger.warning(f"More than 100 event handlers found ({total_handlers}). Consider optimizing scan.")

        logger.debug(f"Successfully extracted {total_handlers} event handlers.")
        return event_handlers

    def to_json(self, event_handlers: Dict[str, List[EventHandler]], indent: int = 4) -> str:
        """
        Convert event handlers to JSON format.

        Args:
            event_handlers (Dict[str, List[EventHandler]]): Dictionary of event handlers to convert.
            indent (int, optional): Number of spaces for JSON indentation. Defaults to 4.
                Set to None for compact output.

        Returns:
            str: A JSON string representing the event handlers.

        Raises:
            ValueError: If no event handlers are available for conversion.
            TypeError: If conversion to JSON fails.
        """
        if not event_handlers:
            logger.error("No event handlers to convert to JSON.")
            raise ValueError("No event handlers available for conversion to JSON.")

        try:
            json_data = {
                event_type: [handler.to_dict() for handler in handlers]
                for event_type, handlers in event_handlers.items()
            }
            return dumps(json_data, indent=indent)
        except (TypeError, ValueError) as e:
            logger.error(f"Error converting event handlers to JSON: {str(e)}")
            raise

    def extract(self) -> AnalysisResult:
        """
        Extract event handlers from the already loaded HTML.

        Returns:
            AnalysisResult: Result of the extraction process.
        """
        try:
            result = AnalysisResult()
            result.url = self.url if self.url else "unknown"

            event_handlers = self.extract_event_handlers()
            for event_type, handlers in event_handlers.items():
                for handler in handlers:
                    result.add_event_handler(event_type, handler)

            result.set_completed()
            return result

        except Exception as e:
            logger.error(f"Error extracting event handlers from {self.url}: {str(e)}")
            result = AnalysisResult()
            result.url = self.url
            result.set_error(str(e))
            return result
