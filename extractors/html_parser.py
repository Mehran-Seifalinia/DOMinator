"""
HTML Parser Module
Provides functionality for parsing and extracting information from HTML content.
"""

from typing import List, Optional, Tuple
from bs4 import BeautifulSoup
from utils.logger import get_logger
from traceback import format_exc
from html5lib import parse
from re import compile, IGNORECASE

logger = get_logger(__name__)

# Maximum allowed HTML size in bytes to prevent memory issues
MAX_HTML_SIZE = 10 * 1024 * 1024  # 10 MB

# Compiled regex for suspicious protocols in attribute values
SUSPICIOUS_PROTOCOLS = compile(r'^(javascript:|data:|vbscript:)', IGNORECASE)

class ScriptExtractor:
    """
    A class for extracting scripts and other elements from HTML content.
    
    This class provides methods to parse HTML content and extract various
    elements such as inline scripts and dangerous HTML elements.
    """
    
    def __init__(self, html: str) -> None:
        """
        Initialize the ScriptExtractor with HTML content.
        
        Args:
            html (str): The HTML content to parse
            
        Raises:
            TypeError: If HTML content is not a string
            ValueError: If HTML content is empty, too large, invalid, or parsing fails
        
        Note: Proxy and user_agent parameters have been removed as they are unused.
        """
        if not isinstance(html, str) or not html.strip():
            raise TypeError("HTML content must be a non-empty string.")
        
        if len(html) > MAX_HTML_SIZE:
            logger.error(f"HTML content exceeds maximum size ({MAX_HTML_SIZE} bytes).")
            raise ValueError("HTML content is too large.")
        
        if not self._validate_html(html):
            raise ValueError("Invalid HTML: The provided HTML is not valid.")
        
        try:
            # Use 'html5lib' for better position tracking and consistency with validation
            self.soup = BeautifulSoup(html, "html5lib")
        except Exception as e:
            logger.error(f"Error parsing HTML with BeautifulSoup: {str(e)}\n{format_exc()}")
            raise ValueError("Failed to parse the HTML content.")

    def _validate_html(self, html: str) -> bool:
        """
        Validate the HTML content using html5lib.
        
        Args:
            html (str): The HTML content to validate
        
        Returns:
            bool: True if HTML is valid, False otherwise
        
        Note:
            html5lib is tolerant and may not catch all structural errors strictly.
            For stricter validation, consider additional checks in future versions.
        """
        try:
            parse(html)
            return True
        except ValueError as e:
            logger.error(f"Invalid HTML content: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during HTML validation: {str(e)}\n{format_exc()}")
            return False

    def extract_inline_scripts(self) -> List[str]:
        """
        Extract all inline scripts from the HTML content.
        
        Returns:
            List[str]: List of unique inline script contents
        
        Note:
            This method extracts only scripts with actual content and
            removes duplicates. Scripts with type != 'text/javascript' are still extracted.
        """
        try:
            scripts: set[str] = set()
            for script in self.soup.find_all("script"):
                if script.string and script.string.strip():
                    scripts.add(script.string.strip())
            
            if not scripts:
                logger.debug("No inline scripts found in the HTML.")
            
            return list(scripts)
        
        except Exception as e:
            logger.error(f"Unexpected error extracting inline scripts: {str(e)}\n{format_exc()}")
            return []

    def get_dangerous_html_elements(self) -> List[Tuple[str, str, str, Optional[int]]]:
        """
        Get potentially dangerous HTML elements.
        
        This method checks for:
        - Event handler attributes starting with 'on' (e.g., onerror, onload) with non-empty values.
        - Attribute values starting with suspicious protocols (javascript:, data:, vbscript:).
        
        Returns:
            List[Tuple[str, str, str, Optional[int]]]: List of tuples containing
            (tag_name, attribute, value, line_number)
        """
        try:
            dangerous_elements = []
            for tag in self.soup.find_all(True):  # Consider limiting to common vulnerable tags for performance
                line = tag.sourceline if hasattr(tag, 'sourceline') else None
                for attr, value in tag.attrs.items():
                    if not isinstance(value, str):
                        continue
                    
                    value_lower = value.lower().strip()
                    is_dangerous = False
                    
                    # Check for event handlers
                    if attr.lower().startswith('on') and value_lower:
                        is_dangerous = True
                    
                    # Check for suspicious protocols in values
                    elif SUSPICIOUS_PROTOCOLS.match(value_lower):
                        is_dangerous = True
                    
                    if is_dangerous:
                        dangerous_elements.append((tag.name, attr, value, line))
            
            if not dangerous_elements:
                logger.debug("No dangerous HTML elements found.")
            
            return dangerous_elements
        
        except Exception as e:
            logger.error(f"Error extracting dangerous HTML elements: {str(e)}\n{format_exc()}")
            return []

if __name__ == "__main__":
    # Test with sample HTML
    sample_html = """
    <html>
    <body>
        <script>console.log("test");</script>
        <script>document.write("hello");</script>
        <script src="external.js"></script>
        <script>console.log("test");</script> <!-- Duplicate -->
    </body>
    </html>
    """
    extractor = ScriptExtractor(sample_html)
    scripts = extractor.extract_inline_scripts()
    logger.info(f"Extracted inline scripts: {scripts}")
