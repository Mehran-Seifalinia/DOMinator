"""
HTML Parser Module
Provides functionality for parsing and extracting information from HTML content.
"""

from typing import List, Optional, Set
from bs4 import BeautifulSoup
from utils.logger import get_logger
from traceback import format_exc
from html5lib import parse

logger = get_logger(__name__)

def validate_html(html: str) -> bool:
    """
    Validate the HTML content using html5lib.
    
    Args:
        html (str): The HTML content to validate
        
    Returns:
        bool: True if HTML is valid, False otherwise
        
    Note:
        This function uses html5lib to validate HTML content and handles
        various types of validation errors.
    """
    try:
        parse(html)
        return True
    except ValueError as e:
        logger.error(f"Invalid HTML content: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during HTML validation: {e}\n{format_exc()}")
        return False

class ScriptExtractor:
    """
    A class for extracting scripts and other elements from HTML content.
    
    This class provides methods to parse HTML content and extract various
    elements such as inline scripts and dangerous HTML elements.
    """
    
    def __init__(self, html: str, proxy: Optional[str] = None, user_agent: Optional[str] = None) -> None:
        """
        Initialize the ScriptExtractor with HTML content.
        
        Args:
            html (str): The HTML content to parse
            proxy (Optional[str]): Proxy configuration for external requests
            user_agent (Optional[str]): Custom user agent for requests
            
        Raises:
            TypeError: If HTML content is not a string
            ValueError: If HTML content is invalid or parsing fails
        """
        if not isinstance(html, str) or not html.strip():
            raise TypeError("HTML content must be a non-empty string.")
        
        if not validate_html(html):
            raise ValueError("Invalid HTML: The provided HTML is not valid.")
        
        try:
            self.soup = BeautifulSoup(html, "html.parser")
            self.proxy = proxy
            self.user_agent = user_agent
        except Exception as e:
            logger.error(f"Error parsing HTML with BeautifulSoup: {e}\n{format_exc()}")
            raise ValueError("Failed to parse the HTML content.")

    def extract_inline_scripts(self) -> List[str]:
        """
        Extract all inline scripts from the HTML content.
        
        Returns:
            List[str]: List of unique inline script contents
            
        Note:
            This method extracts only scripts with actual content and
            removes duplicates.
        """
        try:
            scripts: Set[str] = set()
            for script in self.soup.find_all("script"):
                if script.string:
                    scripts.add(script.string.strip())
            
            if not scripts:
                logger.debug("No inline scripts found in the HTML.")
            
            return list(scripts)
        
        except Exception as e:
            logger.error(f"Unexpected error extracting inline scripts: {e}\n{format_exc()}")
            return []

    def get_scripts(self) -> List[str]:
        """
        Get all extracted inline scripts.
        
        Returns:
            List[str]: List of all extracted inline scripts
        """
        return self.extract_inline_scripts()

    def get_dangerous_html_elements(self) -> List[tuple]:
        """
        Get potentially dangerous HTML elements.
        
        Returns:
            List[tuple]: List of tuples containing (tag, attribute, value, line)
        """
        try:
            dangerous_elements = []
            for tag in self.soup.find_all(True):
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and any(
                        keyword in value.lower() for keyword in
                        ['javascript:', 'data:', 'vbscript:', 'onerror', 'onload']
                    ):
                        dangerous_elements.append((
                            tag.name,
                            attr,
                            value,
                            tag.sourceline if hasattr(tag, 'sourceline') else None
                        ))
            return dangerous_elements
        except Exception as e:
            logger.error(f"Error extracting dangerous HTML elements: {e}\n{format_exc()}")
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
    scripts = extractor.get_scripts()
    print("Extracted inline scripts:", scripts)
