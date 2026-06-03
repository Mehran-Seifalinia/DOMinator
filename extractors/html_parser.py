"""
HTML Parser Module
Provides functionality for parsing and extracting information from HTML content.
"""

from typing import List, Optional, Tuple
from bs4 import BeautifulSoup
from utils.logger import get_logger
from utils.patterns import EVENT_HANDLER_ATTRIBUTES
from traceback import format_exc
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
        if not isinstance(html, str) or not html.strip():
            raise TypeError("HTML content must be a non-empty string.")
        
        if len(html) > MAX_HTML_SIZE:
            logger.error(f"HTML content exceeds maximum size ({MAX_HTML_SIZE} bytes).")
            raise ValueError("HTML content is too large.")
        
        self.html = html
        
        try:
            self.soup = BeautifulSoup(html, "html5lib")
        except Exception as e:
            logger.error(f"Error parsing HTML: {str(e)}\n{format_exc()}")
            raise ValueError("Failed to parse the HTML content.")

    def extract_inline_scripts(self) -> List[Tuple[int, str]]:
        try:
            scripts: List[Tuple[int, str]] = []
            seen: set[str] = set()
            
            for script in self.soup.find_all("script"):
                if script.string and script.string.strip():
                    content = script.string.strip()
                    if content in seen:
                        continue
                    seen.add(content)
                    
                    line_no = getattr(script, 'sourceline', None)
                    if line_no is None:
                        # fallback: find the exact script tag string
                        script_str = str(script)
                        pos = self.html.find(script_str)
                        if pos != -1:
                            line_no = self.html.count('\n', 0, pos) + 1
                        else:
                            line_no = 0
                    scripts.append((line_no if line_no else 0, content))
            
            return scripts
        except Exception as e:
            logger.error(f"Error extracting inline scripts: {e}")
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
                    if attr.lower() in EVENT_HANDLER_ATTRIBUTES and value_lower:
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
