import json
from typing import List, Optional
from bs4 import BeautifulSoup
from utils.logger import get_logger
from traceback import format_exc
from html5lib import parse

# Logger setup
logger = get_logger()

def validate_html(html: str) -> bool:
    """Validate the HTML content using html5lib."""
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
    def __init__(self, html: str, proxy: Optional[str] = None, user_agent: Optional[str] = None):
        # Ensure the HTML input is a valid non-empty string
        if not isinstance(html, str) or not html.strip():
            raise TypeError("HTML content must be a non-empty string.")
        
        # Validate HTML content
        if not validate_html(html):
            raise ValueError("Invalid HTML: The provided HTML is not valid.")
        
        # Parse the HTML content into BeautifulSoup object
        try:
            self.soup = BeautifulSoup(html, "html.parser")
        except Exception as e:
            logger.error(f"Error parsing HTML with BeautifulSoup: {e}\n{format_exc()}")
            raise ValueError("Failed to parse the HTML content.")

    def extract_inline_scripts(self) -> List[str]:
        """Extract all inline scripts without filtering."""
        try:
            # Extract all inline scripts (only those with content)
            scripts = [
                script.string.strip() for script in self.soup.find_all("script") 
                if script.string  # Only include scripts with inline content
            ]
            
            if not scripts:
                logger.debug("No inline scripts found in the HTML.")
            
            # Remove duplicates using set and return as list
            return list(set(scripts))
        
        except Exception as e:
            logger.error(f"Unexpected error extracting inline scripts: {e}\n{format_exc()}")
            return []

    def get_scripts(self) -> List[str]:
        """Return all extracted inline scripts."""
        return self.extract_inline_scripts()

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
