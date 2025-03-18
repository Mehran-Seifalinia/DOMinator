from bs4 import BeautifulSoup
from logging import getLogger, basicConfig, INFO, error
from os import getenv
from typing import Dict, List, Union

# Setup logger with dynamic log level
log_level = getenv("LOG_LEVEL", "INFO").upper()
log_level = getattr(globals(), log_level, INFO)  # Ensure safe resolution of log level
if log_level not in globals():
    logger.error(f"Invalid log level '{log_level}', falling back to INFO.")
basicConfig(level=log_level, format="%(levelname)s: %(message)s")
logger = getLogger(__name__)

class ScriptExtractor:
    """Extracts inline scripts, external scripts, event handlers, and inline styles from HTML content."""

    def __init__(self, html: str):
        if not html or not isinstance(html, str):
            raise ValueError("Invalid input: HTML content must be a non-empty string.")
        self.soup = BeautifulSoup(html, "html.parser")

    def extract_inline_scripts(self) -> List[str]:
        """Extracts inline JavaScript from <script> tags."""
        try:
            return [script.text for script in self.soup.find_all("script") if script.text.strip()]
        except Exception as e:
            logger.error(f"Error extracting inline scripts: {e}")
            return []

    def extract_external_scripts(self) -> List[str]:
        """Extracts external <script> sources (src attributes)."""
        try:
            return [script["src"].strip() for script in self.soup.find_all("script", src=True) if script.get("src", "").strip()]
        except Exception as e:
            logger.error(f"Error extracting external scripts: {e}")
            return []

    def extract_event_handlers(self) -> Dict[str, Dict[str, str]]:
        """Extracts inline event handlers (e.g., onclick, onmouseover) from HTML elements."""
        try:
            return {
                tag.name: {attr: value.strip() for attr, value in tag.attrs.items() if attr.lower().startswith("on") and value.strip()}
                for tag in self.soup.find_all(True)
            }
        except Exception as e:
            logger.error(f"Error extracting event handlers: {e}")
            return {}


    def extract_inline_styles(self) -> Dict[str, str]:
        """Extracts inline styles from HTML elements."""
        try:
            return {
                f"{tag.name}[style]": tag["style"].strip()
                for tag in self.soup.find_all(style=True) if tag.get("style", "").strip()
            }
        except Exception as e:
            logger.error(f"Error extracting inline styles: {e}")
            return {}

    def get_scripts(self) -> Dict[str, Union[List[str], Dict[str, Dict[str, str]]]]:
        """Extracts all scripts, event handlers, and inline styles."""
        return {
            "inline_scripts": self.extract_inline_scripts(),
            "external_scripts": self.extract_external_scripts(),
            "event_handlers": self.extract_event_handlers(),
            "inline_styles": self.extract_inline_styles(),
        }
