from os import getenv
from typing import Dict, List
from collections import defaultdict
from dataclasses import dataclass
from bs4 import BeautifulSoup
from logging import getLogger, basicConfig, INFO, DEBUG, WARNING, ERROR, CRITICAL
from traceback import format_exc
from concurrent.futures import ThreadPoolExecutor, as_completed
from html5lib import parse
from functools import lru_cache

# Setup logger with dynamic log level
log_levels = {
    "DEBUG": DEBUG,
    "INFO": INFO,
    "WARNING": WARNING,
    "ERROR": ERROR,
    "CRITICAL": CRITICAL
}

log_level = getenv("LOG_LEVEL", "INFO").upper()
log_level = log_levels.get(log_level, INFO)

basicConfig(level=log_level, format="%(levelname)s: %(message)s")
logger = getLogger(__name__)

def validate_html(html: str) -> bool:
    """Validates the HTML content using html5lib."""
    try:
        parse(html)  # Try parsing the HTML
        return True
    except ValueError as e:  # Handle specific exception for invalid HTML
        logger.error(f"Invalid HTML content: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during HTML validation: {e}\n{format_exc()}")
        return False

@dataclass
class ScriptData:
    inline_scripts: List[str]
    external_scripts: List[str]
    event_handlers: Dict[str, List[Dict[str, str]]]
    inline_styles: Dict[str, List[str]]

    def __init__(self, inline_scripts=None, external_scripts=None, event_handlers=None, inline_styles=None):
        self.inline_scripts = inline_scripts or []
        self.external_scripts = external_scripts or []
        self.event_handlers = event_handlers or defaultdict(list)
        self.inline_styles = inline_styles or defaultdict(list)

    def __str__(self) -> str:
        """Return a formatted string representation of extracted data."""
        return (
            f"Inline Scripts: {len(self.inline_scripts)}\n"
            f"External Scripts: {len(self.external_scripts)}\n"
            f"Event Handlers: {sum(len(v) for v in self.event_handlers.values())} handlers\n"
            f"Inline Styles: {sum(len(v) for v in self.inline_styles.values())} elements"
        )

class ScriptExtractor:
    """Extracts inline scripts, external scripts, event handlers, and inline styles from HTML content."""

    def __init__(self, html: str):
        if not html or not isinstance(html, str) or not html.strip():
            raise ValueError("Invalid input: HTML content must be a non-empty string.")
        
        # Validate HTML content before processing
        if not validate_html(html):
            raise ValueError("Invalid HTML: The provided HTML is not valid.")
        
        # Now we can safely parse the HTML with BeautifulSoup
        self.soup = BeautifulSoup(html, "html.parser")

    @lru_cache()
    def extract_scripts(self, script_type: str, attr_name: str = "src") -> List[str]:
        """General method to extract scripts based on type and attribute."""
        try:
            if script_type == 'inline':
                scripts = [script.text.strip() for script in self.soup.find_all("script") if script.text.strip()]
            else:
                scripts = [script.get(attr_name) for script in self.soup.find_all("script", src=True) if script.get(attr_name)]

            if not scripts:
                logger.warning(f"No {script_type} scripts found.")
            return scripts
        except Exception as e:
            logger.error(f"Unexpected error extracting {script_type} scripts: {e}\n{format_exc()}")
            return []

    @lru_cache()
    def extract_inline_scripts(self) -> List[str]:
        return self.extract_scripts('inline')

    @lru_cache()
    def extract_external_scripts(self) -> List[str]:
        return self.extract_scripts('external')

    @lru_cache()
    def extract_event_handlers(self) -> Dict[str, List[Dict[str, str]]]:
        """Extracts inline event handlers (e.g., onclick, onmouseover) from HTML elements."""
        try:
            event_handlers = defaultdict(list)
            for tag in self.soup.find_all(True):
                handlers = {attr: value.strip() for attr, value in tag.attrs.items() if attr.lower().startswith("on") and value.strip()}
                if handlers:
                    event_handlers[tag.name].append(handlers)
            if not event_handlers:
                logger.warning("No event handlers found.")
            return dict(event_handlers)
        except Exception as e:
            logger.error(f"Unexpected error extracting event handlers: {e}\n{format_exc()}")
            return {}

    @lru_cache()
    def extract_inline_styles(self) -> Dict[str, List[str]]:
        """Extracts inline styles from HTML elements and <style> tags."""
        try:
            styles = defaultdict(list)
            
            for tag in self.soup.find_all(style=True):
                styles[tag.name].append(tag["style"].strip())

            for style_tag in self.soup.find_all("style"):
                if style_tag.string:
                    styles["style"].append(style_tag.string.strip())

            return dict(styles)
        except Exception as e:
            logger.error(f"Error extracting inline styles: {e}\n{format_exc()}")
            return {}

    def get_scripts(self) -> ScriptData:
        """Extracts inline JavaScript, external scripts, inline event handlers, and inline styles from HTML content."""
        with ThreadPoolExecutor() as executor:
            # Submit each task for concurrent execution
            futures = {
                executor.submit(self.extract_inline_scripts): "inline_scripts",
                executor.submit(self.extract_external_scripts): "external_scripts",
                executor.submit(self.extract_event_handlers): "event_handlers",
                executor.submit(self.extract_inline_styles): "inline_styles"
            }

            result = {}
            # Collect results as each task completes
            for future in as_completed(futures):
                key = futures[future]
                try:
                    result[key] = future.result()
                except Exception as e:
                    logger.error(f"Error extracting {key}: {e}\n{format_exc()}")
                    result[key] = [] if key != "event_handlers" else {}

            return ScriptData(
                inline_scripts=result.get("inline_scripts", []),
                external_scripts=result.get("external_scripts", []),
                event_handlers=result.get("event_handlers", {}),
                inline_styles=result.get("inline_styles", {})
            )
