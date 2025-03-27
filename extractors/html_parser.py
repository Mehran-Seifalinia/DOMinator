from os import getenv
from typing import Dict, List
from collections import defaultdict
from dataclasses import dataclass
from bs4 import BeautifulSoup
from logging import getLogger, basicConfig, INFO, DEBUG, WARNING, ERROR, CRITICAL
from traceback import format_exc
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
from html5lib import parse

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
    except Exception as e:
        logger.error(f"Invalid HTML content: {e}")
        return False

@dataclass
class ScriptData:
    inline_scripts: List[str]
    external_scripts: List[str]
    event_handlers: Dict[str, List[Dict[str, str]]]
    inline_styles: Dict[str, List[str]]

    def __str__(self) -> str:
        """Return a formatted string representation of extracted data."""
        return (
            f"Inline Scripts: {len(self.inline_scripts)}\n"
            f"External Scripts: {len(self.external_scripts)}\n"
            f"Event Handlers: {len(self.event_handlers)} types\n"
            f"Inline Styles: {len(self.inline_styles)} elements"
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

    @lru_cache
    def extract_inline_scripts(self) -> List[str]:
        """Extracts inline JavaScript from <script> tags."""
        try:
            scripts = [script.text.strip() for script in self.soup.find_all("script") if script.text.strip()]
            if not scripts:
                logger.warning("No inline scripts found.")
            return scripts
        except AttributeError as e:
            logger.error(f"Error extracting inline scripts due to attribute issue: {e}\n{format_exc()}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error extracting inline scripts: {e}\n{format_exc()}")
            return []

    @lru_cache
    def extract_external_scripts(self) -> List[str]:
        """Extracts external <script> sources (src attributes)."""
        try:
            scripts = []
            for script in self.soup.find_all("script", src=True):
                src = script.get("src")
                if src and src.strip():  # Ensure src is not empty or invalid
                    scripts.append(src.strip())
            if not scripts:
                logger.warning("No external scripts found.")
            return scripts
        except Exception as e:
            logger.error(f"Unexpected error extracting external scripts: {e}\n{format_exc()}")
            return []

    @lru_cache
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

    @lru_cache
    def extract_inline_styles(self) -> Dict[str, List[str]]:
        """Extracts inline styles from HTML elements."""
        try:
            styles = defaultdict(list)
            for tag in self.soup.find_all(style=True):
                styles[tag.name].append(tag["style"].strip())
            if not styles:
                logger.warning("No inline styles found.")
            return dict(styles)
        except Exception as e:
            logger.error(f"Unexpected error extracting inline styles: {e}\n{format_exc()}")
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

# Example usage:
# extractor = ScriptExtractor(html_content)
# scripts_data = extractor.get_scripts()
# print(scripts_data)
