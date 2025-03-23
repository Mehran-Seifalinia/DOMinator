import logging
import functools
from os import getenv
from typing import Dict, List
from collections import defaultdict
from dataclasses import dataclass
from bs4 import BeautifulSoup

# Setup logger with dynamic log level
logging.basicConfig(
    level=getattr(logging, getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)

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
        if not isinstance(html, str) or not html.strip():
            raise ValueError("Invalid input: HTML content must be a non-empty string.")
        self.soup = BeautifulSoup(html, "html.parser")

    @functools.lru_cache(maxsize=128)
    def extract_inline_scripts(self) -> List[str]:
        """Extracts inline JavaScript from <script> tags."""
        return [script.text.strip() for script in self.soup.find_all("script") if script.text.strip()]

    @functools.lru_cache(maxsize=128)
    def extract_external_scripts(self) -> List[str]:
        """Extracts external <script> sources (src attributes)."""
        return [script["src"].strip() for script in self.soup.find_all("script", src=True) if script.get("src")]

    @functools.lru_cache(maxsize=128)
    def extract_event_handlers(self) -> Dict[str, List[Dict[str, str]]]:
        """Extracts inline event handlers (e.g., onclick, onmouseover) from HTML elements."""
        event_handlers = defaultdict(list)
        for tag in self.soup.find_all(True):
            handlers = {attr: value.strip() for attr, value in tag.attrs.items() if attr.startswith("on")}
            if handlers:
                event_handlers[tag.name].append(handlers)
        return dict(event_handlers)

    @functools.lru_cache(maxsize=128)
    def extract_inline_styles(self) -> Dict[str, List[str]]:
        """Extracts inline styles from HTML elements."""
        styles = defaultdict(list)
        for tag in self.soup.find_all(style=True):
            style = tag.get("style", "").strip()
            if style:
                styles[tag.name].append(style)
        return dict(styles)

    def get_scripts(self) -> ScriptData:
        """Extracts all scripts and inline styles from HTML content."""
        return ScriptData(
            inline_scripts=self.extract_inline_scripts(),
            external_scripts=self.extract_external_scripts(),
            event_handlers=self.extract_event_handlers(),
            inline_styles=self.extract_inline_styles(),
        )

# Example usage:
# extractor = ScriptExtractor(html_content)
# scripts_data = extractor.get_scripts()
# print(scripts_data)
