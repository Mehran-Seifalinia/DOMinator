from os import getenv
from typing import Dict, List
from collections import defaultdict
from dataclasses import dataclass
from bs4 import BeautifulSoup
from logging import getLogger, basicConfig, INFO, getLevelName
from functools import lru_cache

# Setup logger with dynamic log level
log_level = getenv("LOG_LEVEL", "INFO").upper()
log_level = getattr(INFO, log_level, INFO) if isinstance(getLevelName(log_level), int) else INFO
basicConfig(level=log_level, format="%(levelname)s: %(message)s")
logger = getLogger(__name__)

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
        self.soup = BeautifulSoup(html, "html.parser")

    @lru_cache(maxsize=128)
    def extract_inline_scripts(self) -> List[str]:
        """Extracts inline JavaScript from <script> tags."""
        try:
            return [script.text.strip() for script in self.soup.find_all("script") if script.text.strip()]
        except AttributeError as e:
            logger.error(f"Error extracting inline scripts due to attribute issue: {e}")
            return []
        except Exception as e:
            logger.error(f"Error extracting inline scripts: {e}")
            return []

    @lru_cache(maxsize=128)
    def extract_external_scripts(self) -> List[str]:
        """Extracts external <script> sources (src attributes)."""
        try:
            return [src.strip() for script in self.soup.find_all("script", src=True) if (src := script.get("src"))]
        except AttributeError as e:
            logger.error(f"Error extracting external scripts due to attribute issue: {e}")
            return []
        except Exception as e:
            logger.error(f"Error extracting external scripts: {e}")
            return []

    @lru_cache(maxsize=128)
    def extract_event_handlers(self) -> Dict[str, List[Dict[str, str]]]:
        """Extracts inline event handlers (e.g., onclick, onmouseover) from HTML elements."""
        try:
            event_handlers = defaultdict(list)
            for tag in self.soup.find_all(True):
                handlers = {attr: value.strip() for attr, value in tag.attrs.items() if attr.lower().startswith("on") and value.strip()}
                if handlers:
                    event_handlers[tag.name].append(handlers)
            return dict(event_handlers)
        except Exception as e:
            logger.error(f"Error extracting event handlers: {e}")
            return {}

    @lru_cache(maxsize=128)
    def extract_inline_styles(self) -> Dict[str, List[str]]:
        """Extracts inline styles from HTML elements."""
        try:
            styles = defaultdict(list)
            for tag in self.soup.find_all(style=True):
                styles[tag.name].append(tag["style"].strip())
            return dict(styles)
        except Exception as e:
            logger.error(f"Error extracting inline styles: {e}")
            return {}

    def get_scripts(self) -> ScriptData:
        """Extracts inline JavaScript, external scripts, inline event handlers, and inline styles from HTML content."""
        try:
            inline_scripts = self.extract_inline_scripts()
            external_scripts = self.extract_external_scripts()
            event_handlers = self.extract_event_handlers()
            inline_styles = self.extract_inline_styles()
            return ScriptData(
                inline_scripts=inline_scripts,
                external_scripts=external_scripts,
                event_handlers=event_handlers,
                inline_styles=inline_styles,
            )
        except Exception as e:
            logger.error(f"Error extracting scripts: {e}")
            return ScriptData(inline_scripts=[], external_scripts=[], event_handlers={}, inline_styles={})

# Example usage:
# extractor = ScriptExtractor(html_content)
# scripts_data = extractor.get_scripts()
# print(scripts_data)
