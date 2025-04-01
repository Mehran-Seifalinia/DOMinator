import re
from os import getenv
from typing import Dict, List, Optional
from collections import defaultdict
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
from utils.logger import get_logger
from traceback import format_exc
from concurrent.futures import ThreadPoolExecutor, as_completed
from html5lib import parse
import json

# Logger setup
logger = get_logger()

# RegEx Patterns for DOM XSS detection (can be extended or customized)
DOM_XSS_PATTERNS = [
    r"eval\(", r"document\.write\(", r"setTimeout\(", r"setInterval\(", r"innerHTML", 
    r"document\.location", r"Function\(", r"window\.location", r"window\.eval", 
    r"document\.createElement", r"document\.createTextNode", r"String\(", 
    r"unescape\(", r"decodeURIComponent\(", r"escape\(", r"XMLHttpRequest", 
    r"location\.replace", r"localStorage", r"sessionStorage", r"window\.open",
    r"alert\(", r"console\.log\(", r"confirm\(", r"prompt\("
]

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
    inline_scripts: List[str] = field(default_factory=list)
    external_scripts: List[str] = field(default_factory=list)
    event_handlers: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    inline_styles: Dict[str, List[str]] = field(default_factory=dict)

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
            raise TypeError("HTML content must be a non-empty string.")
        
        # Validate HTML content before processing
        if not validate_html(html):
            raise ValueError("Invalid HTML: The provided HTML is not valid.")
        
        # Now we can safely parse the HTML with BeautifulSoup
        self.soup = BeautifulSoup(html, "html.parser")

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

    def extract_inline_scripts(self) -> List[str]:
        """Extract inline scripts and filter for potential DOM XSS patterns."""
        scripts = self.extract_scripts('inline')
        filtered_scripts = []
        for script in scripts:
            for pattern in DOM_XSS_PATTERNS:
                if re.search(pattern, script):
                    filtered_scripts.append(script)
                    break
        if not filtered_scripts:
            logger.warning("No potential DOM XSS inline scripts found.")
        return filtered_scripts

    def extract_external_scripts(self) -> List[str]:
        """Extract external scripts."""
        return self.extract_scripts('external')

    def extract_event_handlers(self) -> Dict[str, List[Dict[str, str]]]:
        """Extracts inline event handlers (e.g., onclick, onmouseover) from HTML elements."""
        try:
            event_handlers = defaultdict(list)
            for tag in self.soup.find_all(True):
                handlers = {attr: value.strip() for attr, value in tag.attrs.items() if attr.lower().startswith("on") and value.strip()}
                if handlers:
                    event_handlers[tag.name].append(handlers)
            # Filter event handlers related to DOM XSS using patterns
            dom_xss_event_handlers = defaultdict(list)
            for tag, handlers in event_handlers.items():
                for handler in handlers:
                    if any(re.search(pattern, handler.get('onclick', '')) for pattern in DOM_XSS_PATTERNS):
                        dom_xss_event_handlers[tag].append(handler)
            if not dom_xss_event_handlers:
                logger.warning("No event handlers found that may lead to DOM XSS.")
            return dom_xss_event_handlers
        except Exception as e:
            logger.error(f"Unexpected error extracting event handlers: {e}\n{format_exc()}")
            return {}

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
        with ThreadPoolExecutor(max_workers=4) as executor:
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
                key = list(futures.keys())[list(futures.values()).index(futures[future])]
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

    def generate_report(self, script_data: ScriptData) -> Dict[str, str]:
        """Generate a comprehensive report of findings."""
        report = {
            "inline_scripts": len(script_data.inline_scripts),
            "external_scripts": len(script_data.external_scripts),
            "event_handlers": sum(len(v) for v in script_data.event_handlers.values()),
            "inline_styles": sum(len(v) for v in script_data.inline_styles.values())
        }
        # Add more detailed information if needed
        logger.info(f"Generated report: {json.dumps(report, indent=4)}")
        return report
