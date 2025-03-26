from re import compile
from logging import getLogger, basicConfig, INFO
from requests import get, Response
from os import getenv
from typing import Dict, List, Tuple, Optional, TypedDict
from dataclasses import dataclass
from bs4 import BeautifulSoup

# Setup logger with dynamic log level
log_level = getenv("LOG_LEVEL", "INFO").upper()
if log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
    log_level = "INFO"
    getLogger().warning(f"Invalid log level: {log_level}, falling back to INFO")
basicConfig(level=getattr(INFO, log_level), format="%(levelname)s: %(message)s")
logger = getLogger(__name__)

# Precompiled regex patterns for better performance
dangerous_patterns = [
    compile(r"(?i)\beval\s*\("),  # \b ensures that we match only the word "eval"
    compile(r"(?i)\bFunction\s*\("),
    compile(r"(?i)window\s*\[\s*['\"]eval['\"]\s*\]"),
    compile(r"(?i)\(\s*\d+\s*,\s*eval\s*\)"),
    compile(r"(?i)\.eval\s*\("),
    compile(r"(?i)\.(innerHTML|outerHTML|innerText|outerText)\s*="),
    compile(r"(?i)document\.(write|writeln|open)\s*\("),  # Added open() as it's dangerous
    compile(r"(?i)(setTimeout|setInterval)\s*\("),
    compile(r"(?i)new\s+(ActiveXObject|XMLHttpRequest)\s*\("),
    compile(r"(?i)document\.cookie\s*="),  # Detect potential XSS or CSRF issues
    compile(r"(?i)localStorage\s*=",),
    compile(r"(?i)sessionStorage\s*=",),
    compile(r"(?i)window\.location\s*="),  # Sensitive location access
    compile(r"(?i)fetch\s*\("),  # Detect potential AJAX requests
]

dangerous_html_patterns = [
    compile(r"(?i)on\w+\s*="),
    compile(r"(?i)javascript\s*:"),  # Avoid javascript: in href or src
    compile(r"(?i)data\s*:\s*text\s*/\s*html"),  # Avoid data:text/html
    compile(r"(?i)<\s*script[^>]*>.*<\s*/\s*script\s*>"),
    compile(r"(?i)<\s*iframe[^>]*>.*<\s*/\s*iframe\s*>"),  # Iframe injection
    compile(r"(?i)<\s*object\s*data\s*=\s*['\"].*['\"]\s*>"),  # Object tag with external resources
]



# Define risk levels for different patterns
RISK_LEVELS = {
    'eval': 'high',
    'Function': 'high',
    'innerHTML': 'medium',
    'onclick': 'medium',
}

def assess_risk(pattern: str) -> str:
    """Assesses the risk level based on the matched pattern."""
    return RISK_LEVELS.get(pattern.lower(), 'unknown')

@dataclass
class ScriptData:
    inline_scripts: List[Tuple[int, str]]
    external_scripts: List[str]
    event_handlers: Dict[str, List[Tuple[int, str]]]
    inline_styles: Dict[str, List[str]]
    dangerous_occurrences: List[Occurrence]

class Occurrence(TypedDict):
    line: int
    column: int
    pattern: str
    context: str
    risk_level: str

class StaticAnalyzer:
    """Extracts scripts, event handlers, inline styles, and dangerous patterns from HTML content."""

    def __init__(self, html: str):
        """Initializes the analyzer with the provided HTML content."""
        if not html or not isinstance(html, str) or not html.strip():
            raise ValueError("Invalid input: HTML content must be a non-empty string.")
        try:
            self.soup = BeautifulSoup(html, "html.parser")
        except Exception as e:
            logger.error(f"Error parsing HTML: {e}")
            self.soup = None

    def fetch_external_script(self, url: str) -> Optional[str]:
        """Fetches external JavaScript content while using a cache to avoid duplicate requests."""
        if not hasattr(self, "_script_cache"):
            self._script_cache = {}
        
        if url in self._script_cache:
            return self._script_cache[url]
        
        try:
            response: Response = get(url, timeout=5)
            response.raise_for_status()
            if "text/javascript" not in response.headers.get("Content-Type", ""):
                logger.warning(f"URL {url} did not return JavaScript content.")
                return None
            self._script_cache[url] = response.text
            return response.text
        except Exception as e:
            logger.warning(f"Failed to fetch external script {url}: {e}")
            return None

    def detect_dangerous_patterns(self) -> List[Occurrence]:
        """Detects dangerous JavaScript functions and HTML attributes with positions."""
        occurrences = []

        # Check inline scripts for dangerous patterns
        for script in self.soup.find_all("script"):
            if script.text.strip():
                for pattern in dangerous_patterns:
                    for match in pattern.finditer(script.text):
                        occurrences.append({
                            "line": script.sourceline,
                            "column": match.start(),
                            "pattern": match.group(),
                            "context": script.text[max(0, match.start()-20):match.end()+20],
                            "risk_level": assess_risk(match.group())
                        })

        # Check HTML attributes for dangerous patterns
        for tag in self.soup.find_all(True):
            for attr, value in tag.attrs.items():
                # Avoid triggering on non-executable attributes or harmless cases
                if 'href' in attr or 'src' in attr:
                    if 'javascript:' in str(value).lower() or 'data:text/html' in str(value).lower():
                        continue  # Skip javascript and data URIs
                for pattern in dangerous_html_patterns:
                    if pattern.search(attr) or pattern.search(str(value)):
                        occurrences.append({
                            "line": tag.sourceline,
                            "column": 0,
                            "pattern": attr,
                            "context": f"{tag.name} {attr}={value[:50]}...",
                            "risk_level": assess_risk(attr)
                        })

        # Reduce false positives by combining matching patterns
        refined_occurrences = []
        seen_patterns = set()
        for occurrence in occurrences:
            if occurrence["pattern"] not in seen_patterns:
                refined_occurrences.append(occurrence)
                seen_patterns.add(occurrence["pattern"])

        return refined_occurrences

    def analyze(self) -> ScriptData:
        """Extracts all relevant script-related data from HTML content."""
        try:
            return ScriptData(
                inline_scripts=self.extract_inline_scripts(),
                external_scripts=self.extract_external_scripts(),
                event_handlers=self.extract_event_handlers(),
                inline_styles=self.extract_inline_styles(),
                dangerous_occurrences=self.detect_dangerous_patterns(),
            )
        except Exception as e:
            logger.error(f"Error analyzing scripts: {e}")
            return ScriptData(inline_scripts=[], external_scripts=[], event_handlers={}, inline_styles={}, dangerous_occurrences=[])

    def extract_inline_scripts(self) -> List[Tuple[int, str]]:
        """Extracts inline scripts from the HTML."""
        inline_scripts = []
        for script in self.soup.find_all("script"):
            if script.text.strip():
                inline_scripts.append((script.sourceline, script.text))
        return inline_scripts

    def extract_external_scripts(self) -> List[str]:
        """Extracts external script URLs from the HTML."""
        external_scripts = []
        for script in self.soup.find_all("script", src=True):
            external_scripts.append(script["src"])
        return external_scripts

    def extract_event_handlers(self) -> Dict[str, List[Tuple[int, str]]]:
        """Extracts inline event handlers like onClick, onError, etc."""
        event_handlers = {}
        for tag in self.soup.find_all(True):  # All tags
            for attr, value in tag.attrs.items():
                if attr.startswith("on"):
                    event_handlers.setdefault(attr, []).append((tag.sourceline, value))
        return event_handlers

    def extract_inline_styles(self) -> Dict[str, List[str]]:
        """Extracts inline styles from the HTML."""
        inline_styles = {}
        for tag in self.soup.find_all(style=True):
            inline_styles.setdefault(tag.name, []).append(tag["style"])
        return inline_styles
