from re import compile
from logging import getLogger, basicConfig, INFO
from requests import get
from os import getenv
from typing import Dict, List, Tuple, Optional, TypedDict
from dataclasses import dataclass
from bs4 import BeautifulSoup

# Setup logger with dynamic log level
log_level = getenv("LOG_LEVEL", "INFO").upper()
basicConfig(level=getattr(INFO, log_level, INFO), format="%(levelname)s: %(message)s")
logger = getLogger(__name__)

# Precompiled regex patterns for better performance
dangerous_patterns = [
    compile(r"(?i)(?<!\w)(eval|Function)\s*\("),
    compile(r"(?i)window\s*\[\s*['\"]eval['\"]\s*\]"),
    compile(r"(?i)\(\s*\d+\s*,\s*eval\s*\)"),
    compile(r"(?i)\.eval\s*\("),
    compile(r"(?i)\.(innerHTML|outerHTML)\s*="),
    compile(r"(?i)document\.(write|writeln)\s*\("),
    compile(r"(?i)(setTimeout|setInterval)\s*\("),
    compile(r"(?i)new\s+(ActiveXObject|XMLHttpRequest)\s*\("),
]

dangerous_html_patterns = [
    compile(r"(?i)on\w+\s*="),
    compile(r"(?i)javascript\s*:"),
    compile(r"(?i)data\s*:\s*text\s*/\s*html"),
    compile(r"(?i)<\s*script[^>]*>.*<\s*/\s*script\s*>"),
]

class Occurrence(TypedDict):
    line: int
    column: int
    pattern: str
    context: str
    risk_level: str

RISK_LEVELS = {
    'eval': 'high',
    'Function': 'high',
    'innerHTML': 'medium',
    'onclick': 'medium',
}

def assess_risk(pattern: str) -> str:
    return RISK_LEVELS.get(pattern.lower(), 'unknown')

@dataclass
class ScriptData:
    inline_scripts: List[Tuple[int, str]]
    external_scripts: List[str]
    event_handlers: Dict[str, List[Tuple[int, str]]]
    inline_styles: Dict[str, List[str]]
    dangerous_occurrences: List[Occurrence]

class StaticAnalyzer:
    """Extracts scripts, event handlers, inline styles, and dangerous patterns from HTML content."""

    def __init__(self, html: str):
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
            response = get(url, timeout=5)
            response.raise_for_status()
            self._script_cache[url] = response.text
            return response.text
        except Exception as e:
            logger.warning(f"Failed to fetch external script {url}: {e}")
            return None

    def detect_dangerous_patterns(self) -> List[Occurrence]:
        """Detects dangerous JavaScript functions and HTML attributes with positions."""
        occurrences = []
        
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
        
        for tag in self.soup.find_all(True):
            for attr, value in tag.attrs.items():
                for pattern in dangerous_html_patterns:
                    if pattern.search(attr) or pattern.search(str(value)):
                        occurrences.append({
                            "line": tag.sourceline,
                            "column": 0,
                            "pattern": attr,
                            "context": f"{tag.name} {attr}={value[:50]}...",
                            "risk_level": assess_risk(attr)
                        })
        
        return occurrences

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
