from re import compile
from utils.logger import get_logger
from requests import get, Response
from os import getenv
from typing import Dict, List, Tuple, Optional, TypedDict
from dataclasses import dataclass
from bs4 import BeautifulSoup
from priority_manager import calculate_priority

logger = get_logger()

dangerous_patterns = [
    compile(r"(?i)\beval\s*\("),
    compile(r"(?i)\bFunction\s*\("),
    compile(r"(?i)window\s*\[\s*['\"]eval['\"]\s*\]"),
    compile(r"(?i)\(\s*\d+\s*,\s*eval\s*\)"),
    compile(r"(?i)\.eval\s*\("),
    compile(r"(?i)\.(innerHTML|outerHTML|innerText|outerText)\s*="),
    compile(r"(?i)document\.(write|writeln|open)\s*\("),
    compile(r"(?i)(setTimeout|setInterval)\s*\("),
    compile(r"(?i)new\s+(ActiveXObject|XMLHttpRequest)\s*\("),
    compile(r"(?i)document\.cookie\s*="),
    compile(r"(?i)localStorage\s*=",),
    compile(r"(?i)sessionStorage\s*=",),
    compile(r"(?i)window\.location\s*="), 
    compile(r"(?i)fetch\s*\("),
]

dangerous_html_patterns = [
    compile(r"(?i)on\w+\s*="),
    compile(r"(?i)javascript\s*:"), 
    compile(r"(?i)data\s*:\s*text\s*/\s*html"),
    compile(r"(?i)<\s*script[^>]*>.*<\s*/\s*script\s*>"),
    compile(r"(?i)<\s*iframe[^>]*>.*<\s*/\s*iframe\s*>"),
    compile(r"(?i)<\s*object\s*data\s*=\s*['\"].*['\"]\s*>"),
]

RISK_LEVELS = {
    'eval': 'high',
    'Function': 'high',
    'innerHTML': 'medium',
    'onclick': 'medium',
}

def assess_risk(pattern: str) -> str:
    return RISK_LEVELS.get(pattern.lower(), 'unknown')

class Occurrence(TypedDict):
    line: int
    column: int
    pattern: str
    context: str
    risk_level: str
    priority: str

@dataclass
class ScriptData:
    inline_scripts: List[Tuple[int, str]]
    external_scripts: List[str]
    event_handlers: Dict[str, List[Tuple[int, str]]]
    inline_styles: Dict[str, List[str]]
    dangerous_occurrences: List[Occurrence]

class StaticAnalyzer:
    def __init__(self, html: str):
        if not html or not isinstance(html, str) or not html.strip():
            raise ValueError("Invalid input: HTML content must be a non-empty string.")
        try:
            self.soup = BeautifulSoup(html, "html.parser")
        except Exception as e:
            logger.error(f"Error parsing HTML: {e}")
            self.soup = None

    def fetch_external_script(self, url: str) -> Optional[str]:
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
        occurrences = []

        for script in self.soup.find_all("script"):
            if script.text.strip():
                for pattern in dangerous_patterns:
                    for match in pattern.finditer(script.text):
                        risk_level = assess_risk(match.group())
                        priority = calculate_priority(risk_level)
                        occurrences.append({
                            "line": script.sourceline,
                            "column": match.start(),
                            "pattern": match.group(),
                            "context": script.text[max(0, match.start()-20):match.end()+20],
                            "risk_level": risk_level,
                            "priority": priority
                        })

        for tag in self.soup.find_all(True):
            for attr, value in tag.attrs.items():
                if 'href' in attr or 'src' in attr:
                    if 'javascript:' in str(value).lower() or 'data:text/html' in str(value).lower():
                        continue
                for pattern in dangerous_html_patterns:
                    if pattern.search(attr) or pattern.search(str(value)):
                        risk_level = assess_risk(attr)
                        priority = calculate_priority(risk_level)
                        occurrences.append({
                            "line": tag.sourceline,
                            "column": 0,
                            "pattern": attr,
                            "context": f"{tag.name} {attr}={value[:50]}...",
                            "risk_level": risk_level,
                            "priority": priority
                        })

        refined_occurrences = []
        seen_patterns = set()
        for occurrence in occurrences:
            if occurrence["pattern"] not in seen_patterns:
                refined_occurrences.append(occurrence)
                seen_patterns.add(occurrence["pattern"])

        return refined_occurrences

    def analyze(self) -> ScriptData:
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
        inline_scripts = []
        for script in self.soup.find_all("script"):
            if script.text.strip():
                inline_scripts.append((script.sourceline, script.text))
        return inline_scripts

    def extract_external_scripts(self) -> List[str]:
        external_scripts = []
        for script in self.soup.find_all("script", src=True):
            external_scripts.append(script["src"])
        return external_scripts

    def extract_event_handlers(self) -> Dict[str, List[Tuple[int, str]]]:
        event_handlers = {}
        for tag in self.soup.find_all(True):
            for attr, value in tag.attrs.items():
                if attr.startswith("on"):
                    event_handlers.setdefault(attr, []).append((tag.sourceline, value))
        return event_handlers
    
    def extract_inline_styles(self) -> Dict[str, List[str]]:
        inline_styles = {}
        for tag in self.soup.find_all(style=True):
            inline_styles.setdefault(tag.name, []).append(tag["style"])
        return inline_styles
