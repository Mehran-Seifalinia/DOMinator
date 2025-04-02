from re import compile
from utils.logger import get_logger
from requests import get, Response
from typing import List, Dict, Optional, TypedDict
from dataclasses import dataclass
from priority_manager import calculate_priority
from html_parser import ScriptExtractor

logger = get_logger()

dangerous_patterns = [
    compile(r"(?i)\beval\s*\("),
    compile(r"(?i)\bFunction\s*\("),
    compile(r"(?i)window\s*\[\s*['\"]eval['\"]\s*\]"),
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
    line: Optional[int]
    column: int
    pattern: str
    context: str
    risk_level: str
    priority: str

@dataclass
class ScriptAnalysis:
    dangerous_occurrences: List[Occurrence]

class StaticAnalyzer:
    def __init__(self, html: str):
        if not html or not isinstance(html, str) or not html.strip():
            raise ValueError("Invalid input: HTML content must be a non-empty string.")
        
        self.extractor = ScriptExtractor(html)
        self.html = html

    def detect_dangerous_patterns(self) -> List[Occurrence]:
        occurrences = []
        

        for line, script in self.extractor.inline_scripts:
            for pattern in dangerous_patterns:
                for match in pattern.finditer(script):
                    risk_level = assess_risk(match.group())
                    priority = calculate_priority(risk_level)
                    occurrences.append({
                        "line": line,
                        "column": match.start(),
                        "pattern": match.group(),
                        "context": script[max(0, match.start()-20):match.end()+20],
                        "risk_level": risk_level,
                        "priority": priority
                    })

        for tag, attr, value, line in self.extractor.dangerous_html_elements:
            for pattern in dangerous_html_patterns:
                if pattern.search(attr) or pattern.search(value):
                    risk_level = assess_risk(attr)
                    priority = calculate_priority(risk_level)
                    occurrences.append({
                        "line": line,
                        "column": 0,
                        "pattern": attr,
                        "context": f"{tag} {attr}={value[:50]}...",
                        "risk_level": risk_level,
                        "priority": priority
                    })

        return occurrences

    def analyze(self) -> ScriptAnalysis:
        try:
            return ScriptAnalysis(dangerous_occurrences=self.detect_dangerous_patterns())
        except Exception as e:
            logger.error(f"Error analyzing scripts: {e}")
            return ScriptAnalysis(dangerous_occurrences=[])
