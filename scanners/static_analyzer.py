from typing import List, Dict, Optional, TypedDict
from dataclasses import dataclass
from scanners.priority_manager import PriorityManager
from extractors.html_parser import ScriptExtractor
from utils.logger import get_logger
from utils.patterns import DANGEROUS_JS_PATTERNS, DANGEROUS_HTML_PATTERNS, get_risk_level

logger = get_logger()

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
        
        for line_num, script in enumerate(self.extractor.inline_scripts, start=1):
            for pattern in DANGEROUS_JS_PATTERNS:
                for match in pattern.finditer(script):
                    risk_level = get_risk_level(match.group())
                    priority = PriorityManager.calculate_optimized_priority(risk_level)
                    occurrences.append({
                        "line": line_num,
                        "column": match.start(),
                        "pattern": match.group(),
                        "context": script[max(0, match.start()-20):match.end()+20],
                        "risk_level": risk_level,
                        "priority": priority
                    })
    
        for tag, attr, value, line in self.extractor.dangerous_html_elements:
            for pattern in DANGEROUS_HTML_PATTERNS:
                if pattern.search(attr) or pattern.search(value):
                    risk_level = get_risk_level(attr)
                    priority = PriorityManager.calculate_optimized_priority(risk_level)
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
