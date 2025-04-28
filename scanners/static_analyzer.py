from typing import List, Dict, Optional
from scanners.priority_manager import PriorityManager
from extractors.html_parser import ScriptExtractor
from utils.logger import get_logger
from utils.patterns import DANGEROUS_JS_PATTERNS, DANGEROUS_HTML_PATTERNS, get_risk_level
from utils.analysis_result import AnalysisResult, Occurrence

logger = get_logger()

class StaticAnalyzer:
    def __init__(self, html: str):
        if not html or not isinstance(html, str) or not html.strip():
            raise ValueError("Invalid input: HTML content must be a non-empty string.")
        
        self.extractor = ScriptExtractor(html)
        self.html = html
        self.result = AnalysisResult()

    def detect_dangerous_patterns(self) -> None:
        # Analyze inline scripts
        for line_num, script in enumerate(self.extractor.inline_scripts, start=1):
            for pattern in DANGEROUS_JS_PATTERNS:
                for match in pattern.finditer(script):
                    risk_level = get_risk_level(match.group())
                    priority = PriorityManager.calculate_optimized_priority(risk_level)
                    occurrence: Occurrence = {
                        "line": line_num,
                        "column": match.start(),
                        "pattern": match.group(),
                        "context": script[max(0, match.start()-20):match.end()+20],
                        "risk_level": risk_level,
                        "priority": priority,
                        "source": "static"
                    }
                    self.result.add_static_occurrence(occurrence)
    
        # Analyze HTML elements
        for tag, attr, value, line in self.extractor.dangerous_html_elements:
            for pattern in DANGEROUS_HTML_PATTERNS:
                if pattern.search(attr) or pattern.search(value):
                    risk_level = get_risk_level(attr)
                    priority = PriorityManager.calculate_optimized_priority(risk_level)
                    occurrence: Occurrence = {
                        "line": line,
                        "column": 0,
                        "pattern": attr,
                        "context": f"{tag} {attr}={value[:50]}...",
                        "risk_level": risk_level,
                        "priority": priority,
                        "source": "static"
                    }
                    self.result.add_static_occurrence(occurrence)

    def analyze(self) -> AnalysisResult:
        try:
            self.detect_dangerous_patterns()
            self.result.set_completed()
            return self.result
        except Exception as e:
            logger.error(f"Error analyzing scripts: {e}")
            self.result.set_error(str(e))
            return self.result
