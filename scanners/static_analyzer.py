"""
Static Analyzer Module
Performs static analysis of HTML content to detect potential DOM XSS vulnerabilities.
"""

from typing import List, Dict, Optional, Any
from scanners.priority_manager import PriorityManager
from extractors.html_parser import ScriptExtractor
from utils.logger import get_logger
from utils.patterns import DANGEROUS_JS_PATTERNS, DANGEROUS_HTML_PATTERNS, get_risk_level
from utils.analysis_result import AnalysisResult, Occurrence

logger = get_logger(__name__)

class StaticAnalyzer:
    """
    A class for performing static analysis of HTML content to detect potential DOM XSS vulnerabilities.
    
    This class analyzes HTML content for dangerous patterns in both inline scripts
    and HTML elements that could lead to DOM XSS attacks.
    """
    
    def __init__(self, html: str) -> None:
        """
        Initialize the StaticAnalyzer with HTML content.
        
        Args:
            html (str): The HTML content to analyze
            
        Raises:
            ValueError: If HTML content is invalid
        """
        if not html or not isinstance(html, str) or not html.strip():
            raise ValueError("Invalid input: HTML content must be a non-empty string.")
        
        self.extractor = ScriptExtractor(html)
        self.html = html
        self.result = AnalysisResult()

    def detect_dangerous_patterns(self) -> None:
        """
        Detect dangerous patterns in both inline scripts and HTML elements.
        
        This method analyzes the HTML content for patterns that could indicate
        potential DOM XSS vulnerabilities. It checks both inline JavaScript code
        and HTML element attributes.
        """
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
        """
        Perform static analysis on the HTML content.
        
        Returns:
            AnalysisResult: The result of the static analysis
            
        Note:
            This method coordinates the analysis process and handles any errors
            that occur during analysis.
        """
        try:
            self.detect_dangerous_patterns()
            self.result.set_completed()
            return self.result
        except Exception as e:
            logger.error(f"Error analyzing scripts: {e}")
            self.result.set_error(str(e))
            return self.result

    @staticmethod
    def static_analyze(url: str, level: int) -> AnalysisResult:
        """
        Perform static analysis on a given URL.
        
        Args:
            url (str): The URL to analyze
            level (int): The analysis level (1-4)
            
        Returns:
            AnalysisResult: The result of the static analysis
        """
        try:
            analyzer = StaticAnalyzer(url)
            return analyzer.analyze()
        except Exception as e:
            logger.error(f"Error in static analysis of {url}: {e}")
            result = AnalysisResult()
            result.set_error(str(e))
            return result
