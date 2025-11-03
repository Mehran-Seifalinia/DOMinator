"""
Static Analyzer Module
Performs static analysis of HTML content to detect potential DOM XSS vulnerabilities.
"""

from typing import List
from scanners.priority_manager import PriorityManager, RiskLevel, ExploitComplexity
from extractors.html_parser import ScriptExtractor
from utils.logger import get_logger
from utils.patterns import DANGEROUS_JS_PATTERNS, DANGEROUS_HTML_PATTERNS, get_risk_level
from utils.analysis_result import AnalysisResult, Occurrence

logger = get_logger(__name__)

# Maximum allowed HTML size in bytes to prevent memory issues
MAX_HTML_SIZE = 10 * 1024 * 1024  # 10 MB

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
            ValueError: If HTML content is invalid or too large
        """
        if not isinstance(html, str) or not html.strip():
            raise ValueError("Invalid input: HTML content must be a non-empty string.")
        
        if len(html) > MAX_HTML_SIZE:
            logger.error(f"HTML content exceeds maximum size ({MAX_HTML_SIZE} bytes).")
            raise ValueError("HTML content is too large.")
        
        self.extractor = ScriptExtractor(html)
        self.html = html
        self.result = AnalysisResult()
        self.priority_manager = PriorityManager()

    def detect_dangerous_patterns(self) -> None:
        """
        Detect dangerous patterns in both inline scripts and HTML elements.
        
        This method analyzes the HTML content for patterns that could indicate
        potential DOM XSS vulnerabilities. It checks both inline JavaScript code
        and HTML element attributes.
        """
        # Analyze inline scripts
        inline_scripts = self.extractor.extract_inline_scripts()
        for line_num, script in enumerate(inline_scripts, start=1):
            for pattern in DANGEROUS_JS_PATTERNS:
                for match in pattern.finditer(script):
                    risk_level_str = get_risk_level(match.group())
                    try:
                        risk_level = RiskLevel(risk_level_str.upper())  # Convert to Enum if possible
                    except ValueError:
                        risk_level = RiskLevel.INNER_HTML  # Default fallback
                    priority, _ = self.priority_manager.calculate_optimized_priority(
                        methods=[risk_level],
                        complexity=ExploitComplexity.MEDIUM  # Default complexity
                    )
                    occurrence: Occurrence = {
                        "line": line_num,
                        "column": match.start(),
                        "pattern": match.group(),
                        "context": script[max(0, match.start()-20):match.end()+20],
                        "risk_level": risk_level_str,
                        "priority": priority,
                        "source": "static"
                    }
                    self.result.add_static_occurrence(occurrence)
    
        # Analyze HTML elements
        dangerous_elements = self.extractor.get_dangerous_html_elements()
        for tag, attr, value, line in dangerous_elements:
            for pattern in DANGEROUS_HTML_PATTERNS:
                if pattern.search(attr) or pattern.search(value):
                    risk_level_str = get_risk_level(attr)
                    try:
                        risk_level = RiskLevel(risk_level_str.upper())  # Convert to Enum if possible
                    except ValueError:
                        risk_level = RiskLevel.INNER_HTML  # Default fallback
                    priority, _ = self.priority_manager.calculate_optimized_priority(
                        methods=[risk_level],
                        complexity=ExploitComplexity.MEDIUM  # Default complexity
                    )
                    occurrence: Occurrence = {
                        "line": line,
                        "column": 0,
                        "pattern": attr,
                        "context": f"{tag} {attr}={value[:50]}..." if len(value) > 50 else f"{tag} {attr}={value}",
                        "risk_level": risk_level_str,
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
            logger.info("Static analysis completed successfully.")
            return self.result
        except Exception as e:
            logger.error(f"Error during static analysis: {str(e)}")
            self.result.set_error(str(e))
            return self.result

    @staticmethod
    def static_analyze(html_content: str, level: int) -> AnalysisResult:
        """
        Perform static analysis on given HTML content.
        
        Args:
            html_content (str): The HTML content to analyze
            level (int): The analysis level (1-4) - currently unused, reserved for future depth control
            
        Returns:
            AnalysisResult: The result of the static analysis
            
        Note: This static method assumes html_content is pre-fetched; no network requests are made.
        """
        try:
            analyzer = StaticAnalyzer(html_content)
            return analyzer.analyze()
        except Exception as e:
            logger.error(f"Error in static analysis: {str(e)}")
            result = AnalysisResult()
            result.set_error(str(e))
            return result
