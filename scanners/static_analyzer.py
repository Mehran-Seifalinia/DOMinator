"""
Static Analyzer Module
Performs static analysis of HTML content to detect potential DOM XSS vulnerabilities.
"""
from re import compile
from typing import List
from scanners.priority_manager import PriorityManager, RiskLevel, ExploitComplexity
from extractors.html_parser import ScriptExtractor
from utils.logger import get_logger
from utils.patterns import DANGEROUS_JS_PATTERNS, DANGEROUS_HTML_PATTERNS, get_risk_level, DOM_SOURCES_PATTERNS
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

    _RISK_TO_ENUM = {
    'critical': RiskLevel.EVAL,
    'high': RiskLevel.DOCUMENT_WRITE,
    'medium': RiskLevel.INNER_HTML,
    'low': RiskLevel.LOCATION,
    'unknown': RiskLevel.INNER_HTML,
    }

    _CLEAN_SOURCE_REGEX = compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)+)')
    
    def __init__(self, html: str, level: int = 2) -> None:
        """
        Initialize the StaticAnalyzer with HTML content.
        
        Args:
            html (str): The HTML content to analyze
            level (int): Analysis level (1-4, currently unused, reserved for future)
            
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
        risk_to_enum = self._RISK_TO_ENUM
        seen_occurrences = set()

        # Analyze inline scripts
        inline_scripts = self.extractor.extract_inline_scripts()  # returns List[Tuple[int, str]]
        for line_num, script in inline_scripts:
            for pattern in DANGEROUS_JS_PATTERNS:
                for match in pattern.finditer(script):
                    unique_key = (line_num, match.start(), match.group())
                    if unique_key in seen_occurrences:
                        continue
                    seen_occurrences.add(unique_key)

                    if pattern.pattern == r"(?i)\.innerHTML\ s*=":
                        if 'replace' in script and ('[&<>]' in script or '&lt;' in script):
                            continue
                        line_start = script.rfind('\n', 0, match.start()) + 1
                        line_end = script.find('\n', match.start())
                        if line_end == -1:
                            line_end = len(script)
                        current_line = script[line_start:line_end]
                        if 'replace' in current_line and ('[&<>]' in current_line or '&lt;' in current_line):
                            continue

                    risk_level_str = get_risk_level(match.group())
                    risk_level = risk_to_enum.get(risk_level_str, RiskLevel.INNER_HTML)
                    priority, _ = self.priority_manager.calculate_optimized_priority(
                        methods=[risk_level],
                        complexity=ExploitComplexity.MEDIUM
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
                match_attr = pattern.search(attr)
                match_value = pattern.search(value)
                if match_attr or match_value:
                    matched_pattern = (match_attr.group() if match_attr else match_value.group())
                    risk_level_str = get_risk_level(matched_pattern)
                    risk_level = risk_to_enum.get(risk_level_str, RiskLevel.INNER_HTML)
                    priority, _ = self.priority_manager.calculate_optimized_priority(
                        methods=[risk_level],
                        complexity=ExploitComplexity.MEDIUM
                    )
                    occurrence: Occurrence = {
                        "line": line,
                        "column": 0,
                        "pattern": matched_pattern,
                        "context": f"{tag} {attr}={value[:50]}..." if len(value) > 50 else f"{tag} {attr}={value}",
                        "risk_level": risk_level_str,
                        "priority": priority,
                        "source": "static"
                    }
                    unique_key = (line, tag, attr, matched_pattern)
                    if unique_key in seen_occurrences:
                        continue
                    seen_occurrences.add(unique_key)
                    self.result.add_static_occurrence(occurrence)
                    break

    def extract_dom_sources(self) -> List[str]:
        """
        Extract DOM sources (e.g., location.hash, location.search) from inline scripts.
        Returns clean source names without method calls or extra characters.
        """

        sources = set()
        inline_scripts = self.extractor.extract_inline_scripts()
        
        for item in inline_scripts:
            if isinstance(item, tuple):
                script = item[1]
            else:
                script = item
            
            for pattern in DOM_SOURCES_PATTERNS:
                for match in pattern.finditer(script):
                    full_match = match.group()
                    clean = self._CLEAN_SOURCE_REGEX.search(full_match)
                    if clean:
                        sources.add(clean.group(1))
                    else:
                        sources.add(full_match)
        return list(sources)

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
            self.result.dom_sources = self.extract_dom_sources()
            self.result.set_completed()
            logger.debug("Static analysis completed successfully.")
            return self.result
        except Exception as e:
            logger.error(f"Error during static analysis: {str(e)}")
            self.result.set_error(str(e))
            return self.result

    @staticmethod
    def static_analyze(html_content: str, _level: int) -> AnalysisResult:
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
