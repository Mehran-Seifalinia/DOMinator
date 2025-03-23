import logging
import re
from html_Parser import ScriptExtractor
from typing import List, Dict, Any, Union

# Setup logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(levelname)s: %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

class StaticAnalyzer:
    """Performs static analysis on the HTML and JavaScript content for potential XSS vulnerabilities."""
    
    def __init__(self, html: str):
        """Initializes the analyzer with the given HTML content."""
        try:
            self.extractor = ScriptExtractor(html)
            self.scripts_data = self.extractor.get_scripts()
            
            if not self.scripts_data:
                raise ValueError("ScriptExtractor returned None or invalid data.")
                
            logger.info("Static analyzer initialized.")
        except ValueError as e:
            logger.error(f"Error initializing StaticAnalyzer: {e}")
            self.scripts_data = None
            raise

    def analyze_inline_scripts(self) -> List[Dict[str, Union[str, List[str]]]]:
        """Analyzes inline JavaScript for risky patterns like eval(), document.write(), etc."""
        if not self.scripts_data:
            logger.warning("No scripts data available.")
            return []

        risky_patterns = [r'\beval\(', r'\bdocument\.write\(', r'\bsetTimeout\(', r'\bsetInterval\(']
        risky_scripts = []

        for script in self.scripts_data.inline_scripts:
            risky_functions = [pattern for pattern in risky_patterns if re.search(pattern, script)]
            if risky_functions:
                risky_scripts.append({"script": script, "risky_functions": risky_functions})

        logger.info(f"Found {len(risky_scripts)} risky inline scripts.")
        return risky_scripts

    def analyze_external_scripts(self) -> List[str]:
        """Checks external scripts for potential risks (basic URL filtering)."""
        if not self.scripts_data:
            logger.warning("No scripts data available.")
            return []

        known_malicious_sources = ["malicious.com", "untrusted-source.net", "suspicious-domain.org"]
        risky_urls = [url for url in self.scripts_data.external_scripts if any(domain in url for domain in known_malicious_sources)]

        logger.info(f"Found {len(risky_urls)} risky external scripts.")
        return risky_urls

    def analyze_event_handlers(self) -> Dict[str, List[Dict[str, str]]]:
        """Analyzes event handlers in the HTML content to check for XSS risks."""
        if not self.scripts_data:
            logger.warning("No scripts data available.")
            return {}

        risky_event_handlers = {
            tag: handlers for tag, handlers in self.scripts_data.event_handlers.items()
            if any(any(re.search(r'\beval\(|\bdocument\.write\(', handler[attr]) for attr in handler) for handler in handlers)
        }

        logger.info(f"Found {len(risky_event_handlers)} risky event handlers.")
        return risky_event_handlers

    def run_analysis(self) -> Dict[str, Any]:
        """Runs the full static analysis and returns the results."""
        return {
            "risky_inline_scripts": self.analyze_inline_scripts(),
            "risky_external_scripts": self.analyze_external_scripts(),
            "risky_event_handlers": self.analyze_event_handlers()
        }

# Example usage:
if __name__ == "__main__":
    html_content = "<html><body><script>eval('alert(1)');</script></body></html>"
    
    try:
        analyzer = StaticAnalyzer(html_content)
        analysis_result = analyzer.run_analysis()
        print(analysis_result)
    except ValueError as e:
        logger.error("Failed to initialize StaticAnalyzer.")
