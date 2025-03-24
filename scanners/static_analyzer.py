import logging
import re
from html_Parser import ScriptExtractor
from typing import List, Dict

# Setup logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

class StaticAnalyzer:
    """Performs static analysis on the HTML and JavaScript content for potential XSS vulnerabilities."""
    
    def __init__(self, html: str):
        """Initializes the analyzer with the given HTML content."""
        try:
            self.extractor = ScriptExtractor(html)
            self.scripts_data = self.extractor.get_scripts()  # Extract all script-related data
            logger.info("Static analyzer initialized.")
        except ValueError as e:
            logger.error(f"Error initializing StaticAnalyzer: {e}")
            raise

    def analyze_inline_scripts(self) -> Dict[int, Dict]:
        """Analyzes inline JavaScript for risky patterns like eval(), document.write(), etc."""
        risky_patterns = {
            r'\beval\(': "eval() execution",
            r'\bdocument\.write\(': "document.write() execution",
            r'\bsetTimeout\(': "setTimeout() execution",
            r'\bsetInterval\(': "setInterval() execution",
            r'\batob\(': "Base64 decode (atob)",
            r'\bbtoa\(': "Base64 encode (btoa)"
        }
        risky_scripts = {}

        for index, script in enumerate(self.scripts_data.inline_scripts):
            matches = {desc: re.findall(pattern, script) for pattern, desc in risky_patterns.items() if re.search(pattern, script)}
            if matches:
                risky_scripts[index] = {"script": script, "issues": matches}

        logger.info(f"Risky inline scripts found: {len(risky_scripts)}")
        return risky_scripts

    def analyze_external_scripts(self) -> List[str]:
        """Checks external scripts for potential risks (e.g., hosted on untrusted sources)."""
        risky_urls = [url for url in self.scripts_data.external_scripts if "example.com" in url]
        logger.info(f"Risky external scripts found: {len(risky_urls)}")
        return risky_urls

    def analyze_event_handlers(self) -> Dict[str, List[Dict[str, str]]]:
        """Analyzes event handlers in the HTML content to check for XSS risks."""
        risky_event_handlers = {}
        for tag, handlers in self.scripts_data.event_handlers.items():
            filtered_handlers = [handler for handler in handlers if any(re.search(r'\beval\(|\bdocument\.write\(', handler[attr]) for attr in handler)]
            if filtered_handlers:
                risky_event_handlers[tag] = filtered_handlers

        logger.info(f"Risky event handlers found: {len(risky_event_handlers)}")
        return risky_event_handlers

    def analyze_data_urls(self) -> List[str]:
        """Checks for risky data: URLs with embedded JavaScript."""
        risky_data_urls = [url for url in self.scripts_data.data_urls if re.search(r'data:text/javascript;base64,', url)]
        logger.info(f"Risky data URLs found: {len(risky_data_urls)}")
        return risky_data_urls

    def run_analysis(self) -> Dict:
        """Runs the full static analysis and returns the results."""
        result = {
            "risky_inline_scripts": self.analyze_inline_scripts(),
            "risky_external_scripts": self.analyze_external_scripts(),
            "risky_event_handlers": self.analyze_event_handlers(),
            "risky_data_urls": self.analyze_data_urls()
        }
        return result

# Example usage:
if __name__ == "__main__":
    html_content = """
    <html>
        <body>
            <script>eval('alert(1)');</script>
            <script>atob('c2NyaXB0IGFsZXJ0KDEpOw==');</script>
            <img src=x onerror="document.write('XSS')">
        </body>
    </html>
    """
    analyzer = StaticAnalyzer(html_content)
    analysis_result = analyzer.run_analysis()
    print(analysis_result)
