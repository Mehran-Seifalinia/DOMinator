import re
import logging
from html_Parser import ScriptExtractor
from typing import List, Dict

# Initialize logger for security analysis
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def analyze_script(script: str) -> int:
    """
    Analyze JavaScript code to detect potential XSS vulnerabilities.
    Uses regex patterns and a weighted risk scoring system.
    """
    risk_score = 0  # Initialize risk score

    # 🛑 Detect `eval()` with dynamic input (avoid detecting static values)
    if re.search(r'\beval\s*\(\s*[a-zA-Z_$][\w$]*', script):
        risk_score += 3  # High-risk behavior: executing dynamic input

    # 🚨 Identify `innerHTML` and `outerHTML` assignments with dynamic values
    if re.search(r'\b(innerHTML|outerHTML)\s*=\s*[a-zA-Z_$][\w$]*', script):
        risk_score += 2  # Medium-risk: possible DOM injection

    # ⏳ Detect `setTimeout` and `setInterval` executing strings instead of functions
    if re.search(r'\bset(Time|Interval)\s*\(\s*[\'"]', script):
        risk_score += 2  # Medium-risk: unsafe delayed execution

    # 🔓 Identify `atob()` misuse leading to `eval()` or `document.write()`
    if re.search(r'atob\s*\(\s*.*?\s*\)\s*(\||\+|\*|\/|\(|\[|\{)*\s*(eval|document\.write)', script):
        risk_score += 3  # High-risk: Base64 payload decoding & execution

    # ⚠️ Detect potentially risky event handlers
    if "onerror=" in script or "onload=" in script:
        risk_score += 1  # Low-risk: could be used for malicious payloads

    # 🌍 Detect location-based redirections (possible phishing attempt)
    if "location.href=" in script or "document.URL=" in script:
        risk_score += 1  # Low-risk: potential URL manipulation

    # 🟢 Ignore harmless functions like `console.log()` and `alert()`
    if "console.log(" in script or "alert(" in script:
        risk_score -= 1  # Reduce false positives

    # 🚨 Risk classification based on accumulated score
    if risk_score >= 5:
        logger.warning("⚠️ High-risk script detected!")
    elif risk_score >= 3:
        logger.info("⚠️ Medium-risk script detected.")
    else:
        logger.info("✅ Low-risk script.")

    return risk_score  # Return final risk score for further analysis


class StaticAnalyzer:
    """Performs static analysis on the HTML and JavaScript content for potential XSS vulnerabilities."""
    
    def __init__(self, html: str):
        """Initializes the analyzer with the given HTML content."""
        try:
            self.extractor = ScriptExtractor(html)
            self.scripts_data = self.extractor.get_scripts()
            logger.info("Static analyzer initialized.")
        except ValueError as e:
            logger.error(f"Error initializing StaticAnalyzer: {e}")
            raise

    def analyze_inline_scripts(self) -> Dict[int, Dict]:
        """Analyzes inline JavaScript for risky patterns like eval(), document.write(), etc."""
        risky_scripts = {}
        for index, script in enumerate(self.scripts_data.inline_scripts):
            risk_score = analyze_script(script)  # Get risk score for each script
            if risk_score > 0:
                risky_scripts[index] = {"script": script, "risk_score": risk_score}

        logger.info(f"Risky inline scripts found: {len(risky_scripts)}")
        return risky_scripts

    def analyze_external_scripts(self) -> List[str]:
        """Checks external scripts for potential risks (e.g., hosted on untrusted sources)."""
        known_malicious_sources = ["malicious.com", "untrusted-source.net", "suspicious-domain.org"]
        risky_urls = [url for url in self.scripts_data.external_scripts if any(domain in url for domain in known_malicious_sources)]
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
