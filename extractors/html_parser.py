import re
import json
from typing import List, Dict
from bs4 import BeautifulSoup
from utils.logger import get_logger
from traceback import format_exc
from html5lib import parse
from concurrent.futures import ThreadPoolExecutor

# Logger setup
logger = get_logger()

# Regex patterns to detect potentially dangerous JavaScript patterns
DOM_XSS_PATTERNS = [
    r"eval\(", r"document\.write\(", r"setTimeout\(", r"setInterval\(", r"innerHTML",
    r"document\.location", r"Function\(", r"window\.location", r"window\.eval",
    r"document\.createElement", r"document\.createTextNode", r"String\(",
    r"unescape\(", r"decodeURIComponent\(", r"escape\(", r"XMLHttpRequest",
    r"location\.replace", r"localStorage", r"sessionStorage", r"window\.open",
    r"alert\(", r"console\.log\(", r"confirm\(", r"prompt\(",
    r"insertAdjacentHTML\(", r"insertBefore\(", r"outerHTML", r"createRange", r"createContextualFragment",
    r"window\.open\(", r"location\.href", r"document\.location\.href", r"document\.domain",
    r"document\.getElementById\(", r"document\.getElementsByClassName\(", r"document\.getElementsByName\(",
    r"javascript:", r"srcdoc"
]

def validate_html(html: str) -> bool:
    """Validate the HTML content using html5lib."""
    try:
        parse(html)
        return True
    except ValueError as e:
        logger.error(f"Invalid HTML content: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during HTML validation: {e}\n{format_exc()}")
        return False

class ScriptExtractor:
    def __init__(self, html: str):
        if not html or not isinstance(html, str) or not html.strip():
            raise TypeError("HTML content must be a non-empty string.")

        if not validate_html(html):
            raise ValueError("Invalid HTML: The provided HTML is not valid.")

        self.soup = BeautifulSoup(html, "html.parser")

    def extract_inline_scripts(self) -> List[str]:
        """Extract inline scripts that match DOM XSS patterns."""
        try:
            scripts = [
                script.string.strip() if script.string else script.text.strip()
                for script in self.soup.find_all("script")
                if script.string or script.text
            ]
            ffiltered_scripts = set()
            for script in scripts:
                for pattern in DOM_XSS_PATTERNS:
                    if re.search(pattern, script):
                        filtered_scripts.append(script)
                        break

            if not filtered_scripts:
                logger.warning("No potential DOM XSS inline scripts found.")
            return filtered_scripts
        except Exception as e:
            logger.error(f"Unexpected error extracting inline scripts: {e}\n{format_exc()}")
            return []

    def get_scripts(self) -> List[str]:
        """Extract inline scripts concurrently."""
        with ThreadPoolExecutor(max_workers=4) as executor:
            future = executor.submit(self.extract_inline_scripts)
            try:
                return future.result()
            except Exception as e:
                logger.error(f"Error extracting inline scripts: {e}\n{format_exc()}")
                return []

    def generate_report(self, inline_scripts: List[str]) -> Dict[str, List[str]]:
        """Generate a summary report based on inline scripts."""
        report = {
            "inline_scripts": len(inline_scripts),
        }

        detailed_report = []
        for idx, script in enumerate(inline_scripts, start=1):
            detailed_report.append(f"Script {idx}: {script[:50]}...")

        report["detailed_inline_scripts"] = detailed_report
        logger.info(f"Generated report: {json.dumps(report, indent=4)}")
        return report
