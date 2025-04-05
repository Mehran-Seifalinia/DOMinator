if __name__ == "__main__":
    from sys import path as spath
    from os import path as opath
    spath.append(opath.abspath(opath.join(opath.dirname(__file__), '..')))
    
import re
import json
from typing import List, Dict, Optional
from bs4 import BeautifulSoup
from utils.logger import get_logger
from traceback import format_exc
from html5lib import parse
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    """Validate the HTML content using html5lib.
    
    This function uses html5lib to parse the given HTML content. It ensures that the HTML is syntactically valid,
    even if it's not fully correct, since html5lib tries to correct certain mistakes. If the HTML content is severely 
    malformed and cannot be parsed, a ValueError will be raised.
    
    Returns:
        bool: True if the HTML is valid, False otherwise.
    """
    try:
        # Try parsing the HTML content using html5lib
        parse(html)
        return True
    except ValueError as e:
        # Log and handle the specific error when HTML is invalid
        logger.error(f"Invalid HTML content: {e}")
        return False
    except Exception as e:
        # Log unexpected errors with the full traceback for debugging purposes
        logger.error(f"Unexpected error during HTML validation: {e}\n{format_exc()}")
        return False

class ScriptExtractor:
    def __init__(self, html: str, proxy: Optional[str] = None, user_agent: Optional[str] = None):
        # Ensure the HTML input is a valid non-empty string
        if not isinstance(html, str) or not html.strip():
            raise TypeError("HTML content must be a non-empty string.")
        
        # Validate HTML content
        if not validate_html(html):
            raise ValueError("Invalid HTML: The provided HTML is not valid.")
        
        # Parse the HTML content into BeautifulSoup object
        try:
            self.soup = BeautifulSoup(html, "html.parser")
        except Exception as e:
            logger.error(f"Error parsing HTML with BeautifulSoup: {e}\n{format_exc()}")
            raise ValueError("Failed to parse the HTML content.")  # Raising a more specific exception

    def extract_inline_scripts(self) -> List[str]:
        """Extract inline scripts that match DOM XSS patterns."""
        try:
            # Extracting scripts only once to improve efficiency
            scripts = [
                script.string.strip() if script.string else script.get_text().strip()
                for script in self.soup.find_all("script")
                if script.string or script.get_text()
            ]
            
            # Use a set to avoid duplicate scripts
            filtered_scripts = set()
    
            for script in scripts:
                # Check each script for potential DOM XSS patterns
                for pattern in DOM_XSS_PATTERNS:
                    if re.search(pattern, script):
                        filtered_scripts.add(script)
                        break  # Break once a matching pattern is found
            
            if not filtered_scripts:
                logger.debug("No potential DOM XSS inline scripts found.")
            
            # Return a list of filtered scripts
            return list(filtered_scripts)
        
        except Exception as e:
            logger.error(f"Unexpected error extracting inline scripts: {e}\n{format_exc()}")
            return []


    def get_scripts(self) -> List[str]:
        """Extract inline scripts concurrently."""
        try:
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(self.extract_inline_scripts) for _ in range(4)]
                
                # Using as_completed for better performance with large numbers of futures
                results = []
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Error while processing future: {e}\n{format_exc()}")
                
                # Flatten the results from multiple threads
                return [script for sublist in results for script in sublist]
        
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
    


