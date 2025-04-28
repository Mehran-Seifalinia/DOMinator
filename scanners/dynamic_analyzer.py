import asyncio
from typing import List, Dict, Optional
from playwright.async_api import async_playwright
from extractors.event_handler_extractor import EventHandlerExtractor
from extractors.external_fetcher import ExternalFetcher
from scanners.priority_manager import PriorityManager
from utils.logger import get_logger
from utils.patterns import DANGEROUS_JS_PATTERNS, DANGEROUS_HTML_PATTERNS, get_risk_level

# Get the logger instance from logger.py
logger = get_logger()

class DynamicAnalysisResult:
    def __init__(self):
        self.event_handlers: Dict[str, List[str]] = {}
        self.dom_xss_risks: List[str] = []
        self.external_script_risks: List[str] = []

    def to_dict(self) -> Dict:
        return {
            "event_handlers": self.event_handlers,
            "dom_xss_risks": self.dom_xss_risks,
            "external_script_risks": self.external_script_risks
        }

class DynamicAnalyzer:
    def __init__(self, html_content: str, external_urls: List[str]):
        if not html_content or not isinstance(html_content, str):
            raise ValueError("HTML content must be a non-empty string.")
        
        self.html_content = html_content
        self.external_urls = external_urls
        self.priority_manager = PriorityManager()
        self.result = DynamicAnalysisResult()

    async def analyze_event_handlers(self) -> Dict[str, List[str]]:
        """Extract and analyze event handlers from HTML"""
        try:
            extractor = EventHandlerExtractor(self.html_content)
            event_handlers = extractor.extract_event_handlers()
            logger.info(f"Extracted event handlers: {event_handlers}")
            self.result.event_handlers = event_handlers
            return event_handlers
        except Exception as e:
            logger.error(f"Error analyzing event handlers: {e}")
            return {}

    async def fetch_and_analyze_external_scripts(self) -> None:
        """Fetch and analyze external JavaScript files"""
        try:
            fetcher = ExternalFetcher(self.external_urls)
            await fetcher.fetch_and_process_scripts()
            self.result.external_script_risks = fetcher.get_risks()
        except Exception as e:
            logger.error(f"Error fetching or processing external scripts: {e}")

    async def analyze_dom_xss_risk(self, page) -> List[str]:
        """Analyze DOM XSS vulnerabilities by checking dangerous attributes and script inclusions"""
        xss_risks = []
        try:
            elements = await page.query_selector_all('*')
            for element in elements:
                outer_html = await element.inner_html()
                if "<script>" in outer_html or "javascript:" in outer_html:
                    xss_risks.append(outer_html)
                # Check attributes like src, href, onerror, onload for potential XSS
                attributes = await element.get_property("attributes")
                for attr in attributes:
                    if any(keyword in attr['value'] for keyword in ['javascript:', 'onerror', 'onload']):
                        xss_risks.append(f"Element with {attr['name']}={attr['value']}")
            return xss_risks
        except Exception as e:
            logger.error(f"Error while analyzing DOM XSS risks: {e}")
            return []

    async def execute_in_browser(self) -> List[str]:
        """Execute HTML in a real browser to detect dynamic vulnerabilities"""
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                async with browser.new_context() as context:
                    async with context.new_page() as page:
                        logger.info("Executing HTML in a real browser environment...")
                        await page.set_content(self.html_content)
                        
                        # First analyze DOM XSS risks
                        dom_xss_results = await self.analyze_dom_xss_risk(page)
                        self.result.dom_xss_risks = dom_xss_results
                        return dom_xss_results
        except Exception as e:
            logger.error(f"Error during dynamic analysis in browser: {e}")
            return []

    async def run_analysis(self) -> DynamicAnalysisResult:
        """Run the full dynamic analysis process"""
        logger.info("Starting dynamic analysis...")
    
        try:
            # Running tasks in parallel
            event_handlers_task = self.analyze_event_handlers()
            external_scripts_task = self.fetch_and_analyze_external_scripts()
            dom_results_task = self.execute_in_browser()
    
            # Gathering all the results
            await asyncio.gather(
                event_handlers_task,
                external_scripts_task,
                dom_results_task
            )
    
            logger.info(f"Dynamic analysis completed successfully")
            return self.result
    
        except Exception as e:
            logger.error(f"Error during full analysis: {e}")
            return self.result

if __name__ == "__main__":
    html_content = "<html><body><div onclick='alert(\"Hello\");'></div></body></html>"
    external_urls = ["https://example.com/script1.js", "https://example.com/script2.js"]
    
    analyzer = DynamicAnalyzer(html_content, external_urls)
    asyncio.run(analyzer.run_analysis())
