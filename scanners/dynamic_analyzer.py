"""
Dynamic Analyzer Module
Performs dynamic analysis of HTML content to detect potential DOM XSS vulnerabilities.
"""

import asyncio
from typing import List, Dict, Optional, Any
from playwright.async_api import async_playwright, Page
from extractors.event_handler_extractor import EventHandlerExtractor
from extractors.external_fetcher import ExternalFetcher
from scanners.priority_manager import PriorityManager
from utils.logger import get_logger
from utils.patterns import DANGEROUS_JS_PATTERNS, DANGEROUS_HTML_PATTERNS, get_risk_level
from utils.analysis_result import AnalysisResult, Occurrence

logger = get_logger(__name__)

class DynamicAnalyzer:
    """
    A class for performing dynamic analysis of HTML content to detect potential DOM XSS vulnerabilities.
    
    This class uses a combination of browser automation and static analysis to detect
    potential DOM XSS vulnerabilities in web applications.
    """
    
    def __init__(self, html_content: str, external_urls: List[str]) -> None:
        """
        Initialize the DynamicAnalyzer with HTML content and external URLs.
        
        Args:
            html_content (str): The HTML content to analyze
            external_urls (List[str]): List of external URLs to analyze
            
        Raises:
            ValueError: If HTML content is invalid
        """
        if not html_content or not isinstance(html_content, str):
            raise ValueError("HTML content must be a non-empty string.")
        
        self.html_content = html_content
        self.external_urls = external_urls
        self.priority_manager = PriorityManager()
        self.result = AnalysisResult()

    async def analyze_event_handlers(self) -> None:
        """
        Extract and analyze event handlers from HTML.
        
        This method uses the EventHandlerExtractor to identify and analyze
        event handlers in the HTML content that could be used in DOM XSS attacks.
        """
        try:
            extractor = EventHandlerExtractor(self.html_content)
            event_handlers = extractor.extract_event_handlers()
            logger.info(f"Extracted event handlers: {event_handlers}")
            
            for event_type, handlers in event_handlers.items():
                for handler in handlers:
                    self.result.add_event_handler(event_type, handler)
                    
        except Exception as e:
            logger.error(f"Error analyzing event handlers: {e}")
            self.result.set_error(f"Error analyzing event handlers: {e}")

    async def fetch_and_analyze_external_scripts(self) -> None:
        """
        Fetch and analyze external JavaScript files.
        
        This method fetches external JavaScript files and analyzes them for
        potential DOM XSS vulnerabilities.
        """
        try:
            fetcher = ExternalFetcher(self.external_urls)
            await fetcher.fetch_and_process_scripts()
            
            for risk in fetcher.get_risks():
                occurrence: Occurrence = {
                    "line": None,
                    "column": None,
                    "pattern": risk,
                    "context": risk,
                    "risk_level": get_risk_level(risk),
                    "priority": self.priority_manager.calculate_optimized_priority(get_risk_level(risk)),
                    "source": "external"
                }
                self.result.add_external_script_risk(occurrence)
                
        except Exception as e:
            logger.error(f"Error fetching or processing external scripts: {e}")
            self.result.set_error(f"Error fetching or processing external scripts: {e}")

    async def analyze_dom_xss_risk(self, page: Page) -> None:
        """
        Analyze DOM XSS vulnerabilities by checking dangerous attributes and script inclusions.
        
        Args:
            page (Page): Playwright page object for browser interaction
        """
        try:
            elements = await page.query_selector_all('*')
            for element in elements:
                outer_html = await element.inner_html()
                if "<script>" in outer_html or "javascript:" in outer_html:
                    occurrence: Occurrence = {
                        "line": None,
                        "column": None,
                        "pattern": outer_html,
                        "context": outer_html,
                        "risk_level": "high",
                        "priority": self.priority_manager.calculate_optimized_priority("high"),
                        "source": "dynamic"
                    }
                    self.result.add_dynamic_occurrence(occurrence)
                    
                attributes = await element.get_property("attributes")
                for attr in attributes:
                    if any(keyword in attr['value'] for keyword in ['javascript:', 'onerror', 'onload']):
                        occurrence: Occurrence = {
                            "line": None,
                            "column": None,
                            "pattern": attr['value'],
                            "context": f"Element with {attr['name']}={attr['value']}",
                            "risk_level": get_risk_level(attr['value']),
                            "priority": self.priority_manager.calculate_optimized_priority(get_risk_level(attr['value'])),
                            "source": "dynamic"
                        }
                        self.result.add_dynamic_occurrence(occurrence)
                        
        except Exception as e:
            logger.error(f"Error while analyzing DOM XSS risks: {e}")
            self.result.set_error(f"Error while analyzing DOM XSS risks: {e}")

    async def execute_in_browser(self) -> None:
        """
        Execute HTML in a real browser to detect dynamic vulnerabilities.
        
        This method uses Playwright to load the HTML content in a browser
        and analyze it for potential DOM XSS vulnerabilities.
        """
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                async with browser.new_context() as context:
                    async with context.new_page() as page:
                        logger.info("Executing HTML in a real browser environment...")
                        await page.set_content(self.html_content)
                        await self.analyze_dom_xss_risk(page)
                        
        except Exception as e:
            logger.error(f"Error during dynamic analysis in browser: {e}")
            self.result.set_error(f"Error during dynamic analysis in browser: {e}")

    async def run_analysis(self) -> AnalysisResult:
        """
        Run the full dynamic analysis process.
        
        Returns:
            AnalysisResult: The result of the dynamic analysis
            
        Note:
            This method coordinates all analysis tasks and runs them in parallel
            for better performance.
        """
        logger.info("Starting dynamic analysis...")
    
        try:
            await asyncio.gather(
                self.analyze_event_handlers(),
                self.fetch_and_analyze_external_scripts(),
                self.execute_in_browser()
            )
    
            logger.info("Dynamic analysis completed successfully")
            self.result.set_completed()
            return self.result
    
        except Exception as e:
            logger.error(f"Error during full analysis: {e}")
            self.result.set_error(f"Error during full analysis: {e}")
            return self.result

if __name__ == "__main__":
    html_content = "<html><body><div onclick='alert(\"Hello\");'></div></body></html>"
    external_urls = ["https://example.com/script1.js", "https://example.com/script2.js"]
    
    analyzer = DynamicAnalyzer(html_content, external_urls)
    asyncio.run(analyzer.run_analysis())
