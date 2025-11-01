"""
Dynamic Analyzer Module
Performs dynamic analysis of HTML content to detect potential DOM XSS vulnerabilities.
"""

from asyncio import gather, run
from typing import List, Optional
from playwright.async_api import async_playwright, Page
from extractors.event_handler_extractor import EventHandlerExtractor
from extractors.external_fetcher import ExternalFetcher
from scanners.priority_manager import PriorityManager
from utils.logger import get_logger
from utils.patterns import get_risk_level
from utils.analysis_result import AnalysisResult, Occurrence

logger = get_logger(__name__)

# Maximum allowed HTML size in bytes to prevent memory issues
MAX_HTML_SIZE = 10 * 1024 * 1024  # 10 MB

class DynamicAnalyzer:
    """
    A class for performing dynamic analysis of HTML content to detect potential DOM XSS vulnerabilities.
    
    This class uses a combination of browser automation and static analysis to detect
    potential DOM XSS vulnerabilities in web applications.
    """
    
    def __init__(
        self, 
        html_content: str, 
        external_urls: List[str], 
        headless: bool = True, 
        user_agent: Optional[str] = None
    ) -> None:
        """
        Initialize the DynamicAnalyzer with HTML content and external URLs.
        
        Args:
            html_content (str): The HTML content to analyze
            external_urls (List[str]): List of external URLs to analyze
            headless (bool): Whether to run browser in headless mode
            user_agent (Optional[str]): Custom user agent string
            
        Raises:
            ValueError: If HTML content is invalid or too large
        """
        if not isinstance(html_content, str) or not html_content.strip():
            raise ValueError("HTML content must be a non-empty string.")
        
        if len(html_content) > MAX_HTML_SIZE:
            logger.error(f"HTML content exceeds maximum size ({MAX_HTML_SIZE} bytes).")
            raise ValueError("HTML content is too large.")
        
        self.html_content = html_content
        self.external_urls = external_urls
        self.headless = headless
        self.user_agent = user_agent
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
            logger.info(f"Extracted event handlers: {len(event_handlers)} types found.")
            
            for event_type, handlers in event_handlers.items():
                for handler in handlers:
                    self.result.add_event_handler(event_type, handler)
                    
        except Exception as e:
            logger.error(f"Error analyzing event handlers: {str(e)}")
            self.result.set_error(f"Error analyzing event handlers: {str(e)}")

    async def fetch_and_analyze_external_scripts(self) -> None:
        """
        Fetch and analyze external JavaScript files.
        
        This method fetches external JavaScript files and analyzes them for
        potential DOM XSS vulnerabilities.
        """
        try:
            fetcher = ExternalFetcher(self.external_urls)
            await fetcher.fetch_and_process_scripts()
            
            analysis_results = fetcher.get_analysis_results()
            for res in analysis_results:
                # Aggregate risks from event_listeners, risky_functions, sources, sinks
                risks = res.event_listeners + res.risky_functions + res.sources + res.sinks
                for risk in set(risks):  # Unique risks
                    occurrence: Occurrence = {
                        "line": None,
                        "column": None,
                        "pattern": risk,
                        "context": f"From {res.url}: {risk}",
                        "risk_level": get_risk_level(risk),
                        "priority": self.priority_manager.calculate_optimized_priority(get_risk_level(risk)),
                        "source": "external"
                    }
                    self.result.add_external_script_risk(occurrence)
                
        except Exception as e:
            logger.error(f"Error fetching or processing external scripts: {str(e)}")
            self.result.set_error(f"Error fetching or processing external scripts: {str(e)}")

    async def analyze_dom_xss_risk(self, page: Page) -> None:
        """
        Analyze DOM XSS vulnerabilities by checking dangerous attributes and script inclusions.
        
        Args:
            page (Page): Playwright page object for browser interaction
        """
        try:
            # Get all elements
            elements = await page.query_selector_all('*')
            for element in elements:
                # Check for dynamic script injections or javascript: protocols in outer HTML
                outer_html = await element.evaluate('el => el.outerHTML')
                if "<script>" in outer_html.lower() or "javascript:" in outer_html.lower():
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
                
                # Get all attributes for the element
                attr_names = await element.evaluate('el => Array.from(el.attributes).map(attr => attr.name)')
                for attr_name in attr_names:
                    attr_value = await element.get_attribute(attr_name)
                    if attr_value and any(keyword in attr_value.lower() for keyword in ['javascript:', 'onerror', 'onload']):
                        occurrence: Occurrence = {
                            "line": None,
                            "column": None,
                            "pattern": attr_value,
                            "context": f"Element {await element.evaluate('el => el.tagName')} with {attr_name}={attr_value}",
                            "risk_level": get_risk_level(attr_value),
                            "priority": self.priority_manager.calculate_optimized_priority(get_risk_level(attr_value)),
                            "source": "dynamic"
                        }
                        self.result.add_dynamic_occurrence(occurrence)
                        
        except Exception as e:
            logger.error(f"Error while analyzing DOM XSS risks: {str(e)}")
            self.result.set_error(f"Error while analyzing DOM XSS risks: {str(e)}")

    async def execute_in_browser(self) -> None:
        """
        Execute HTML in a real browser to detect dynamic vulnerabilities.
        
        This method uses Playwright to load the HTML content in a browser
        and analyze it for potential DOM XSS vulnerabilities.
        
        Note: Browser is launched with sandbox for security.
        """
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless, args=['--no-sandbox'] if not self.headless else ['--sandbox'])
                context_options = {}
                if self.user_agent:
                    context_options["user_agent"] = self.user_agent
                    
                context = await browser.new_context(**context_options)
                page = await context.new_page()
                logger.info("Executing HTML in a real browser environment...")
                await page.set_content(self.html_content)
                await self.analyze_dom_xss_risk(page)
                await context.close()
                await browser.close()
                        
        except Exception as e:
            logger.error(f"Error during dynamic analysis in browser: {str(e)}")
            self.result.set_error(f"Error during dynamic analysis in browser: {str(e)}")

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
            await gather(
                self.analyze_event_handlers(),
                self.fetch_and_analyze_external_scripts(),
                self.execute_in_browser()
            )
    
            logger.info("Dynamic analysis completed successfully")
            self.result.set_completed()
            return self.result
    
        except Exception as e:
            logger.error(f"Error during full analysis: {str(e)}")
            self.result.set_error(f"Error during full analysis: {str(e)}")
            return self.result

if __name__ == "__main__":
    html_content = "<html><body><div onclick='alert(\"Hello\");'></div></body></html>"
    external_urls = ["https://example.com/script1.js", "https://example.com/script2.js"]
    
    analyzer = DynamicAnalyzer(html_content, external_urls)
    run(analyzer.run_analysis())
