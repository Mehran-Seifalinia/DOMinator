"""
Dynamic Analyzer Module
Performs dynamic analysis of HTML content to detect potential DOM XSS vulnerabilities.
"""

from asyncio import gather, run
from typing import List, Optional
from pathlib import Path
from playwright.async_api import async_playwright, Page
from extractors.event_handler_extractor import EventHandlerExtractor
from extractors.external_fetcher import ExternalFetcher
from scanners.priority_manager import PriorityManager
from utils.logger import get_logger
from utils.patterns import get_risk_level
from utils.analysis_result import AnalysisResult, Occurrence
from utils.browser_setup import ensure_browser_installed
from utils.browser_setup import ensure_browser_installed, BrowserNotInstalledError

logger = get_logger(__name__)

INSTRUMENT_SCRIPT_PATH = Path(__file__).parent.parent / 'utils' / 'dom_instrument.js'
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
        user_agent: Optional[str] = None,
        url: Optional[str] = None
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
        self.url = url

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

    async def _instrument_and_collect(self, page: Page) -> None:
        """Collect DOM XSS vulnerability reports from instrumented page."""
        try:
            await page.wait_for_timeout(1000)
            results: list = await page.evaluate("window.__DOMINATOR_RESULTS__ || []")
            logger.info(f"Instrumentation collected {len(results)} potential vulnerability reports.")
            
            for item in results:
                sink = item.get('sink', 'unknown')
                source = item.get('source', 'unknown')
                payload = item.get('payloadSuggestion', '')
                context = item.get('context', '')
                
                occurrence: Occurrence = {
                    "line": None,
                    "column": None,
                    "pattern": f"{sink} (source: {source})",
                    "context": f"[{sink}] {context}",
                    "risk_level": "high",
                    "priority": self.priority_manager.get_priority_from_risk_level("high"),
                    "source": "dynamic"
                }
                if payload:
                    occurrence['context'] += f' | PAYLOAD: {payload}'
                self.result.add_dynamic_occurrence(occurrence)
                
        except Exception as e:
            logger.error(f"Error during instrumentation collection: {str(e)}")

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
                        "priority": self.priority_manager.get_priority_from_risk_level(get_risk_level(risk)),
                        "source": "external"
                    }
                    self.result.add_external_script_risk(occurrence)
                
        except Exception as e:
            logger.error(f"Error fetching or processing external scripts: {str(e)}")
            self.result.set_error(f"Error fetching or processing external scripts: {str(e)}")

    async def execute_in_browser(self) -> None:
        """Execute HTML in a real browser to detect dynamic vulnerabilities."""
        try:
            try:
                await ensure_browser_installed()
            except BrowserNotInstalledError as e:
                logger.warning(f"Browser not available: {e}. Skipping browser-based analysis.")
                return

            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=self.headless,
                    args=['--no-sandbox'] if not self.headless else ['--sandbox']
                )
                context_options = {}
                if self.user_agent:
                    context_options["user_agent"] = self.user_agent
                context = await browser.new_context(**context_options)
                page = await context.new_page()

                # Inject instrumentation script before any page script runs
                if INSTRUMENT_SCRIPT_PATH.exists():
                    instrument_code = INSTRUMENT_SCRIPT_PATH.read_text(encoding='utf-8')
                    await page.add_init_script(instrument_code)
                else:
                    logger.error(f"Instrumentation script not found at {INSTRUMENT_SCRIPT_PATH}")

                if self.url and (self.url.startswith('http://') or self.url.startswith('https://')):
                    test_url = self.url + '#__DOMINATOR_TEST__'
                    logger.info(f"Navigating to {test_url} for dynamic analysis...")
                    await page.goto(test_url, wait_until='networkidle')
                else:
                    logger.info("Executing HTML in a real browser environment (offline)...")
                    await page.set_content(self.html_content)

                await self._instrument_and_collect(page)
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
