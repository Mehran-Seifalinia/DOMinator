"""
Dynamic Analyzer Module
Performs dynamic analysis of HTML content to detect potential DOM XSS vulnerabilities.
"""

from asyncio import gather, run, TimeoutError
from typing import List, Optional
from pathlib import Path
from playwright.async_api import async_playwright, Page
from extractors.event_handler_extractor import EventHandlerExtractor
from extractors.external_fetcher import ExternalFetcher
from scanners.priority_manager import PriorityManager
from utils.logger import get_logger
from utils.patterns import get_risk_level
from utils.analysis_result import AnalysisResult, Occurrence
from utils.browser_setup import ensure_browser_installed, BrowserNotInstalledError
from urllib.parse import quote
from json import dumps
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
        url: Optional[str] = None,
        payloads: Optional[List[str]] = None,
        sink_types: Optional[List[str]] = None,
        dom_sources: Optional[List[str]] = None,
        timeout: int = 10,
        browser = None,
        level: int = 2,
        proxy: Optional[str] = None,
        cookies: Optional[str] = None
    ) -> None:
        """
        Initialize the DynamicAnalyzer with HTML content and external URLs.
        
        Args:
            html_content (str): The HTML content to analyze
            external_urls (List[str]): List of external URLs to analyze
            headless (bool): Whether to run browser in headless mode
            user_agent (Optional[str]): Custom user agent string
            url (Optional[str]): Original URL of the page
            payloads (Optional[List[str]]): List of XSS payloads to inject
            sink_types (Optional[List[str]]): List of sink types for payload filtering
            dom_sources (Optional[List[str]]): List of DOM sources to guide injection points
            timeout (int): Navigation timeout in seconds
            browser: Optional existing browser instance to reuse
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
        self.payloads = payloads if payloads else []   # store payloads
        self.sink_types = sink_types if sink_types else []
        self.dom_sources = dom_sources if dom_sources else []
        self.timeout = timeout
        self.browser = browser
        self.level = level
        self.proxy = proxy
        self.cookies = cookies
        self._dialog_detected_for_payload = False


    async def analyze_event_handlers(self) -> None:
        """
        Extract and analyze event handlers from HTML.
        
        This method uses the EventHandlerExtractor to identify and analyze
        event handlers in the HTML content that could be used in DOM XSS attacks.
        """
        try:
            extractor = EventHandlerExtractor(self.html_content)
            event_handlers = extractor.extract_event_handlers()
            logger.debug(f"Extracted event handlers: {len(event_handlers)} types found.")
            
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
            results = await page.evaluate("window.__DOMINATOR_RESULTS__ || []")
            if results is None:
                results = []
            logger.debug(f"Instrumentation collected {len(results)} potential vulnerability reports.")
            
            for item in results:
                sink = item.get('sink', 'unknown')
                source = item.get('source', 'unknown')
                payload = item.get('payloadSuggestion', '')
                context = item.get('context', '')
                
                if self._dialog_detected_for_payload:
                    logger.debug("Skipping instrumentation report because dialog was already captured.")
                    continue

                occurrence: Occurrence = {
                    "line": None,
                    "column": None,
                    "pattern": f"{sink} (source: {source})",
                    "context": f"[{sink}] {context}",
                    "risk_level": "informative",
                    "priority": self.priority_manager.get_priority_from_risk_level("high"),
                    "source": "dynamic"
                }
                if payload:
                    occurrence['context'] += f' | PAYLOAD: {payload}'
                self.result.add_dynamic_occurrence(occurrence)
                
        except Exception as e:
            logger.error(f"Error during instrumentation collection: {str(e)}")

    async def _check_for_alert(self, page: Page, timeout: int = 2000) -> Optional[str]:
        try:
            dialog = await page.wait_for_event('dialog', timeout=timeout)
            await dialog.dismiss()
            return dialog.message
        except Exception as e:
            logger.debug(f"Dialog not detected within {timeout}ms: {e}")
            return None
    
    async def _click_buttons_and_check(self, page: Page) -> None:
        """
        Find all buttons or elements with onclick attribute and click them,
        then check for alerts.
        """
        try:
            elements = await page.query_selector_all('[onclick]')
            logger.debug(f"Found {len(elements)} elements with onclick attribute")
            for elem in elements:
                try:
                    # Use expect_event to capture dialog after click
                    async with page.expect_event('dialog', timeout=5000) as dialog_info:
                        await elem.click()
                        await page.wait_for_timeout(500)
                    dialog = await dialog_info.value
                    await dialog.dismiss()
                    occurrence: Occurrence = {
                        "line": None,
                        "column": None,
                        "pattern": "onclick event triggered XSS",
                        "context": f"Clicked element with onclick, alert: {dialog.message}",
                        "risk_level": "medium",
                        "priority": 70,
                        "source": "dynamic"
                    }
                    self.result.add_dynamic_occurrence(occurrence)
                except Exception as e:
                    logger.debug(f"Error clicking element: {e}")
        except Exception as e:
            logger.error(f"Error in click simulation: {e}")

    async def fetch_and_analyze_external_scripts(self) -> None:
        """
        Fetch and analyze external JavaScript files.
        
        This method fetches external JavaScript files and analyzes them for
        potential DOM XSS vulnerabilities.
        """
        try:
            fetcher = ExternalFetcher(
                urls=self.external_urls,
                proxy=self.proxy,
                timeout=self.timeout,
                max_concurrent_requests=5
            )
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
            if "No valid URLs provided" in str(e):
                logger.debug(f"Skipping external script fetch: {str(e)}")
            else:
                logger.error(f"Error fetching or processing external scripts: {str(e)}")

    async def execute_in_browser(self) -> None:
        """Execute HTML in a real browser to detect dynamic vulnerabilities."""
        try:
            self._dialog_detected_for_payload = False
            p = None
            if self.browser is None:
                try:
                    await ensure_browser_installed()
                except BrowserNotInstalledError as e:
                    logger.warning(f"Browser not available: {e}. Skipping browser-based analysis.")
                    return

            close_browser_after = False
            if self.browser is None:
                p = await async_playwright().start()
                self.browser = await p.chromium.launch(
                    headless=self.headless,
                    args=['--no-sandbox'] if not self.headless else ['--sandbox']
                )
                close_browser_after = True

            try:
                context_options = {}
                if self.user_agent:
                    context_options["user_agent"] = self.user_agent
                context = await self.browser.new_context(**context_options)
                page = await context.new_page()

                # Inject instrumentation script if exists (optional)
                if INSTRUMENT_SCRIPT_PATH.exists():
                    instrument_code = INSTRUMENT_SCRIPT_PATH.read_text(encoding='utf-8')
                    await page.add_init_script(instrument_code)
                else:
                    logger.warning(f"Instrumentation script not found at {INSTRUMENT_SCRIPT_PATH}")

                # Case 1: We have a real URL - test with payloads only if sink_types indicate risk
                if self.url and (self.url.startswith('http://') or self.url.startswith('https://')):
                    # First load clean page to set up any initial state
                    await page.goto(self.url, wait_until='networkidle')
                    await self._click_buttons_and_check(page)
                    
                    # Instead of brute-force payload testing, we only inject a marker value
                    # into relevant DOM sources (hash, search, window.name) and rely on
                    # instrumentation to detect if it reaches a sink.
                    
                    # First, load the original URL to let instrumentation hook sinks.
                    await page.goto(self.url, wait_until='networkidle')
                    await self._click_buttons_and_check(page)
                    
                    # Determine which sources are present based on dom_sources.
                    inject_hash = any('hash' in src.lower() for src in self.dom_sources)
                    inject_search = any('search' in src.lower() or 'query' in src.lower() for src in self.dom_sources)
                    
                    # Default to both if no sources detected (common DOM XSS patterns)
                    if not inject_hash and not inject_search:
                        inject_hash = True
                        inject_search = True
                    
                    marker = '__DOMINATOR_TEST__'
                    
                    # Test injection via URL hash if relevant
                    if inject_hash:
                        test_url_hash = self.url + '#' + marker
                        await page.goto(test_url_hash, wait_until='networkidle')
                        await page.wait_for_timeout(500)
                    
                    # Test injection via URL query parameter if relevant
                    if inject_search:
                        from urllib.parse import urlparse, urlunparse, quote
                        parsed = urlparse(self.url)
                        # Replace or add query parameter
                        if parsed.query:
                            new_query = parsed.query + '&__dominator_test__=' + quote(marker)
                        else:
                            new_query = '__dominator_test__=' + quote(marker)
                        new_parsed = parsed._replace(query=new_query)
                        test_url_query = urlunparse(new_parsed)
                        await page.goto(test_url_query, wait_until='networkidle')
                        await page.wait_for_timeout(500)
                    
                    # Also test window.name (a common but less used source)
                    # Only if any source pattern suggests window.name is used
                    if any('window.name' in src.lower() for src in self.dom_sources):
                        await page.evaluate(f"window.name = '{marker}'")
                        await page.reload(wait_until='networkidle')
                        await page.wait_for_timeout(500)
                
                # Case 2: Offline HTML content
                else:
                    logger.debug("Executing HTML in a real browser environment (offline)...")
                    await page.set_content(self.html_content)
                    await self._click_buttons_and_check(page)
                    
                    # Simulate DOM sources by setting window.name and a fake location hash
                    marker = '__DOMINATOR_TEST__'
                    await page.evaluate(f"window.name = '{marker}'")
                    
                    # Set a fake location hash using history.pushState
                    await page.evaluate(f"""
                        history.pushState({{}}, '', '#{marker}');
                        window.dispatchEvent(new HashChangeEvent('hashchange'));
                    """)
                    await page.wait_for_timeout(500)

                # Collect instrumentation results if any (optional)
                await self._instrument_and_collect(page)
                
                await context.close()
            finally:
                if close_browser_after:
                    await self.browser.close()
                    if p:
                        await p.stop()
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
        logger.debug("Starting dynamic analysis...")
    
        try:
            await gather(
                self.analyze_event_handlers(),
                self.fetch_and_analyze_external_scripts(),
                self.execute_in_browser()
            )
    
            logger.debug("Dynamic analysis completed successfully")
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
