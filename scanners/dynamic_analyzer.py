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
from utils.browser_setup import ensure_browser_installed, BrowserNotInstalledError
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

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
    
    async def _test_url_with_payload(self, page: Page, base_url: str, payload: str, inject_in: str = 'hash') -> bool:
        """
        Test a single payload by injecting it into URL hash or query parameter.
        
        Args:
            page (Page): Playwright page
            base_url (str): Original URL
            payload (str): XSS payload
            inject_in (str): 'hash' or 'query'
            
        Returns:
            bool: True if alert was detected
        """
        # Build test URLs based on inject_in
        test_urls = []
        if inject_in == 'hash':
            if '#' in base_url:
                test_urls.append(base_url.split('#')[0] + '#' + payload)
            else:
                test_urls.append(base_url + '#' + payload)
        elif inject_in == 'query':
            parsed = urlparse(base_url)
            query_dict = parse_qs(parsed.query)
            if query_dict:
                # Test each existing parameter (max 2)
                params_list = list(query_dict.keys())
                for param in params_list[:2]:
                    new_query_dict = {}
                    for other_param, values in query_dict.items():
                        if other_param == param:
                            new_query_dict[param] = [payload]
                        else:
                            new_query_dict[other_param] = values
                    new_query = urlencode(new_query_dict, doseq=True)
                    test_urls.append(urlunparse(parsed._replace(query=new_query)))
                # Fallback: add xss parameter
                query_dict['xss'] = [payload]
                new_query = urlencode(query_dict, doseq=True)
                test_urls.append(urlunparse(parsed._replace(query=new_query)))
            else:
                # No existing params, add xss
                test_urls.append(urlunparse(parsed._replace(query=f"xss={payload}")))
        else:
            return False
        
        # Test each URL
        for test_url in test_urls[:3]:  # limit to 3 variants
            logger.debug(f"Testing payload in {inject_in}: {test_url}")
            try:
                # Set up dialog listener BEFORE navigation
                dialog_msg = None
                async def on_dialog(dialog):
                    nonlocal dialog_msg
                    dialog_msg = dialog.message
                    await dialog.dismiss()
                page.once('dialog', on_dialog)
                
                await page.goto(test_url, wait_until='networkidle', timeout=self.timeout * 1000)
                await page.wait_for_timeout(1000)
                
                if dialog_msg:
                    occurrence: Occurrence = {
                        "line": None,
                        "column": None,
                        "pattern": f"DOM XSS via {inject_in} injection",
                        "context": f"Payload: {payload} triggered alert: {dialog_msg}",
                        "risk_level": "high",
                        "priority": 90,
                        "source": "dynamic"
                    }
                    self.result.add_dynamic_occurrence(occurrence)
                    return True
            except Exception as e:
                logger.debug(f"Error testing URL {test_url}: {e}")
        return False
    
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
                    # Set up dialog listener BEFORE click
                    dialog_msg = None
                    async def on_dialog(dialog):
                        nonlocal dialog_msg
                        dialog_msg = dialog.message
                        await dialog.dismiss()
                    page.once('dialog', on_dialog)
                    
                    await elem.click()
                    await page.wait_for_timeout(1500)
                    
                    if dialog_msg:
                        occurrence: Occurrence = {
                            "line": None,
                            "column": None,
                            "pattern": "onclick event triggered XSS",
                            "context": f"Clicked element with onclick, alert: {dialog_msg}",
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
                    
                    # Determine which injection points to test based on DOM sources
                    inject_locations = set()
                    for src in self.dom_sources:
                        src_lower = src.lower()
                        if 'hash' in src_lower:
                            inject_locations.add('hash')
                        if 'search' in src_lower or '? ' in src_lower or 'query' in src_lower:
                            inject_locations.add('query')
                        if 'href' in src_lower or 'url' in src_lower:
                            # For href/URL, test both? but to be safe, add both
                            inject_locations.add('hash')
                            inject_locations.add('query')
                    
                    # If no specific source found, default to testing hash only (more common for DOM XSS)
                    if not inject_locations:
                        inject_locations.add('hash')
                    
                    sink_lower_set = {s.lower() for s in self.sink_types}

                    is_html_sink = any(s in sink_lower_set for s in ['innerhtml', 'outerhtml', 'document.write'])
                    is_eval_sink = any(s in sink_lower_set for s in ['eval', 'settimeout', 'setinterval', 'function'])
                    is_location_sink = any(s in sink_lower_set for s in ['location', 'href', 'assign', 'replace'])
                    relevant_payloads = []

                    if self.payloads:
                        for p in self.payloads:
                            p_lower = p.lower()
                            if is_html_sink and ('<img' in p_lower or '<script' in p_lower or 'onerror' in p_lower):
                                if p not in relevant_payloads:
                                    relevant_payloads.append(p)
                            elif is_eval_sink and ('alert(' in p_lower or 'confirm(' in p_lower or 'prompt(' in p_lower) and '<' not in p_lower and '>' not in p_lower:
                                if p not in relevant_payloads:
                                    relevant_payloads.append(p)
                            elif is_location_sink and 'javascript:' in p_lower:
                                if p not in relevant_payloads:
                                    relevant_payloads.append(p)

                    if is_eval_sink and not any('alert(' in p.lower() for p in relevant_payloads):
                        relevant_payloads.append('alert(1)')
                    if is_html_sink and not any('<img' in p.lower() for p in relevant_payloads):
                        relevant_payloads.append('<img src=x onerror=alert(1)>')
                    if is_location_sink and not any('javascript:' in p.lower() for p in relevant_payloads):
                        relevant_payloads.append('javascript:alert(1)')
                        
                    relevant_payloads = relevant_payloads[:2]

                    if not relevant_payloads and self.payloads:
                        relevant_payloads = self.payloads[:2]
                    
                    logger.debug(f"Testing {len(relevant_payloads)} payloads for {self.url} in locations: {inject_locations}")

                    # Test each payload only in relevant injection locations
                    for payload in relevant_payloads:
                        for loc in inject_locations:
                            await self._test_url_with_payload(page, self.url, payload, loc)
                    
                    # Also test the original __DOMINATOR_TEST__ for compatibility (optional) - only if hash is relevant
                    if 'hash' in inject_locations:
                        test_url = self.url + '#__DOMINATOR_TEST__'
                        await page.goto(test_url, wait_until='networkidle')
                        await self._click_buttons_and_check(page)
                
                # Case 2: Offline HTML content
                else:
                    logger.debug("Executing HTML in a real browser environment (offline)...")
                    await page.set_content(self.html_content)
                    await self._click_buttons_and_check(page)
                    # For offline content, we can also try to inject payloads into the DOM via evaluate
                    for payload in self.payloads:
                        try:
                            dialog_msg = None
                            async def on_dialog(dialog):
                                nonlocal dialog_msg
                                dialog_msg = dialog.message
                                await dialog.dismiss()
                            page.once('dialog', on_dialog)

                            await page.evaluate("(payload) => { document.body.innerHTML += payload; }", payload)
                            await page.wait_for_timeout(500)

                            if dialog_msg:
                                occurrence: Occurrence = {
                                "line": None,
                                "column": None,
                                "pattern": "DOM XSS via innerHTML injection (offline)",
                                "context": f"Payload: {payload} triggered alert: {dialog_msg}",
                                "risk_level": "high",
                                "priority": 90,
                                "source": "dynamic"
                                }
                                self.result.add_dynamic_occurrence(occurrence)
                        except Exception:
                            pass

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
