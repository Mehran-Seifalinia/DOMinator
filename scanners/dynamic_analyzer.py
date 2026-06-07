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
from urllib.parse import quote, urlparse, urlunparse, parse_qs, urlencode
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
            level (int): Analysis level (1-3)
            proxy (Optional[str]): Proxy URL for browser
            cookies (Optional[str]): Cookies string to set
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

                # Build exploit URL if we have a payload and a current URL
                exploit_url = None
                if payload and self.url and (self.url.startswith('http://') or self.url.startswith('https://')):
                    current_url = page.url
                    parsed = urlparse(current_url)
                    
                    param_name = None
                    if 'param name:' in source:
                        try:
                            param_name = source.split('param name:')[1].split(',')[0].strip()
                        except:
                            pass
                    
                    # Priority 1: window.name
                    if 'window.name' in source:
                        base = current_url.split('?')[0].split('#')[0]
                        # Build a data: URI that sets window.name and redirects
                        # Properly escape the payload for JavaScript string
                        safe_payload = payload.replace("'", "\\'").replace('"', '\\"')
                        data_html = f"<script>window.name='{safe_payload}';location.href='{base}';</script>"
                        encoded_data = quote(data_html, safe='')
                        exploit_url = f"data:text/html,{encoded_data}"
                   
                    # Priority 2: location.hash
                    elif 'location.hash' in source:
                        # No encoding for hash fragment
                        if '#' in current_url and '__DOMINATOR_TEST__' in current_url.split('#')[-1]:
                            new_fragment = current_url.split('#')[-1].replace('__DOMINATOR_TEST__', payload)
                            exploit_url = current_url.split('#')[0] + '#' + new_fragment
                        else:
                            exploit_url = current_url.split('#')[0] + '#' + payload
                    
                    # Priority 3: location.search
                    elif 'location.search' in source:
                        # Check if we have a real parameter name (not our test marker)
                        if param_name and param_name != '__dominator_test__':
                            # Parameter-based injection
                            query_parts = [f"{param_name}={payload}"]
                            clean_params = parse_qs(parsed.query, keep_blank_values=True)
                            if '__dominator_test__' in clean_params:
                                del clean_params['__dominator_test__']
                            if param_name in clean_params:
                                del clean_params[param_name]
                            for k, v in clean_params.items():
                                val = v[0] if isinstance(v, list) else v
                                query_parts.append(f"{k}={val}")
                            new_query = '&'.join(query_parts)
                            exploit_url = urlunparse(parsed._replace(query=new_query))
                        else:
                            # Raw query string injection (no parameter name)
                            exploit_url = urlunparse(parsed._replace(query=payload))

                    # Fallback for any other source that didn't get an exploit_url
                    if not exploit_url and payload:
                        parsed = urlparse(current_url)
                        exploit_url = urlunparse(parsed._replace(query=payload))

                occurrence: Occurrence = {
                    "line": None,
                    "column": None,
                    "pattern": f"{sink} (source: {source})",
                    "context": f"[{sink}] {context}",
                    "risk_level": "high",  # dynamic confirmed -> high risk
                    "priority": self.priority_manager.get_priority_from_risk_level("high"),
                    "source": "dynamic",
                    "injected_url": exploit_url
                }
                # Verification with real payload
                confirmed = False
                if payload and self.url and (self.url.startswith('http://') or self.url.startswith('https://')):
                    # Choose appropriate real payload
                    real_payload = '<img src=x onerror=alert(1)>'
                    if 'eval' in sink or 'setTimeout' in sink or 'setInterval' in sink or 'Function' in sink:
                        real_payload = 'alert(1)'
                    
                    # Build verification URL using same logic as above
                    verify_url = None
                    if exploit_url:
                        # Replace the suggested payload with real payload in the URL
                        if '__DOMINATOR_TEST__' in exploit_url:
                            verify_url = exploit_url.replace('__DOMINATOR_TEST__', real_payload)
                        else:
                            # Try to inject real payload into the parameter position
                            parsed = urlparse(current_url)
                            if param_name:
                                # Remove existing param_name from query to avoid duplication
                                clean_params = parse_qs(parsed.query, keep_blank_values=True)
                                if param_name in clean_params:
                                    del clean_params[param_name]
                                if '__dominator_test__' in clean_params:
                                    del clean_params['__dominator_test__']
                                # Rebuild query with new param first, then others
                                query_parts = [f"{param_name}={real_payload}"]
                                for k, v in clean_params.items():
                                    val = v[0] if isinstance(v, list) else v
                                    query_parts.append(f"{k}={val}")
                                new_query = '&'.join(query_parts)
                                verify_url = urlunparse(parsed._replace(query=new_query))
                            else:
                                verify_url = urlunparse(parsed._replace(query=f"__dominator_test__={real_payload}"))
                    
                    if verify_url:
                        try:
                            # Navigate to verification URL and wait for dialog
                            await page.goto(verify_url, wait_until='networkidle')
                            await page.wait_for_timeout(500)
                            dialog = await page.wait_for_event('dialog', timeout=3000)
                            await dialog.dismiss()
                            confirmed = True
                            # Update occurrence to critical
                            occurrence['risk_level'] = 'critical'
                            occurrence['priority'] = 90.0
                            occurrence['context'] += f' | CONFIRMED with payload: {real_payload}'
                            # Also update exploit_url to the verification URL
                            exploit_url = verify_url
                        except:
                            # No alert, still keep as potential
                            occurrence['context'] += ' | NOT confirmed (no alert)'
                            pass
                
                if payload:
                    occurrence['context'] += f' | SUGGESTED PAYLOAD: {payload}'
                if exploit_url and not confirmed:
                    occurrence['injected_url'] = exploit_url
                self.result.add_dynamic_occurrence(occurrence)
                
        except Exception as e:
            logger.error(f"Error during instrumentation collection: {str(e)}")
    
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
                    async with page.expect_event('dialog', timeout=self.timeout * 1000) as dialog_info:
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

    async def _extract_param_names(self, page: Page) -> List[str]:
        """Extract parameter names from page scripts."""
        try:
            param_names = await page.evaluate('''
                () => {
                    const paramNames = new Set();
                    const scripts = document.querySelectorAll('script');
                    scripts.forEach(script => {
                        const content = script.textContent || script.innerText;
                        if (content) {
                            regex = /\\b(?:URLSearchParams\\.get|params\\.get|new URLSearchParams\\([^)]*\\)\\.get|location\\.search\\s*\\.split\\(['"]\\?['"]\\)\\s*\\[1\\])\\s*\\(\\s*['"]([^'"]+)['"]\\s*\\)/gi
                            let match;
                            while ((match = regex.exec(content)) !== null) {
                                paramNames.add(match[1]);
                            }
                            const paramRegex = /[?&]([^=&#]+)=/g;
                            let paramMatch;
                            while ((paramMatch = paramRegex.exec(content)) !== null) {
                                paramNames.add(paramMatch[1]);
                            }
                        }
                    });
                    return Array.from(paramNames);
                }
            ''')
            return param_names
        except Exception as e:
            logger.debug(f"Error extracting param names: {e}")
            return []

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
        p = None
        try:
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

                # Case 1: We have a real URL
                if self.url and (self.url.startswith('http://') or self.url.startswith('https://')):
                    # First load clean page
                    await page.goto(self.url, wait_until='networkidle')
                    await self._click_buttons_and_check(page)
                    
                    # ========== Extract actual parameter names from page scripts ==========
                    # Extract all parameter names used with URLSearchParams.get() or similar
                    param_names = await self._extract_param_names(page)
                    logger.debug(f"Extracted parameter names from page scripts: {param_names}")
                    
                    # Determine which sources are present based on dom_sources (existing logic)
                    inject_hash = any('hash' in src.lower() for src in self.dom_sources)
                    inject_search = any('search' in src.lower() or 'query' in src.lower() for src in self.dom_sources)
                    
                    if not inject_hash and not inject_search:
                        inject_hash = True
                        inject_search = True
                    
                    marker = '__DOMINATOR_TEST__'
                    
                    # Test injection via URL hash
                    if inject_hash:
                        test_url_hash = self.url + '#' + marker
                        await page.goto(test_url_hash, wait_until='networkidle')
                        await page.reload()  # Ensure page scripts re-run
                        await page.wait_for_timeout(500)

                    # Test injection via URL query parameters - ONLY those extracted
                    if inject_search and param_names:
                        parsed = urlparse(self.url)
                        existing_params = parse_qs(parsed.query)
                        new_params = {}
                        for key in existing_params:
                            new_params[key] = marker
                        for pname in param_names:
                            new_params[pname] = marker
                        new_params['__dominator_test__'] = marker
                        new_query = urlencode(new_params, doseq=True)
                        new_parsed = parsed._replace(query=new_query)
                        test_url_query = urlunparse(new_parsed)
                        await page.goto(test_url_query, wait_until='networkidle')
                        await page.reload()
                        await page.wait_for_timeout(500)
                    elif inject_search and not param_names:
                        parsed = urlparse(self.url)
                        new_query = marker
                        new_parsed = parsed._replace(query=new_query)
                        test_url_query = urlunparse(new_parsed)
                        await page.goto(test_url_query, wait_until='networkidle')
                        await page.reload()
                        await page.wait_for_timeout(500)
                    
                    # Test window.name if relevant
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
