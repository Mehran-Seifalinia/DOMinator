from asyncio import run
from typing import List, Dict
from logging import getLogger, basicConfig, INFO
from playwright.async_api import async_playwright

from extractors.event_handler_extractor import EventHandlerExtractor
from extractors.external_fetcher import ExternalFetcher
from scanners.priority_manager import PriorityManager
from utils.caching import CacheManager

# Configure logging
basicConfig(level=INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = getLogger(__name__)

class DynamicAnalyzer:
    def __init__(self, html_content: str, external_urls: List[str]):
        self.html_content = html_content
        self.external_urls = external_urls
        self.priority_manager = PriorityManager()
        self.cache_manager = CacheManager()

    def analyze_event_handlers(self) -> Dict[str, List[str]]:
        """Extract and analyze event handlers from HTML"""
        extractor = EventHandlerExtractor(self.html_content)
        event_handlers = extractor.extract_event_handlers()
        logger.info(f"Extracted event handlers: {event_handlers}")
        return event_handlers

    async def fetch_and_analyze_external_scripts(self) -> None:
        """Fetch and analyze external JavaScript files"""
        fetcher = ExternalFetcher(self.external_urls)
        await fetcher.fetch_and_process_scripts()

    async def execute_in_browser(self) -> Dict[str, List[str]]:
        """Execute HTML in a real browser to detect dynamic vulnerabilities"""
        results = {}

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            async with browser.new_context() as context:
                async with context.new_page() as page:

                    logger.info("Executing HTML in a real browser environment...")
                    await page.set_content(self.html_content)

                    # Scan the DOM for suspicious changes
                    dom_changes = await page.evaluate("""
                        () => {
                            let xss_detected = [];
                            document.querySelectorAll('*').forEach(el => {
                                if (el.innerHTML.includes('<script>') || el.innerHTML.includes('javascript:')) {
                                    xss_detected.push(el.outerHTML);
                                }
                            });
                            return xss_detected;
                        }
                    """)

                    results["dom_changes"] = dom_changes
        
        logger.info(f"Dynamic analysis results: {results}")
        return results

    async def run_analysis(self) -> None:
        """Run the full dynamic analysis process"""
        logger.info("Starting dynamic analysis...")

        # Analyze event handlers
        event_handlers = self.analyze_event_handlers()
        self.priority_manager.process_results({"event_handlers": event_handlers})

        # Fetch and analyze external scripts
        await self.fetch_and_analyze_external_scripts()

        # Execute HTML in a real browser
        dom_results = await self.execute_in_browser()
        self.priority_manager.process_results({"dom_results": dom_results})

        # Store results in cache
        self.cache_manager.save_results("dynamic_analysis", {"event_handlers": event_handlers, "dom_results": dom_results})

if __name__ == "__main__":
    html_content = "<html><body><div onclick='alert(\"Hello\");'></div></body></html>"
    external_urls = ["https://example.com/script1.js", "https://example.com/script2.js"]
    
    analyzer = DynamicAnalyzer(html_content, external_urls)
    run(analyzer.run_analysis())
