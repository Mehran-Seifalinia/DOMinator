import asyncio
from typing import List, Dict
from playwright.async_api import async_playwright
from extractors.event_handler_extractor import EventHandlerExtractor
from extractors.external_fetcher import ExternalFetcher
from scanners.priority_manager import PriorityManager
from utils.logger import get_logger

# Get the logger instance from logger.py
logger = get_logger()

class DynamicAnalyzer:
    def __init__(self, html_content: str, external_urls: List[str]):
        self.html_content = html_content
        self.external_urls = external_urls
        self.priority_manager = PriorityManager()

    async def analyze_event_handlers(self) -> Dict[str, List[str]]:
        """Extract and analyze event handlers from HTML"""
        try:
            extractor = EventHandlerExtractor(self.html_content)
            event_handlers = extractor.extract_event_handlers()
            logger.info(f"Extracted event handlers: {event_handlers}")
            self.priority_manager.process_results({"event_handlers": event_handlers})
            return event_handlers
        except Exception as e:
            logger.error(f"Error analyzing event handlers: {e}")
            return {}

    async def fetch_and_analyze_external_scripts(self) -> None:
        """Fetch and analyze external JavaScript files"""
        try:
            fetcher = ExternalFetcher(self.external_urls)
            await fetcher.fetch_and_process_scripts()
        except Exception as e:
            logger.error(f"Error fetching or processing external scripts: {e}")

    async def execute_in_browser(self) -> Dict[str, List[str]]:
        """Execute HTML in a real browser to detect dynamic vulnerabilities"""
        results = {}

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                async with browser.new_context() as context:
                    async with context.new_page() as page:
                        logger.info("Executing HTML in a real browser environment...")
                        await page.set_content(self.html_content)
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
                        self.priority_manager.process_results({"dom_results": dom_changes})
        except Exception as e:
            logger.error(f"Error during dynamic analysis in browser: {e}")

        logger.info(f"Dynamic analysis results: {results}")
        return results

    async def run_analysis(self) -> None:
        """Run the full dynamic analysis process"""
        logger.info("Starting dynamic analysis...")

        try:
            # Running tasks in parallel
            event_handlers_task = self.analyze_event_handlers()
            external_scripts_task = self.fetch_and_analyze_external_scripts()
            dom_results_task = self.execute_in_browser()

            event_handlers, _, dom_results = await asyncio.gather(
                event_handlers_task, external_scripts_task, dom_results_task
            )

            logger.info(f"Dynamic analysis results: {event_handlers}, {dom_results}")
        except Exception as e:
            logger.error(f"Error during full analysis: {e}")

if __name__ == "__main__":
    html_content = "<html><body><div onclick='alert(\"Hello\");'></div></body></html>"
    external_urls = ["https://example.com/script1.js", "https://example.com/script2.js"]
    
    analyzer = DynamicAnalyzer(html_content, external_urls)
    asyncio.run(analyzer.run_analysis())
