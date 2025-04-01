import asyncio
from urllib.parse import urlparse
from typing import List, Dict, Union, Optional
from aiohttp import ClientSession, TCPConnector, ClientTimeout
from extractors.html_parser import ScriptExtractor
from utils.logger import get_logger

logger = get_logger(__name__)

class EventHandlerExtractorError(Exception):
    """Base exception class for EventHandlerExtractor errors"""
    pass

class EventHandlerExtractor:
    def __init__(self, html: str, proxy: Optional[str] = None, user_agent: Optional[str] = None):
        """
        Initialize the event handler extractor with HTML content.
        
        Args:
            html: The HTML content to extract event handlers from
            proxy: Optional proxy server to use
            user_agent: Optional user agent string to use
        """
        try:
            self.extractor = ScriptExtractor(html, proxy=proxy, user_agent=user_agent)
            logger.info("Successfully initialized ScriptExtractor.")
        except ValueError as e:
            logger.error(f"Invalid HTML content: {e}")
            raise EventHandlerExtractorError(f"Invalid HTML content: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error during initialization: {e}")
            raise EventHandlerExtractorError(f"Initialization failed: {e}") from e

    def extract_event_handlers(self) -> Dict[str, Union[str, Dict]]:
        """
        Extract event handlers from the HTML content.
        
        Returns:
            Dictionary containing either:
            - The extracted event handlers under 'data' key
            - Error information under 'error' key
        """
        try:
            event_handlers = self.extractor.extract_event_handlers()
            if not event_handlers:
                logger.info("No event handlers found.")
                return {"status": "success", "data": {}, "message": "No event handlers found"}
            
            logger.info(f"Successfully extracted {len(event_handlers)} event handlers")
            return {"status": "success", "data": event_handlers}
        except Exception as e:
            logger.error(f"Error extracting event handlers: {e}")
            return {"status": "error", "error": str(e), "message": "Extraction failed"}

async def fetch_html(
    session: ClientSession, 
    url: str, 
    timeout: int = 10,
    proxy: Optional[str] = None, 
    user_agent: Optional[str] = None
) -> Dict[str, Union[str, Dict]]:
    """
    Fetch HTML content from a given URL.
    
    Args:
        session: aiohttp ClientSession to use for the request
        url: URL to fetch
        timeout: Request timeout in seconds
        proxy: Optional proxy server to use
        user_agent: Optional user agent string
        
    Returns:
        Dictionary containing either:
        - The HTML content under 'data' key
        - Error information under 'error' key
    """
    try:
        headers = {'User-Agent': user_agent} if user_agent else {}
        timeout_settings = ClientTimeout(total=timeout)
        
        async with session.get(
            url, 
            timeout=timeout_settings, 
            headers=headers,
            proxy=proxy
        ) as response:
            response.raise_for_status()
            html = await response.text()
            
            if not html.strip():
                logger.error(f"Empty HTML response from {url}")
                return {
                    "status": "error",
                    "error": "empty_response",
                    "message": f"Empty HTML response from {url}"
                }
                
            logger.info(f"Successfully fetched HTML from {url}")
            return {"status": "success", "data": html}
            
    except Exception as e:
        logger.error(f"Failed to fetch HTML from {url}: {e}")
        return {
            "status": "error",
            "error": str(e),
            "message": f"Failed to fetch HTML from {url}"
        }

def is_valid_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except ValueError:
        return False

async def extract(
    session: ClientSession, 
    url: str, 
    timeout: int = 10,
    proxy: Optional[str] = None, 
    user_agent: Optional[str] = None
) -> Dict[str, Union[str, Dict]]:
    """
    Extract event handlers from a given URL.
    
    Args:
        session: aiohttp ClientSession to use
        url: URL to extract from
        timeout: Request timeout in seconds
        proxy: Optional proxy server to use
        user_agent: Optional user agent string
        
    Returns:
        Dictionary containing either:
        - The extracted event handlers under 'data' key
        - Error information under 'error' key
    """
    if not is_valid_url(url):
        logger.error(f"Invalid URL: {url}")
        return {
            "status": "error",
            "error": "invalid_url",
            "message": f"Invalid URL: {url}"
        }
    
    html_response = await fetch_html(session, url, timeout, proxy, user_agent)
    if html_response["status"] != "success":
        return html_response
        
    try:
        extractor = EventHandlerExtractor(html_response["data"], proxy, user_agent)
        return extractor.extract_event_handlers()
    except Exception as e:
        logger.error(f"Error during extraction from {url}: {e}")
        return {
            "status": "error",
            "error": str(e),
            "message": f"Extraction failed for {url}"
        }

async def run_extraction(
    urls: List[str], 
    timeout: int = 10,
    proxy: Optional[str] = None, 
    user_agent: Optional[str] = None
) -> List[Dict[str, Union[str, Dict]]]:
    """
    Run extraction for multiple URLs concurrently.
    
    Args:
        urls: List of URLs to process
        timeout: Request timeout in seconds
        proxy: Optional proxy server to use
        user_agent: Optional user agent string
        
    Returns:
        List of results for each URL
    """
    connector = TCPConnector(ssl=True, limit_per_host=10)
    
    async with ClientSession(connector=connector) as session:
        tasks = [extract(session, url, timeout, proxy, user_agent) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to error dictionaries
        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                processed_results.append({
                    "status": "error",
                    "error": str(result),
                    "message": "Unexpected error occurred"
                })
            else:
                processed_results.append(result)
                
        return processed_results

async def async_main(
    urls: List[str], 
    timeout: int = 10,
    proxy: Optional[str] = None, 
    user_agent: Optional[str] = None
) -> List[Dict[str, Union[str, Dict]]]:
    """Async entry point for the extraction process"""
    return await run_extraction(urls, timeout, proxy, user_agent)

def main(
    urls: List[str], 
    timeout: int = 10,
    proxy: Optional[str] = None, 
    user_agent: Optional[str] = None
) -> List[Dict[str, Union[str, Dict]]]:
    """
    Main entry point for the extraction process.
    
    Args:
        urls: List of URLs to process
        timeout: Request timeout in seconds (default: 10)
        proxy: Optional proxy server to use
        user_agent: Optional user agent string
        
    Returns:
        List of results for each URL
    """
    return asyncio.run(async_main(urls, timeout, proxy, user_agent))

if __name__ == "__main__":
    # Example usage
    test_urls = [
        "https://example.com", 
        "https://example.org",
        "invalid-url"
    ]
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    
    results = main(test_urls, timeout=15, user_agent=user_agent)
    for url, result in zip(test_urls, results):
        print(f"URL: {url}")
        print(f"Result: {result}\n")
