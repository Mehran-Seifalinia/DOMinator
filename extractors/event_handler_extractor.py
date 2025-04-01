import asyncio
from urllib.parse import urlparse
from typing import List, Dict, Union, Optional, Any
from dataclasses import dataclass
from aiohttp import ClientSession, TCPConnector, ClientTimeout
from tenacity import retry, stop_after_attempt, wait_exponential
from extractors.html_parser import ScriptExtractor
from utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class ExtractionResult:
    """Dataclass for standardized extraction results"""
    status: str  # "success" or "error"
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    message: Optional[str] = None

class EventHandlerExtractorError(Exception):
    """Base exception class for EventHandlerExtractor errors"""
    pass

class EventHandlerExtractor:
    def __init__(self, html: str, proxy: Optional[str] = None, user_agent: Optional[str] = None):
        if not html or not isinstance(html, str):
            error_msg = "HTML content must be a non-empty string"
            logger.error(error_msg)
            raise EventHandlerExtractorError(error_msg)
            
        try:
            self.extractor = ScriptExtractor(html, proxy=proxy, user_agent=user_agent)
            logger.info("Successfully initialized ScriptExtractor.")
        except ValueError as e:
            logger.error(f"Invalid HTML content: {e}")
            raise EventHandlerExtractorError(f"Invalid HTML content: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error during initialization: {e}")
            raise EventHandlerExtractorError(f"Initialization failed: {e}") from e

    def extract_event_handlers(self) -> ExtractionResult:
        try:
            event_handlers = self.extractor.extract_event_handlers()
            if not event_handlers:
                logger.info("No event handlers found.")
                return ExtractionResult(
                    status="success",
                    data={},
                    message="No event handlers found"
                )
            logger.info(f"Successfully extracted {len(event_handlers)} event handlers")
            return ExtractionResult(
                status="success",
                data=event_handlers
            )
        except Exception as e:
            logger.error(f"Error extracting event handlers: {e}")
            return ExtractionResult(
                status="error",
                error=str(e),
                message="Extraction failed"
            )

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    reraise=True
)
async def fetch_html(
    session: ClientSession, 
    url: str, 
    timeout: int = 10,
    max_size: int = 10_000_000,
    proxy: Optional[str] = None, 
    user_agent: Optional[str] = None
) -> ExtractionResult:
    try:
        headers = {'User-Agent': user_agent} if user_agent else {}
        timeout_settings = ClientTimeout(total=timeout)
        
        async with session.get(
            url, 
            timeout=timeout_settings, 
            headers=headers,
            proxy=proxy,
            read_bufsize=max_size
        ) as response:
            response.raise_for_status()
            html = await response.text()
            
            if not html.strip():
                logger.error(f"Empty HTML response from {url}")
                return ExtractionResult(
                    status="error",
                    error="empty_response",
                    message=f"Empty HTML response from {url}"
                )
                
            logger.info(f"Successfully fetched HTML from {url}")
            return ExtractionResult(
                status="success",
                data={"html": html}
            )
            
    except Exception as e:
        logger.error(f"Failed to fetch HTML from {url}: {e}")
        return ExtractionResult(
            status="error",
            error=str(e),
            message=f"Failed to fetch HTML from {url}"
        )

def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except ValueError:
        return False

async def extract(
    session: ClientSession, 
    url: str, 
    timeout: int = 10,
    max_size: int = 10_000_000,
    proxy: Optional[str] = None, 
    user_agent: Optional[str] = None
) -> ExtractionResult:
    if not is_valid_url(url):
        logger.error(f"Invalid URL: {url}")
        return ExtractionResult(
            status="error",
            error="invalid_url",
            message=f"Invalid URL: {url}"
        )
    
    html_response = await fetch_html(session, url, timeout, max_size, proxy, user_agent)
    if html_response.status != "success":
        return html_response
        
    try:
        extractor = EventHandlerExtractor(html_response.data["html"], proxy, user_agent)
        return extractor.extract_event_handlers()
    except Exception as e:
        logger.error(f"Error during extraction from {url}: {e}")
        return ExtractionResult(
            status="error",
            error=str(e),
            message=f"Extraction failed for {url}"
        )

async def run_extraction(
    urls: List[str], 
    timeout: int = 10,
    max_size: int = 10_000_000,
    proxy: Optional[str] = None, 
    user_agent: Optional[str] = None,
    max_concurrent: int = 10
) -> List[ExtractionResult]:
    connector = TCPConnector(
        ssl=True,
        limit_per_host=max_concurrent,
        keepalive_timeout=30
    )
    
    async with ClientSession(connector=connector) as session:
        tasks = [
            extract(session, url, timeout, max_size, proxy, user_agent) 
            for url in urls
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                processed_results.append(ExtractionResult(
                    status="error",
                    error=str(result),
                    message="Unexpected error occurred"
                ))
            else:
                processed_results.append(result)
                
        return processed_results

async def async_main(
    urls: List[str], 
    timeout: int = 10,
    max_size: int = 10_000_000,
    proxy: Optional[str] = None, 
    user_agent: Optional[str] = None,
    max_concurrent: int = 10
) -> List[ExtractionResult]:
    return await run_extraction(
        urls, 
        timeout, 
        max_size, 
        proxy, 
        user_agent, 
        max_concurrent
    )

def main(
    urls: List[str], 
    timeout: int = 10,
    max_size: int = 10_000_000,
    proxy: Optional[str] = None, 
    user_agent: Optional[str] = None,
    max_concurrent: int = 10
) -> List[ExtractionResult]:
    return asyncio.run(async_main(
        urls, 
        timeout, 
        max_size, 
        proxy, 
        user_agent, 
        max_concurrent
    ))

if __name__ == "__main__":
    test_urls = [
        "https://example.com", 
        "https://example.org",
        "invalid-url"
    ]
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    
    results = main(
        test_urls, 
        timeout=15, 
        user_agent=user_agent,
        max_concurrent=5
    )
    
    for url, result in zip(test_urls, results):
        print(f"\nURL: {url}")
        print(f"Status: {result.status}")
        if result.status == "success":
            print(f"Data: {result.data}")
        else:
            print(f"Error: {result.error}")
            print(f"Message: {result.message}")
