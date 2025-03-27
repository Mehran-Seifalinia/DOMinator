from sys import argv
from asyncio import Lock, gather, run
from logging import getLogger, basicConfig, INFO
from pathlib import Path
from hashlib import sha256
from re import findall
from aiohttp import ClientSession
from aiosqlite import connect, Connection
from typing import List, Optional, Union, Dict

DB_PATH = "scripts.db"

# Set up logging
logger = getLogger(__name__)
basicConfig(level=INFO)

async def init_db() -> bool:
    """Initializes the SQLite database for caching scripts asynchronously."""
    try:
        async with connect(DB_PATH) as conn:
            # Enable WAL mode for better concurrent read/write performance
            await conn.execute("PRAGMA journal_mode=WAL;")
            await conn.execute(""" 
            CREATE TABLE IF NOT EXISTS scripts (
                url TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL,
                content TEXT NOT NULL
            )""")
            await conn.commit()
        logger.info("Database initialized successfully.")
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        return False

class ExternalFetcher:
    def __init__(self, urls: List[str], db_conn: Optional[Connection] = None, proxy: Optional[str] = None, timeout: int = 10):
        """
        Initializes the ExternalFetcher class with a list of URLs, an optional database connection,
        an optional proxy URL, and a timeout setting for requests.
        """
        self.urls: List[str] = urls
        self.db_conn: Optional[Connection] = db_conn
        self.proxy: Optional[str] = proxy
        self.timeout: int = timeout
        self._db_lock: Lock = Lock()  # Ensures only one connection attempt at a time

    async def _connect_db(self) -> bool:
        """Connects to the SQLite database if not already connected."""
        if self.db_conn is None:
            async with self._db_lock:  # Ensures only one connection attempt at a time
                if self.db_conn is None:  # Double-check to avoid redundant connection attempts
                    try:
                        self.db_conn = await connect(DB_PATH)
                        # Enable WAL mode for better performance
                        await self.db_conn.execute("PRAGMA journal_mode=WAL;")
                        logger.info("Database connected")
                    except Exception as e:
                        logger.error(f"Error connecting to the database: {e}")
                        return False
        return True

    async def close_db(self) -> bool:
        """Closes the database connection if it is open."""
        if not self.db_conn:
            logger.warning("Database connection is already closed.")
            return False
        
        try:
            await self.db_conn.close()
            self.db_conn = None  # Reset db_conn after closing
            logger.info("Database connection closed")
            return True
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")
            return False

    async def get_cached_script(self, url: str) -> Optional[str]:
        """Retrieves a cached script from the database if it exists."""
        await self._connect_db()
        try:
            async with self.db_conn.cursor() as cursor:
                await cursor.execute("SELECT content FROM scripts WHERE url = ?", (url,))
                result = await cursor.fetchone()
            return result[0] if result else None
        except Exception as e:
            logger.error(f"Error fetching cached script for URL {url}: {e}")
            return None

    async def cache_script(self, url: str, content: str) -> None:
        """Caches a script into the database if the content has changed."""
        content_hash: str = sha256(content.encode()).hexdigest()
        await self._connect_db()
        try:
            async with self.db_conn.cursor() as cursor:
                await cursor.execute("SELECT content_hash FROM scripts WHERE url = ?", (url,))
                existing_hash = await cursor.fetchone()
                if existing_hash and existing_hash[0] == content_hash:
                    logger.info(f"No changes in script for {url}, skipping cache update.")
                    return  # Skip if content hasn't changed
                await cursor.execute(""" 
                INSERT OR REPLACE INTO scripts (url, content_hash, content)
                VALUES (?, ?, ?)""", (url, content_hash, content))
                await self.db_conn.commit()
                logger.info(f"Script cached for {url}")
        except Exception as e:
            logger.error(f"Error caching script for URL {url}: {e}")

    async def fetch_script(self, session: ClientSession, url: str) -> Optional[str]:
        """Fetches script content from a given URL."""
        try:
            async with session.get(url, timeout=self.timeout, proxy=self.proxy) as response:
                if response.status == 200:
                    return await response.text()
                logger.error(f"Failed to fetch {url}: HTTP {response.status}")
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
        return None

    async def process_script(self, content: str, url: str) -> Optional[Dict[str, Union[str, List[str]]]]]:
        """Processes the JavaScript content to extract event listeners and potential security risks."""
        try:
            logger.info(f"Processing script from {url}")

            # Skip minified scripts
            if ".min.js" in url:
                logger.warning(f"Skipping minified script: {url}")
                return None

            # Extract event listeners (e.g., `element.addEventListener("click", function() {...})`)
            event_listeners: List[str] = findall(r'\.addEventListener\(["\'](\w+)["\']', content)

            # Check for risky functions such as eval(), setTimeout(), setInterval(), document.write()
            risky_functions: List[str] = findall(r'\b(eval|setTimeout|setInterval|document\.write)\b', content)

            # Store the results
            script_analysis: Dict[str, Union[str, List[str]]] = {
                "url": url,
                "event_listeners": list(set(event_listeners)),
                "risky_functions": list(set(risky_functions))
            }

            logger.info(f"Analysis result: {script_analysis}")
            return script_analysis

        except Exception as e:
            logger.error(f"Error processing script from {url}: {e}")
            return None

    async def fetch_and_process_scripts(self) -> None:
        """Fetches and processes scripts, caching the results."""
        try:
            if not self.db_conn:
                await init_db()  # Initialize DB if necessary
            async with ClientSession() as session:
                # Fetch cached scripts first
                cached_scripts: List[Optional[str]] = await gather(*[self.get_cached_script(url) for url in self.urls])

                tasks: List[Union[Optional[str], None]] = []
                for url, cached_script in zip(self.urls, cached_scripts):
                    if cached_script:
                        logger.info(f"Using cached script for {url}")
                        await self.process_script(cached_script, url)
                    else:
                        tasks.append(self.fetch_script(session, url))

                # Improved error handling in gathering
                scripts: List[Union[None, Optional[str], Exception]] = await gather(*tasks, return_exceptions=True)
                for url, script_content in zip(self.urls, scripts):
                    if isinstance(script_content, Exception):
                        # Log the specific exception with the URL that caused it
                        logger.error(f"Error fetching {url}: {script_content}")
                    elif script_content:
                        await self.cache_script(url, script_content)
                        await self.process_script(script_content, url)

        except Exception as e:
            logger.error(f"Error in fetch_and_process_scripts: {e}")
        finally:
            await self.close_db()  # Ensure the DB connection is closed even on error

if __name__ == "__main__":
    urls: List[str] = argv[1:] if len(argv) > 1 else [
        "https://example.com/script1.js",
        "https://example.com/script2.js"
    ]
    proxy: Optional[str] = None  # Optional proxy URL
    timeout: int = 10  # Default timeout in seconds
    fetcher = ExternalFetcher(urls, proxy=proxy, timeout=timeout)

    async def main() -> None:
        try:
            await fetcher.fetch_and_process_scripts()
        finally:
            await fetcher.close_db()

    run(main())
