import asyncio
import aiosqlite
from hashlib import sha256
from aiohttp import ClientSession
from pathlib import Path
import logging
from typing import List, Optional
from re import findall

DB_PATH = "scripts.db"

# Set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

async def init_db():
    """Initializes the SQLite database for caching scripts asynchronously."""
    try:
        if not Path(DB_PATH).exists():
            async with aiosqlite.connect(DB_PATH) as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scripts (
                        url TEXT PRIMARY KEY,
                        content_hash TEXT NOT NULL,
                        content TEXT NOT NULL
                    )""")
                    await conn.commit()
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

class ExternalFetcher:
    def __init__(self, urls: List[str], db_conn: Optional[aiosqlite.Connection] = None):
        """
        Initializes the ExternalFetcher class with a list of URLs and an optional database connection.

        :param urls: List of URLs to be fetched.
        :param db_conn: Optional database connection. If None, the connection will be established later.
        """
        self.urls = urls
        self.db_conn = db_conn
        self._db_lock = asyncio.Lock()  # Lock to prevent concurrent DB connections

    async def _connect_db(self):
        """Connects to the SQLite database if not already connected."""
        if self.db_conn is None:
            async with self._db_lock:  # Ensures only one connection attempt at a time
                if self.db_conn is None:  # Double-check to avoid redundant connection attempts
                    try:
                        self.db_conn = await aiosqlite.connect(DB_PATH)
                    except Exception as e:
                        logger.error(f"Error connecting to the database: {e}")

    async def close_db(self):
        """Closes the database connection if it is open."""
        try:
            if self.db_conn:
                await self.db_conn.close()
                self.db_conn = None  # Reset db_conn after closing
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")

    async def get_cached_script(self, url: str) -> str:
        """Retrieves a cached script from the database if it exists."""
        await self._connect_db()
        try:
            async with self.db_conn.cursor() as cursor:
                await cursor.execute("SELECT content FROM scripts WHERE url = ?", (url,))
                result = await cursor.fetchone()
            return result[0] if result else ""  # Return the content or empty string if not found
        except Exception as e:
            logger.error(f"Error fetching cached script for URL {url}: {e}")
            return ""  # Return empty string in case of error

    async def cache_script(self, url: str, content: str) -> None:
        """Caches a script into the database if the content has changed."""
        content_hash = sha256(content.encode()).hexdigest()
        await self._connect_db()
        try:
            async with self.db_conn.cursor() as cursor:
                await cursor.execute("SELECT content_hash FROM scripts WHERE url = ?", (url,))
                existing_hash = await cursor.fetchone()
                if existing_hash and existing_hash[0] == content_hash:
                    return  # Skip if content hasn't changed
                await cursor.execute("""
                INSERT OR REPLACE INTO scripts (url, content_hash, content)
                VALUES (?, ?, ?)""", (url, content_hash, content))
                await self.db_conn.commit()
        except Exception as e:
            logger.error(f"Error caching script for URL {url}: {e}")

    async def fetch_script(self, session: ClientSession, url: str) -> str:
        """Fetches script content from a given URL."""
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.text()
                logger.error(f"Failed to fetch {url}: HTTP {response.status}")
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
        return ""  # Return empty string if fetching fails

    async def process_script(self, content: str, url: str) -> None:
        """Processes the JavaScript content to extract event listeners and potential security risks."""
        try:
            logger.info(f"Processing script from {url}")

            # Extract event listeners (e.g., `element.addEventListener("click", function() {...})`)
            event_listeners = findall(r'\.addEventListener\(["\'](\w+)["\']', content)

            # Check for risky functions such as eval(), setTimeout(), setInterval(), document.write()
            risky_functions = findall(r'\b(eval|setTimeout|setInterval|document\.write)\b', content)

            # Store the results
            script_analysis = {
                "url": url,
                "event_listeners": list(set(event_listeners)),  # Remove duplicates
                "risky_functions": list(set(risky_functions))
            }

            logger.info(f"Analysis result: {script_analysis}")
            
            # Here we can store the results or send them to another module for further processing
            return script_analysis

        except Exception as e:
            logger.error(f"Error processing script from {url}: {e}")

    async def fetch_and_process_scripts(self) -> None:
        """Fetches and processes scripts, caching the results."""
        try:
            await init_db()  # Initialize DB if necessary
            async with ClientSession() as session:
                tasks = []
                for url in self.urls:
                    cached_script = await self.get_cached_script(url)
                    if cached_script:
                        logger.info(f"Using cached script for {url}")
                        await self.process_script(cached_script, url)
                    else:
                        tasks.append(self.fetch_script(session, url))

                scripts = await asyncio.gather(*tasks, return_exceptions=True)
                for url, script_content in zip(self.urls, scripts):
                    if isinstance(script_content, Exception):
                        logger.error(f"Error fetching {url}: {script_content}")
                    elif script_content:
                        await self.cache_script(url, script_content)
                        await self.process_script(script_content, url)
        except Exception as e:
            logger.error(f"Error in fetch_and_process_scripts: {e}")
        finally:
            await self.close_db()  # Ensure the DB connection is closed even on error

if __name__ == "__main__":
    urls = [
        "https://example.com/script1.js",
        "https://example.com/script2.js"
    ]
    fetcher = ExternalFetcher(urls)
    
    async def main():
        try:
            await fetcher.fetch_and_process_scripts()
        finally:
            await fetcher.close_db()  # Ensure DB connection is closed even on error
    
    asyncio.run(main())
