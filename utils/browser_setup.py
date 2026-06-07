"""
Browser setup and auto-installation utilities for Playwright.
Suppresses noisy output during installation attempts and provides clean error messages.
"""

from pathlib import Path
from sys import executable
from typing import Optional
from asyncio import create_subprocess_exec
from asyncio.subprocess import DEVNULL, PIPE
from playwright.async_api import async_playwright
from utils.logger import get_logger

logger = get_logger(__name__)
_EXECUTABLE_PATH_CACHE: Optional[str] = None

class BrowserNotInstalledError(Exception):
    """Raised when the browser executable is missing and cannot be installed."""
    pass


async def _get_executable_path() -> Optional[str]:
    """
    Get the expected path to the Chromium executable.
    Returns None if the path cannot be determined.
    """
    global _EXECUTABLE_PATH_CACHE
    if _EXECUTABLE_PATH_CACHE is not None:
        return _EXECUTABLE_PATH_CACHE
    try:
        async with async_playwright() as p:
            _EXECUTABLE_PATH_CACHE = p.chromium.executable_path
            return _EXECUTABLE_PATH_CACHE
    except Exception:
        return None


async def ensure_browser_installed() -> bool:
    """
    Ensure that a Chromium browser is installed for Playwright.
    If not found, attempt silent automatic installation; if that fails,
    provide a clean error message and raise BrowserNotInstalledError.
    """
    executable_path = await _get_executable_path()
    if not executable_path:
        raise BrowserNotInstalledError("Could not determine Playwright browser path.")

    # If the executable already exists, nothing to do
    if Path(executable_path).is_file():
        return True

    logger.info("Chromium browser not found. Attempting automatic installation...")

    try:
        # Run installation asynchronously to avoid blocking the event loop
        proc = await create_subprocess_exec(
            executable, "-m", "playwright", "install", "chromium",
            stdout=DEVNULL,
            stderr=PIPE
        )
        _, stderr_bytes = await proc.communicate()
        if proc.returncode != 0:
            error_detail = stderr_bytes.decode().strip() if stderr_bytes else "No additional details"
            logger.error(
                "Automatic browser installation failed. "
                "This may be due to network restrictions (e.g., internet censorship). "
                "Please run 'playwright install chromium' manually in a terminal with unrestricted internet access. "
                f"Details: {error_detail}"
            )
            raise BrowserNotInstalledError(
                "Automatic installation failed. "
                "Please run 'playwright install chromium' manually."
            )
    except Exception as e:
        logger.error(f"Unexpected error during browser installation: {str(e)}")
        raise BrowserNotInstalledError(
            "Installation failed due to unexpected error. "
            "Please run 'playwright install chromium' manually."
        )

    # Verify again after installation attempt
    if Path(executable_path).is_file():
        logger.info("Chromium installed successfully.")
        return True
    else:
        logger.error("Installation command completed but browser still not found.")
        raise BrowserNotInstalledError(
            "Installation did not produce the expected browser executable. "
            "Please run 'playwright install chromium' manually."
        )
