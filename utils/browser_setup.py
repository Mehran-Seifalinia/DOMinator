"""
Browser setup and auto-installation utilities for Playwright.
"""

from os import path
from subprocess import check_call, CalledProcessError
from sys import executable
from typing import Optional

from playwright.async_api import async_playwright


class BrowserNotInstalledError(Exception):
    """Raised when the browser executable is missing and cannot be installed."""
    pass


async def _get_executable_path() -> Optional[str]:
    """
    Get the expected path to the Chromium executable.
    Returns None if the path cannot be determined.
    """
    try:
        async with async_playwright() as p:
            # executable_path returns the expected path string
            return p.chromium.executable_path
    except Exception:
        return None


async def ensure_browser_installed() -> bool:
    """
    Ensure that a Chromium browser is installed for Playwright.
    If not found, try to install it automatically.
    
    Returns:
        bool: True if browser is now installed and ready, False otherwise.
        
    Raises:
        BrowserNotInstalledError: If installation is required but fails.
    """
    executable_path = await _get_executable_path()
    if not executable_path:
        raise BrowserNotInstalledError("Could not determine Playwright browser path.")

    # Check if the executable file actually exists
    if path.isfile(executable_path):
        return True

    # Attempt automatic installation
    print("[INFO] Chromium browser not found. Attempting automatic installation...")
    try:
        check_call(
            [executable, "-m", "playwright", "install", "chromium"]
        )
        # Verify again after installation
        if path.isfile(executable_path):
            print("[INFO] Chromium installed successfully.")
            return True
        else:
            raise BrowserNotInstalledError(
                "Installation completed but browser still not found. "
                "Please run 'playwright install chromium' manually."
            )
    except CalledProcessError:
        raise BrowserNotInstalledError(
            "Automatic installation failed. "
            "Please run 'playwright install chromium' manually."
        )
