from subprocess import CalledProcessError, check_call
from sys import executable, exit

from playwright.async_api import async_playwright


async def ensure_browser_installed():
    try:
        async with async_playwright() as playwright_instance:
            playwright_instance.chromium.executable_path
            return True

    except Exception as error:
        error_message = str(error)

        if (
            "Executable doesn't exist" in error_message
            or "Please run" in error_message
        ):
            print("[INFO] Chromium browser not found. Installing automatically...")

            try:
                check_call(
                    [executable, "-m", "playwright", "install", "chromium"]
                )

                print("[INFO] Chromium installed successfully.")
                return True

            except CalledProcessError:
                print(
                    "[ERROR] Failed to install Chromium. "
                    "Please run 'playwright install chromium' manually."
                )
                exit(1)

        raise
