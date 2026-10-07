"""Console-safe output symbols for the terminal report.

Windows consoles default to a legacy code page such as cp1252 and cannot render
emoji, so every symbol in the report came out as a question mark. Terminal
output therefore uses plain ASCII tags. Reports written to files keep whatever
Unicode text the scanned page produced.
"""

from typing import Dict

SYMBOLS: Dict[str, str] = {
    "start": "[*]",
    "pages": "[-]",
    "analyze": "[>]",
    "found": "[!]",
    "finding": "[!]",
    "clean": "[ok]",
    "error": "[x]",
}

SEVERITY_TAGS: Dict[str, str] = {
    "Critical": "[CRITICAL]",
    "High": "[HIGH]",
    "Medium": "[MEDIUM]",
    "Low": "[LOW]",
    "Informative": "[INFO]",
}

UNKNOWN_SEVERITY_TAG = "[UNKNOWN]"


def severity_tag(severity: str) -> str:
    """Return the ASCII tag for a severity label."""
    return SEVERITY_TAGS.get(severity, UNKNOWN_SEVERITY_TAG)
