"""Payloads used to confirm a finding, and how they are refreshed.

The confirmation step injects a payload that matches the sink it tests, so the
choice lives here instead of inside the analyzer. --auto-update replaces the
built in list with the list published at DOMINATOR_PAYLOAD_SOURCE, which keeps
the tool current without a code change.
"""

from json import dumps, loads
from os import environ
from pathlib import Path
from typing import Dict, Optional

from aiohttp import ClientSession
from utils.logger import get_logger

logger = get_logger(__name__)

SOURCE_ENV = "DOMINATOR_PAYLOAD_SOURCE"
TIMEOUT_SECONDS = 15

# Primary payload per sink: a successful injection opens an alert.
PRIMARY_PAYLOADS: Dict[str, str] = {
    "eval": "alert(1)",
    "function": "alert(1)",
    "settimeout": "alert(1)",
    "setinterval": "alert(1)",
    "documentwrite": "alert(1)",
    "innerhtml": "<img src=x onerror=alert(1)>",
    "outerhtml": "<img src=x onerror=alert(1)>",
    "insertadjacenthtml": "<img src=x onerror=alert(1)>",
    "srcdoc": "<img src=x onerror=alert(1)>",
    "locationhref": "javascript:alert(1)",
}

# Second variant, tried at analysis level 4 when the primary did not fire.
FALLBACK_PAYLOADS: Dict[str, str] = {
    "eval": "alert(document.domain)",
    "function": "alert(document.domain)",
    "settimeout": "alert(document.domain)",
    "setinterval": "alert(document.domain)",
    "documentwrite": "<svg onload=alert(1)>",
    "innerhtml": "<svg onload=alert(1)>",
    "outerhtml": "<svg onload=alert(1)>",
    "insertadjacenthtml": "<svg onload=alert(1)>",
    "srcdoc": "<svg onload=alert(1)>",
    "locationhref": "javascript:alert(document.domain)",
}

DEFAULT_PAYLOAD = "<img src=x onerror=alert(1)>"


def normalise_sink(sink: str) -> str:
    """Reduce a sink name to lowercase letters and digits."""
    return "".join(character for character in sink.lower() if character.isalnum())


def payload_for(sink: str, variant: int = 0, overrides: Optional[Dict[str, str]] = None) -> str:
    """Return the payload to inject into a sink.

    Args:
        sink: Sink name as reported by the instrumentation or the static scan.
        variant: 0 for the primary payload, 1 for the fallback variant.
        overrides: Refreshed payloads from --auto-update, keyed by sink name;
            the key "default" covers every sink the tables do not name.
    """
    key = normalise_sink(sink)
    overrides = overrides or {}
    if key in overrides:
        return overrides[key]
    if variant:
        return FALLBACK_PAYLOADS.get(key) or FALLBACK_PAYLOADS["innerhtml"]
    return overrides.get("default") or PRIMARY_PAYLOADS.get(key) or DEFAULT_PAYLOAD


def cache_path(root: Path) -> Path:
    """Return the local payload cache path for a project root."""
    return root / ".tmp" / "payloads.json"


def parse_payloads(document: object) -> Dict[str, str]:
    """Read a payload document: a mapping of sink to payload, or a plain list.

    Raises:
        ValueError: If the document has the wrong shape.
    """
    if isinstance(document, dict):
        entries = document.get("payloads", document)
        if not isinstance(entries, dict):
            raise ValueError("payloads must be a mapping of sink to payload")
        return {str(key).lower(): str(value) for key, value in entries.items()}
    if isinstance(document, list):
        return {"default": str(document[0])} if document else {}
    raise ValueError("a payload source must be a JSON object or array")


def load_payloads(path: Path) -> Dict[str, str]:
    """Load the cached payloads, or return an empty mapping."""
    if not path.is_file():
        return {}
    try:
        return parse_payloads(loads(path.read_text(encoding="utf-8")))
    except (ValueError, OSError) as error:
        logger.warning("Ignoring the payload cache %s: %s", path, error)
        return {}


def save_payloads(path: Path, payloads: Dict[str, str]) -> None:
    """Write the payload cache."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps(payloads, indent=2), encoding="utf-8")


async def refresh_payloads(session: ClientSession, path: Path) -> Dict[str, str]:
    """Fetch the payload list from DOMINATOR_PAYLOAD_SOURCE and cache it.

    Returns the refreshed payloads, or an empty mapping when no source is
    configured or the fetch failed; the scan then keeps the built in payloads.
    """
    source = environ.get(SOURCE_ENV, "").strip()
    if not source:
        logger.warning("%s is not set, keeping the built in payloads", SOURCE_ENV)
        return {}
    try:
        async with session.get(source, timeout=TIMEOUT_SECONDS) as response:
            if response.status != 200:
                logger.warning(
                    "Payload source answered HTTP %s, keeping the built in payloads",
                    response.status,
                )
                return {}
            payloads = parse_payloads(await response.json(content_type=None))
    except Exception as error:
        logger.warning("Could not refresh the payloads: %s", error)
        return {}
    save_payloads(path, payloads)
    logger.info("Refreshed %d payload(s) from %s", len(payloads), source)
    return payloads
