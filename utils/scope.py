"""Scope helpers: which URLs the scanner may follow and which it must skip.

Crawling and blacklisting both decide whether a URL is in play, and a mistake
there sends requests to a host the engagement does not cover. The rules live
here so they can be tested without a browser or a network.
"""

from re import compile as compile_pattern, escape
from typing import Sequence
from urllib.parse import urlparse


def host_of(url: str) -> str:
    """Return the lowercase host of a URL, or an empty string."""
    try:
        return urlparse(url).netloc.lower()
    except ValueError:
        return ""


def in_scope(candidate: str, base: str) -> bool:
    """Return True when a crawl target stays on the host of the starting URL."""
    candidate_host = host_of(candidate)
    return bool(candidate_host) and candidate_host == host_of(base)


def blacklist_key(url: str) -> str:
    """Reduce a URL to host, path and query for comparison.

    The scheme and the fragment are dropped, and a trailing slash is ignored so
    that http://host and http://host/ compare equal.
    """
    parsed = urlparse(url)
    key = f"{parsed.netloc.lower()}{parsed.path.rstrip('/')}"
    if parsed.query:
        key = f"{key}?{parsed.query}"
    return key


def is_blacklisted(url: str, entries: Sequence[str]) -> bool:
    """Return True when a URL matches one of the blacklist entries.

    An entry may be a full URL, a bare host, or a pattern containing * as a
    wildcard. A bare host or a directory also covers everything below it.
    """
    key = blacklist_key(url)
    for entry in entries:
        candidate = blacklist_key(entry) if "://" in entry else entry.strip().lower().rstrip("/")
        if not candidate:
            continue
        if "*" in candidate:
            # A pattern without a slash describes a host, so it is matched
            # against the host alone; one with a slash matches the full key.
            # Escape first, then join the parts with .* so the wildcard survives.
            subject = key if "/" in candidate else host_of(url)
            pattern = "^" + ".*".join(escape(part) for part in candidate.split("*")) + "$"
            if compile_pattern(pattern).match(subject):
                return True
        elif key == candidate or key.startswith(f"{candidate}/"):
            return True
    return False
