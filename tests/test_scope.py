"""Tests for the scope rules: what the scanner may follow and what it skips."""

from utils.scope import blacklist_key, host_of, in_scope, is_blacklisted


def test_host_of() -> None:
    assert host_of("http://Example.COM/a") == "example.com"
    assert host_of("not a url") == ""


def test_crawl_stays_on_the_starting_host() -> None:
    base = "http://127.0.0.1:8000/app/"
    assert in_scope("http://127.0.0.1:8000/other", base)
    assert not in_scope("http://evil.example/other", base)
    assert not in_scope("http://localhost:8000/other", base)


def test_blacklist_key_drops_the_scheme_and_fragment() -> None:
    assert blacklist_key("https://Example.com/a/#x") == "example.com/a"
    assert blacklist_key("http://example.com/") == "example.com"
    assert blacklist_key("http://example.com/a?b=1") == "example.com/a?b=1"


def test_blacklist_matches_a_full_url() -> None:
    assert is_blacklisted("http://example.com/a", ["http://example.com/a"])
    assert not is_blacklisted("http://example.com/b", ["http://example.com/a"])


def test_blacklist_matches_a_bare_host_and_its_subtree() -> None:
    assert is_blacklisted("http://example.com/anything", ["example.com"])
    assert is_blacklisted("http://example.com/a/b", ["example.com/a"])
    assert not is_blacklisted("http://other.com/a", ["example.com"])


def test_blacklist_matches_a_wildcard() -> None:
    assert is_blacklisted("http://api.example.com/a", ["*.example.com"])
    assert is_blacklisted("http://example.com/a/b", ["example.com/a*"])
    assert not is_blacklisted("http://api.example.org/a", ["*.example.com"])


def test_blacklist_ignores_empty_entries() -> None:
    assert not is_blacklisted("http://example.com/a", ["", "  ", ","])
