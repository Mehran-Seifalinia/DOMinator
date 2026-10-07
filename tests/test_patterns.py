"""Tests for the shared pattern tables and the risk mapping."""

from utils.patterns import (
    DANGEROUS_HTML_PATTERNS,
    DANGEROUS_JS_PATTERNS,
    DOM_SOURCES_PATTERNS,
    EVENT_HANDLER_ATTRIBUTES,
    get_risk_level,
)


def test_critical_patterns() -> None:
    assert get_risk_level("eval(userInput)") == "critical"
    assert get_risk_level("el.innerHTML = data") == "critical"
    assert get_risk_level("document.write(payload)") == "critical"
    assert get_risk_level("node.outerHTML = data") == "critical"


def test_high_risk_patterns() -> None:
    assert get_risk_level("new Function('return 1')") == "high"
    assert get_risk_level("window.location = target") == "high"


def test_medium_and_low_patterns() -> None:
    assert get_risk_level("setTimeout(run, 10)") == "medium"
    assert get_risk_level("fetch('/api')") == "medium"
    assert get_risk_level("localStorage.setItem('a', 'b')") == "low"


def test_unknown_for_benign_code() -> None:
    assert get_risk_level("const total = items.length;") == "unknown"


def test_complexity_argument_is_ignored() -> None:
    assert get_risk_level("eval(x)", 5) == get_risk_level("eval(x)", 1)


def test_event_handler_attributes_are_normalised() -> None:
    assert EVENT_HANDLER_ATTRIBUTES
    assert all(name == name.lower() for name in EVENT_HANDLER_ATTRIBUTES)
    assert {"onclick", "onerror", "onload"} <= EVENT_HANDLER_ATTRIBUTES


def test_pattern_tables_are_populated() -> None:
    assert DANGEROUS_JS_PATTERNS
    assert DANGEROUS_HTML_PATTERNS
    assert DOM_SOURCES_PATTERNS
