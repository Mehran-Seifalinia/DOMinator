"""Tests for the static analyzer: masked JavaScript and handler attributes."""

from typing import Set
from scanners.static_analyzer import StaticAnalyzer


def patterns(html: str) -> Set[str]:
    """Return the raw patterns the static analyzer reports for a page."""
    result = StaticAnalyzer(html).analyze()
    return {str(occurrence["pattern"]) for occurrence in result.static_occurrences}


def test_finds_a_sink_in_an_inline_script() -> None:
    html = "<html><body><script>el.innerHTML = location.hash;</script></body></html>"
    assert any("innerHTML" in pattern for pattern in patterns(html))


def test_ignores_a_sink_inside_a_comment() -> None:
    html = "<html><body><script>// el.innerHTML = location.hash;\nvar x = 1;</script></body></html>"
    assert not any("innerHTML" in pattern for pattern in patterns(html))


def test_ignores_a_sink_inside_a_string() -> None:
    html = "<html><body><script>var note = 'el.innerHTML = x';</script></body></html>"
    assert not any("innerHTML" in pattern for pattern in patterns(html))


def test_ignores_a_data_block() -> None:
    html = '<html><body><script type="application/json">{"x": "eval(1)"}</script></body></html>'
    assert patterns(html) == set()


def test_finds_a_sink_inside_an_event_handler_attribute() -> None:
    html = '<html><body><img src="x" onerror="el.innerHTML = location.hash"></body></html>'
    assert any("innerHTML" in pattern for pattern in patterns(html))


def test_finds_srcdoc() -> None:
    html = "<html><body><script>frame.srcdoc = params.get('q');</script></body></html>"
    assert any("srcdoc" in pattern for pattern in patterns(html))
