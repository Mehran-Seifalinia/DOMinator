"""Tests for the HTML script and attribute extractor."""

from pytest import raises
from extractors.html_parser import ScriptExtractor


def test_rejects_empty_html() -> None:
    with raises(TypeError):
        ScriptExtractor("   ")


def test_rejects_non_string_html() -> None:
    with raises(TypeError):
        ScriptExtractor(None)  # type: ignore[arg-type]


def test_extracts_inline_scripts_and_deduplicates() -> None:
    html = """
    <html><body>
        <script>console.log("first");</script>
        <script src="external.js"></script>
        <script>console.log("first");</script>
    </body></html>
    """
    scripts = ScriptExtractor(html).extract_inline_scripts()
    assert [content for _, content in scripts] == ['console.log("first");']
    assert scripts[0][0] >= 0


def test_flags_event_handler_attributes() -> None:
    html = '<html><body><img src="x" onerror="alert(1)"></body></html>'
    found = ScriptExtractor(html).get_dangerous_html_elements()
    assert ("img", "onerror", "alert(1)") in [(tag, attr, value) for tag, attr, value, _ in found]


def test_flags_suspicious_protocols_only() -> None:
    html = (
        '<html><body>'
        '<a href="javascript:alert(1)">bad</a>'
        '<a href="https://example.com">good</a>'
        '</body></html>'
    )
    found = [(tag, attr, value) for tag, attr, value, _ in ScriptExtractor(html).get_dangerous_html_elements()]
    assert ("a", "href", "javascript:alert(1)") in found
    assert all(value != "https://example.com" for _, _, value in found)


def test_ignores_empty_event_handler_values() -> None:
    html = '<html><body><div onclick="">text</div></body></html>'
    assert ScriptExtractor(html).get_dangerous_html_elements() == []


def test_skips_non_javascript_script_blocks() -> None:
    html = """
    <html><body>
        <script type="application/json">{"cmd": "eval(userInput)"}</script>
        <script type="text/template"><div onclick="x"></div></script>
        <script type="module">eval(userInput)</script>
    </body></html>
    """
    contents = [content for _, content in ScriptExtractor(html).extract_inline_scripts()]
    assert contents == ["eval(userInput)"]


def test_skips_dangerous_elements_inside_inert_containers() -> None:
    html = """
    <html><body>
        <template><img src="x" onerror="alert(1)"></template>
        <noscript><div onclick="alert(2)">x</div></noscript>
        <a href="javascript:alert(3)">live</a>
    </body></html>
    """
    found = ScriptExtractor(html).get_dangerous_html_elements()
    assert [value for _, _, value, _ in found] == ["javascript:alert(3)"]
