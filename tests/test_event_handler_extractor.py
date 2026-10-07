"""Tests for the inline event handler extractor."""

from pytest import raises
from extractors.event_handler_extractor import EventHandlerExtractor

HTML = """
<html><body>
  <img src="x" onerror="alert(1)">
  <div onclick="doWork()">click</div>
  <p onmouseover="">ignored</p>
</body></html>
"""


def test_rejects_empty_html() -> None:
    with raises(ValueError):
        EventHandlerExtractor("   ")


def test_extracts_handlers_and_skips_empty_values() -> None:
    handlers = EventHandlerExtractor(HTML).extract_event_handlers()
    assert set(handlers) == {"onerror", "onclick"}
    assert handlers["onerror"][0].tag == "img"
    assert handlers["onerror"][0].handler == "alert(1)"
    assert handlers["onclick"][0].risk_level == "unknown"


def test_to_json_requires_handlers() -> None:
    with raises(ValueError):
        EventHandlerExtractor(HTML).to_json({})


def test_to_json_serialises_handlers() -> None:
    extractor = EventHandlerExtractor(HTML)
    payload = extractor.to_json(extractor.extract_event_handlers())
    assert '"handler": "alert(1)"' in payload


def test_extract_returns_a_completed_result() -> None:
    result = EventHandlerExtractor(HTML, url="http://127.0.0.1/").extract()
    assert result.status == "completed"
    assert result.url == "http://127.0.0.1/"
    assert sorted(result.event_handlers) == ["onclick", "onerror"]


def test_skips_handlers_inside_inert_containers() -> None:
    html = """
    <html><body>
      <template><img src="x" alt="" onerror="alert(1)"></template>
      <noscript><img src="x" alt="" onerror="alert(2)"></noscript>
      <div onclick="live()">live</div>
    </body></html>
    """
    handlers = EventHandlerExtractor(html).extract_event_handlers()
    assert sorted(handlers) == ["onclick"]
