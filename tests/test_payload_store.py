"""Tests for the payload store used by the confirmation step."""

from pathlib import Path
from pytest import raises
from utils.payload_store import (
    DEFAULT_PAYLOAD,
    load_payloads,
    normalise_sink,
    parse_payloads,
    payload_for,
    save_payloads,
)


def test_normalise_sink() -> None:
    assert normalise_sink("innerHTML") == "innerhtml"
    assert normalise_sink("document.write") == "documentwrite"


def test_primary_payload_matches_the_sink() -> None:
    assert payload_for("innerHTML") == "<img src=x onerror=alert(1)>"
    assert payload_for("eval") == "alert(1)"
    assert payload_for("document.write") == "alert(1)"


def test_unknown_sink_gets_the_default_payload() -> None:
    assert payload_for("somethingElse") == DEFAULT_PAYLOAD


def test_fallback_variant_differs_from_the_primary() -> None:
    assert payload_for("innerHTML", 1) != payload_for("innerHTML", 0)
    assert payload_for("somethingElse", 1) == payload_for("innerHTML", 1)


def test_overrides_win_over_the_built_in_table() -> None:
    overrides = {"innerhtml": "<b onmouseover=alert(1)>x</b>", "default": "alert(9)"}
    assert payload_for("innerHTML", 0, overrides) == "<b onmouseover=alert(1)>x</b>"
    assert payload_for("eval", 0, overrides) == "alert(9)"


def test_parse_a_mapping_and_a_list() -> None:
    assert parse_payloads({"innerhtml": "x"}) == {"innerhtml": "x"}
    assert parse_payloads({"payloads": {"eval": "y"}}) == {"eval": "y"}
    assert parse_payloads(["alert(1)"]) == {"default": "alert(1)"}
    assert parse_payloads([]) == {}


def test_parse_rejects_the_wrong_shape() -> None:
    with raises(ValueError):
        parse_payloads("alert(1)")
    with raises(ValueError):
        parse_payloads({"payloads": ["alert(1)"]})


def test_cache_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "payloads.json"
    assert load_payloads(path) == {}
    save_payloads(path, {"innerhtml": "x"})
    assert load_payloads(path) == {"innerhtml": "x"}


def test_a_broken_cache_is_ignored(tmp_path: Path) -> None:
    path = tmp_path / "payloads.json"
    path.write_text("{ not json", encoding="utf-8")
    assert load_payloads(path) == {}
