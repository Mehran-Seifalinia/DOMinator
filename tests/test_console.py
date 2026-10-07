"""Tests for the console symbol table, which must stay renderable in CMD."""

from utils.console import SEVERITY_TAGS, SYMBOLS, UNKNOWN_SEVERITY_TAG, severity_tag


def test_every_symbol_is_ascii() -> None:
    assert SYMBOLS
    for name, value in SYMBOLS.items():
        assert value.isascii(), name


def test_every_severity_tag_is_ascii() -> None:
    assert SEVERITY_TAGS
    for label, tag in SEVERITY_TAGS.items():
        assert tag.isascii(), label
    assert UNKNOWN_SEVERITY_TAG.isascii()


def test_severity_tag_maps_known_labels() -> None:
    assert severity_tag("Critical") == "[CRITICAL]"
    assert severity_tag("Informative") == "[INFO]"


def test_severity_tag_falls_back_for_unknown_labels() -> None:
    assert severity_tag("Whatever") == UNKNOWN_SEVERITY_TAG
    assert severity_tag("") == UNKNOWN_SEVERITY_TAG
