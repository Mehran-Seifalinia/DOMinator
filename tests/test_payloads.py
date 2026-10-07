"""Tests for the payload collection."""

from json import loads
from pathlib import Path
from pytest import raises
from utils.payloads import Encoding, PayloadType, Payloads, get_default_payloads


def test_add_and_filter_payloads() -> None:
    payloads = Payloads()
    payloads.add_payload("<script>alert(1)</script>", PayloadType.SIMPLE, Encoding.RAW)
    payloads.add_payload("javascript:alert(1)", PayloadType.DYNAMIC, Encoding.RAW)
    assert len(payloads.get_payloads()) == 2
    assert len(payloads.get_payloads(payload_type=PayloadType.DYNAMIC)) == 1
    assert payloads.get_payloads(encoding=Encoding.BASE64) == []


def test_duplicate_payload_is_ignored() -> None:
    payloads = Payloads()
    payloads.add_payload("alert(1)")
    payloads.add_payload("alert(1)")
    assert len(payloads.get_payloads()) == 1


def test_invalid_payload_raises() -> None:
    with raises(ValueError):
        Payloads().add_payload("   ")


def test_update_and_exact_remove() -> None:
    payloads = Payloads()
    payloads.add_payload("alert(1)")
    assert payloads.update_payload("alert(1)", "alert(2)") is True
    assert payloads.update_payload("absent", "alert(3)") is False
    assert payloads.remove_exact("alert(2)", PayloadType.SIMPLE, Encoding.RAW) is True
    assert payloads.remove_exact("alert(2)", PayloadType.SIMPLE, Encoding.RAW) is False


def test_remove_all_by_string_counts_every_encoding() -> None:
    payloads = Payloads()
    payloads.add_payload("alert(1)", PayloadType.SIMPLE, Encoding.RAW)
    payloads.add_payload("alert(1)", PayloadType.ENCODED, Encoding.URL)
    assert payloads.remove_all_by_string("alert(1)") == 2
    assert payloads.get_payloads() == []


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    target = tmp_path / "payloads.json"
    payloads = Payloads()
    payloads.add_default_payloads()
    payloads.save_to_file(str(target))
    assert len(loads(target.read_text(encoding="utf-8"))) == 4

    reloaded = Payloads()
    reloaded.load_from_file(str(target))
    assert len(reloaded.get_payloads()) == 4


def test_missing_file_is_not_fatal(tmp_path: Path) -> None:
    payloads = Payloads()
    payloads.load_from_file(str(tmp_path / "absent.json"))
    assert payloads.get_payloads() == []


def test_search_is_case_insensitive() -> None:
    payloads = Payloads()
    payloads.add_payload("<IMG SRC=x onerror=alert(1)>")
    assert len(payloads.search_payloads("img")) == 1
    assert payloads.search_payloads("nonexistent") == []


def test_clear_empties_the_collection() -> None:
    payloads = Payloads()
    payloads.add_default_payloads()
    payloads.clear()
    assert payloads.get_payloads() == []


def test_default_payload_strings() -> None:
    defaults = get_default_payloads()
    assert len(defaults) == 4
    assert "<script>alert(1)</script>" in defaults
