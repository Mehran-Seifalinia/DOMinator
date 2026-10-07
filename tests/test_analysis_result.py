"""Tests for the analysis result container."""

from datetime import datetime, timedelta
from typing import Any, Dict
from pytest import raises
from utils.analysis_result import AnalysisResult, EventHandler


def make_occurrence(**overrides: Any) -> Dict[str, Any]:
    occurrence: Dict[str, Any] = {
        "line": 1,
        "column": None,
        "pattern": "eval(",
        "context": "eval(userInput)",
        "risk_level": "critical",
        "priority": 0.9,
        "source": "static",
        "injected_url": None,
    }
    occurrence.update(overrides)
    return occurrence


def test_occurrence_is_tagged_and_deduplicated() -> None:
    result = AnalysisResult()
    result.add_static_occurrence(make_occurrence())
    result.add_static_occurrence(make_occurrence())
    assert len(result.static_occurrences) == 1
    assert result.static_occurrences[0]["source"] == "static"


def test_static_and_dynamic_occurrences_stay_separate() -> None:
    result = AnalysisResult()
    result.add_static_occurrence(make_occurrence())
    result.add_dynamic_occurrence(make_occurrence())
    assert len(result.static_occurrences) == 1
    assert len(result.dynamic_occurrences) == 1
    assert result.dynamic_occurrences[0]["source"] == "dynamic"


def test_missing_required_field_raises() -> None:
    occurrence = make_occurrence()
    occurrence.pop("risk_level")
    with raises(ValueError):
        AnalysisResult().add_static_occurrence(occurrence)


def test_merge_from_merges_every_source_and_keeps_deduplication() -> None:
    first = AnalysisResult()
    first.add_static_occurrence(make_occurrence())
    first.dom_sources.append("location.hash")

    second = AnalysisResult()
    second.add_static_occurrence(make_occurrence())
    second.add_dynamic_occurrence(make_occurrence(pattern="innerHTML", context="el.innerHTML = x"))
    second.add_external_script_risk(make_occurrence(pattern="eval(", context="eval(x)"))
    second.dom_sources.append("location.search")

    first.merge_from(second)
    assert len(first.static_occurrences) == 1
    assert len(first.dynamic_occurrences) == 1
    assert len(first.external_script_risks) == 1
    assert first.dom_sources == ["location.hash", "location.search"]


def test_merge_rejects_a_foreign_object() -> None:
    with raises(TypeError):
        AnalysisResult().merge_static_results({"static_occurrences": []})  # type: ignore[arg-type]


def test_error_state_propagates_on_merge() -> None:
    other = AnalysisResult()
    other.set_error("target unreachable")
    result = AnalysisResult()
    result.merge_from(other)
    assert result.status == "error"
    assert result.error_message == "target unreachable"


def test_high_risk_and_source_filters() -> None:
    result = AnalysisResult()
    result.add_static_occurrence(make_occurrence(risk_level="Critical"))
    result.add_static_occurrence(
        make_occurrence(pattern="localStorage", context="localStorage.a", risk_level="low", line=5)
    )
    result.add_dynamic_occurrence(
        make_occurrence(pattern="innerHTML", context="x.innerHTML = y", risk_level="high", line=9)
    )
    assert len(result.get_high_risk_occurrences()) == 2
    assert len(result.get_occurrences_by_source("static")) == 2
    assert result.get_occurrences_by_source("unknown-source") == []


def test_event_handler_serialisation() -> None:
    result = AnalysisResult()
    result.add_event_handler("onerror", EventHandler(tag="img", attribute="onerror", handler="alert(1)", line=3))
    payload = result.to_dict()
    assert payload["event_handlers"]["onerror"][0]["handler"] == "alert(1)"
    assert payload["status"] == "pending"


def test_elapsed_time_needs_both_timestamps() -> None:
    result = AnalysisResult()
    assert result.elapsed_time == 0.0
    result.start_time = datetime(2026, 1, 1, 0, 0, 0)
    assert result.elapsed_time == 0.0
    result.end_time = result.start_time + timedelta(seconds=2.5)
    assert result.elapsed_time == 2.5


def test_merge_dynamic_results_keeps_handlers_and_external_risks() -> None:
    other = AnalysisResult()
    other.add_dynamic_occurrence(make_occurrence(pattern="innerHTML", context="el.innerHTML = x"))
    other.add_event_handler("onerror", EventHandler(tag="img", attribute="onerror", handler="alert(1)"))
    other.add_external_script_risk(make_occurrence(pattern="eval(", context="eval(x)"))

    result = AnalysisResult()
    result.merge_dynamic_results(other)
    assert len(result.dynamic_occurrences) == 1
    assert list(result.event_handlers) == ["onerror"]
    assert len(result.external_script_risks) == 1


def test_unconfirmed_occurrences_stay_out_of_the_confirmed_lists() -> None:
    result = AnalysisResult()
    result.add_unconfirmed_occurrence(make_occurrence())
    assert result.dynamic_occurrences == []
    assert len(result.unconfirmed_occurrences) == 1
    assert result.unconfirmed_occurrences[0]["source"] == "unconfirmed"
    assert result.unconfirmed_occurrences[0]["confirmed"] is False
    assert result.get_high_risk_occurrences() == []
    assert result.get_all_occurrences() == []
    assert result.to_dict()["unconfirmed_occurrences"] == result.unconfirmed_occurrences


def test_dynamic_occurrences_are_marked_confirmed() -> None:
    result = AnalysisResult()
    result.add_dynamic_occurrence(make_occurrence())
    assert result.dynamic_occurrences[0]["confirmed"] is True


def test_merge_from_carries_unconfirmed_occurrences() -> None:
    other = AnalysisResult()
    other.add_unconfirmed_occurrence(make_occurrence())
    result = AnalysisResult()
    result.merge_from(other)
    assert len(result.unconfirmed_occurrences) == 1
