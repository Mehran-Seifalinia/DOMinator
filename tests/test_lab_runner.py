"""Tests for the lab runner scoring logic."""

from pathlib import Path
from typing import Any, Dict, List
from tools.lab_runner import Lab, collect_names, evaluate, load_labs, normalise

ROOT = Path(__file__).resolve().parent.parent


def make_result(**overrides: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "status": "completed",
        "static_occurrences": [],
        "dynamic_occurrences": [],
        "external_script_risks": [],
        "event_handlers": {},
    }
    result.update(overrides)
    return result


def occurrence(pattern: str) -> Dict[str, Any]:
    return {"pattern": pattern, "context": "", "risk_level": "high", "priority": 1.0}


def test_normalise_reduces_a_pattern_to_letters_and_digits() -> None:
    assert normalise(".innerHTML = ") == "innerhtml"
    assert normalise("document.write(") == "documentwrite"
    assert normalise("<script>alert(1)</script>") == "scriptalert1script"


def test_normalise_cuts_the_dynamic_source_annotation() -> None:
    assert normalise("innerHTML (source: location.hash (exact))") == "innerhtml"
    assert normalise("eval (source: location.search (param name: q, exact match))") == "eval"


def test_collect_names_gathers_every_source() -> None:
    result = make_result(
        static_occurrences=[occurrence("setTimeout(")],
        dynamic_occurrences=[occurrence("innerHTML")],
        event_handlers={"onerror": [{"attribute": "onerror"}]},
    )
    everywhere, dynamic, handlers = collect_names([result])
    assert everywhere == {"settimeout", "innerhtml", "onerror"}
    assert dynamic == {"innerhtml"}
    assert handlers == {"onerror"}


def test_evaluate_reports_a_false_negative() -> None:
    outcome = evaluate(Lab(slug="x", expect_dynamic=("innerhtml",)), [make_result()])
    assert not outcome.passed
    assert outcome.missing == ["dynamic:innerhtml"]


def test_evaluate_reports_a_false_positive_on_a_dirty_page() -> None:
    outcome = evaluate(Lab(slug="x", expect_clean=True), [make_result(static_occurrences=[occurrence("eval(")])])
    assert outcome.unexpected == ["eval"]


def test_evaluate_accepts_a_clean_page() -> None:
    assert evaluate(Lab(slug="x", expect_clean=True), [make_result()]).passed


def test_evaluate_checks_the_status() -> None:
    lab = Lab(slug="x", expect_status="error")
    assert evaluate(lab, [make_result(status="error")]).passed
    assert not evaluate(lab, [make_result(status="completed")]).passed


def test_forbid_dynamic_only_looks_at_dynamic_results() -> None:
    lab = Lab(slug="x", forbid_dynamic=("innerhtml",))
    static_only = make_result(static_occurrences=[occurrence("innerHTML")])
    assert evaluate(lab, [static_only]).passed
    dynamic_hit = make_result(dynamic_occurrences=[occurrence("innerHTML")])
    assert not evaluate(lab, [dynamic_hit]).passed


def test_the_manifest_describes_every_fixture() -> None:
    labs: List[Lab] = load_labs(ROOT / "labs" / "manifest.json")
    assert len(labs) >= 20
    assert len({lab.slug for lab in labs}) == len(labs)
    for lab in labs:
        assert (ROOT / "labs" / lab.slug / "index.html").is_file(), lab.slug
