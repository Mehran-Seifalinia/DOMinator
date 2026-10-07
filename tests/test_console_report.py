"""Tests for the console report, which is the main output path of the tool."""

from typing import Any, Dict, List
from pytest import CaptureFixture
from dominator import print_console_report


def make_result(**overrides: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "url": "http://127.0.0.1:8899/",
        "status": "completed",
        "severity": "Critical",
        "elapsed_time": 1.5,
        "static_occurrences": [],
        "dynamic_occurrences": [],
        "event_handlers": {},
        "external_script_risks": [],
    }
    result.update(overrides)
    return result


def make_dynamic_occurrence(**overrides: Any) -> Dict[str, Any]:
    occurrence: Dict[str, Any] = {
        "line": 21,
        "column": None,
        "pattern": "innerHTML",
        "context": "document.getElementById('query-sink').innerHTML = params.get('q')",
        "risk_level": "critical",
        "priority": 0.9,
        "source": "dynamic",
        "injected_url": "http://127.0.0.1:8899/?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E",
    }
    occurrence.update(overrides)
    return occurrence


def make_static_occurrence(**overrides: Any) -> Dict[str, Any]:
    occurrence: Dict[str, Any] = {
        "line": 12,
        "column": None,
        "pattern": "document.write(",
        "context": "document.write(location.hash)",
        "risk_level": "critical",
        "priority": 0.8,
        "source": "static",
        "injected_url": None,
    }
    occurrence.update(overrides)
    return occurrence


def make_event_handler(**overrides: Any) -> Dict[str, Any]:
    handler: Dict[str, Any] = {
        "tag": "img",
        "attribute": "onerror",
        "handler": "alert(1)",
        "line": 7,
        "column": None,
        "risk_level": "unknown",
        "priority": 0.0,
    }
    handler.update(overrides)
    return handler


def test_reports_the_exploit_url_when_output_is_not_a_terminal(capsys: CaptureFixture) -> None:
    results: List[Dict[str, Any]] = [make_result(dynamic_occurrences=[make_dynamic_occurrence()])]
    print_console_report(results)
    out = capsys.readouterr().out
    assert "Exploit URL:" in out
    assert "?q=" in out
    assert "innerHTML" in out


def test_reports_a_clean_target(capsys: CaptureFixture) -> None:
    print_console_report([make_result(severity="Informative")])
    assert "No DOM XSS vulnerabilities detected." in capsys.readouterr().out


def test_reports_an_error_status(capsys: CaptureFixture) -> None:
    print_console_report([make_result(status="error", error_message="target unreachable")])
    assert "target unreachable" in capsys.readouterr().out


def test_report_output_is_pure_ascii(capsys: CaptureFixture) -> None:
    results: List[Dict[str, Any]] = [
        make_result(
            dynamic_occurrences=[make_dynamic_occurrence()],
            static_occurrences=[make_static_occurrence()],
            event_handlers={"onerror": [make_event_handler()]},
            external_script_risks=[make_static_occurrence(source="external")],
        )
    ]
    print_console_report(results)
    out = capsys.readouterr().out
    assert out.isascii()
    assert "[CRITICAL]" in out
    assert "Found 4 potential issue(s):" in out
