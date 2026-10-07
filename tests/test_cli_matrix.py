"""Tests for the command line matrix harness."""

from pathlib import Path
from tools.cli_matrix import BEHAVIOR_CASES, PLAN_CASES, all_cases, format_args


def test_case_names_are_unique() -> None:
    names = [case.name for case in all_cases()]
    assert len(names) == len(set(names))


def test_every_behavior_case_declares_an_output_file() -> None:
    for case in BEHAVIOR_CASES:
        assert case.output, case.name


def test_every_behavior_case_can_be_judged() -> None:
    for case in BEHAVIOR_CASES:
        judged = case.validate is not None or case.expect_out or case.expect_absent
        assert judged, case.name


def test_format_args_substitutes_the_placeholders() -> None:
    case = next(candidate for candidate in PLAN_CASES if candidate.name == "plan-url")
    args = format_args(case, "http://127.0.0.1:1234/", Path("out.json"))
    assert args == ["-u", "http://127.0.0.1:1234/", "--dry-run"]


def test_no_placeholder_survives_substitution() -> None:
    for case in all_cases():
        rendered = " ".join(format_args(case, "http://127.0.0.1:1234/", Path("out.json")))
        assert "{" not in rendered, case.name
