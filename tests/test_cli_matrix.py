"""Tests for the command line matrix harness."""

from tools.cli_matrix import BEHAVIOR_CASES, PLAN_CASES, all_cases, base_values, format_args, format_env

TARGET = "http://127.0.0.1:1234/"


def values_for(out: str = "out.json") -> dict:
    """Build the placeholder values the runner passes to a case."""
    return base_values(TARGET, "http://127.0.0.1:1", "http://127.0.0.1:2/payloads-source.json") | {"out": out}


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
    assert format_args(case, values_for()) == ["-u", TARGET, "--dry-run"]


def test_format_env_substitutes_the_placeholders() -> None:
    case = next(candidate for candidate in BEHAVIOR_CASES if candidate.env)
    rendered = format_env(case, values_for())
    assert all("{" not in value for value in rendered.values())
    assert rendered["DOMINATOR_PAYLOAD_SOURCE"].endswith("payloads-source.json")


def test_no_placeholder_survives_substitution() -> None:
    for case in all_cases():
        values = values_for()
        rendered = " ".join(format_args(case, values)) + " ".join(format_env(case, values).values())
        assert "{" not in rendered, case.name
