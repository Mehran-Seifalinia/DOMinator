#!/usr/bin/env python3
"""Run every DOMinator command line parameter and record what it really does.

Tier "plan" pairs each flag with --dry-run, so it needs neither a browser nor a
network: it proves the flag is accepted and reaches the scan plan. Tier
"behavior" runs the flags that change scanning against the local lab target and
checks the exit code, the output markers, the report files and the requests the
target really received. A regression turns into a failing row instead of a
silent change.

The behavior tier needs full access: Playwright opens named pipes that the DSH
sandbox blocks.
"""

from argparse import ArgumentParser
from dataclasses import dataclass
from json import dump, load
from pathlib import Path
from subprocess import TimeoutExpired, run
from sys import executable, path as sys_path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys_path:
    sys_path.insert(0, str(ROOT))

from tools.lab_server import read_records, serve

DOMINATOR = ROOT / "dominator.py"
LAB_DIR = ROOT / "labs" / "dom-xss-lab"
OUTPUT_DIR = ROOT / ".tmp" / "cli-matrix"
RECORD_FILE = OUTPUT_DIR / "requests.jsonl"
LIST_FILE = OUTPUT_DIR / "targets.txt"
MISSING_LIST_FILE = OUTPUT_DIR / "absent.txt"

Validator = Callable[[Any, Path, List[Dict[str, Any]]], None]


@dataclass(frozen=True)
class Case:
    """One command line invocation and what it must produce."""

    name: str
    args: Tuple[str, ...] = ()
    tier: str = "plan"
    expect_exit: int = 0
    expect_out: Tuple[str, ...] = ()
    expect_absent: Tuple[str, ...] = ()
    needs_target: bool = True
    output: Optional[str] = None
    validate: Optional[Validator] = None
    timeout: int = 300


@dataclass
class Result:
    """The outcome of one case."""

    name: str
    tier: str
    args: List[str]
    exit_code: Optional[int]
    passed: bool
    reason: str = ""


def parse_results(path: Path) -> Any:
    """Load a JSON report, or return None when it is missing."""
    if not path.is_file():
        return None
    return load(path.open(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    """Raise AssertionError with a message when a case expectation fails."""
    if not condition:
        raise AssertionError(message)


def validate_one_completed(payload: Any, _out: Path, _records: List[Dict[str, Any]]) -> None:
    require(isinstance(payload, list) and len(payload) == 1, f"expected one result, got {payload!r}")
    require(payload[0].get("status") == "completed", f"status is {payload[0].get('status')!r}")


def validate_two_results(payload: Any, _out: Path, _records: List[Dict[str, Any]]) -> None:
    require(isinstance(payload, list) and len(payload) == 2, f"expected two results, got {len(payload or [])}")


def validate_completed(payload: Any, _out: Path, _records: List[Dict[str, Any]]) -> None:
    require(isinstance(payload, list) and payload, "result list is empty")
    require(payload[0].get("status") == "completed", f"status is {payload[0].get('status')!r}")


def validate_empty(payload: Any, _out: Path, _records: List[Dict[str, Any]]) -> None:
    require(payload == [], f"blacklisted target still produced {payload!r}")


def validate_error_status(payload: Any, _out: Path, _records: List[Dict[str, Any]]) -> None:
    require(isinstance(payload, list) and payload, "result list is empty")
    require(payload[0].get("status") == "error", f"status is {payload[0].get('status')!r}")


def validate_csv(_payload: Any, out: Path, _records: List[Dict[str, Any]]) -> None:
    text = out.read_text(encoding="utf-8", errors="replace")
    require(len(text.splitlines()) >= 2, "csv has no data row")
    require("http" in text, "csv does not contain the target url")


def validate_html(_payload: Any, out: Path, _records: List[Dict[str, Any]]) -> None:
    text = out.read_text(encoding="utf-8", errors="replace").lower()
    require("<html" in text or "<!doctype" in text, "html report is not a document")
    require("http" in text, "html report does not contain the target url")


def validate_user_agent(_payload: Any, _out: Path, records: List[Dict[str, Any]]) -> None:
    agents = [record["headers"].get("user-agent", "") for record in records]
    require(any("dsh-matrix-probe" in agent for agent in agents), f"user agent never arrived: {agents}")


def validate_cookie(_payload: Any, _out: Path, records: List[Dict[str, Any]]) -> None:
    cookies = [record["headers"].get("cookie", "") for record in records]
    require(any("dsh=probe" in cookie for cookie in cookies), f"cookie never arrived: {cookies}")


PLAN_CASES: Tuple[Case, ...] = (
    Case("help-short", ("-h",), expect_out=("usage:", "--dry-run"), needs_target=False),
    Case("help-long", ("--help",), expect_out=("usage:", "DOM XSS Scanner"), needs_target=False),
    Case("plan-url", ("-u", "{target}", "--dry-run"), expect_out=("Dry run:", "Targets (1):")),
    Case("plan-threads", ("-u", "{target}", "-t", "4", "--dry-run"), expect_out=("Threads          : 4",)),
    Case("plan-level", ("-u", "{target}", "-l", "4", "--dry-run"), expect_out=("Analysis level   : 4",)),
    Case("plan-timeout", ("-u", "{target}", "-to", "25", "--dry-run"), expect_out=("Timeout (s)      : 25",)),
    Case("plan-report-html", ("-u", "{target}", "-r", "html", "--dry-run"), expect_out=("Report format    : html",)),
    Case("plan-output", ("-u", "{target}", "-o", "x.json", "--dry-run"), expect_out=("Output file      : x.json",)),
    Case("plan-proxy", ("-u", "{target}", "-p", "http://127.0.0.1:8080", "--dry-run"), expect_out=("Proxy            : http://127.0.0.1:8080",)),
    Case("plan-external-default", ("-u", "{target}", "--dry-run"), expect_out=("External scripts : analyzed",)),
    Case("plan-no-external", ("-u", "{target}", "--no-external", "--dry-run"), expect_out=("External scripts : skipped",)),
    Case("plan-visible", ("-u", "{target}", "--visible", "--dry-run"), expect_out=("Headless         : False",)),
    Case("plan-max-depth", ("-u", "{target}", "--max-depth", "3", "--dry-run"), expect_out=("Max crawl depth  : 3",)),
    Case("plan-force", ("-u", "{target}", "-f", "--dry-run")),
    Case("plan-verbose", ("-u", "{target}", "-v", "--dry-run")),
    Case("plan-quiet", ("-u", "{target}", "-q", "--dry-run")),
    Case("plan-blacklist", ("-u", "{target}", "-b", "http://example.com", "--dry-run")),
    Case("plan-user-agent", ("-u", "{target}", "--user-agent", "dsh-probe", "--dry-run")),
    Case("plan-cookie", ("-u", "{target}", "--cookie", "a=1", "--dry-run")),
    Case("plan-auto-update", ("-u", "{target}", "--auto-update", "--dry-run")),
    Case("plan-list-url", ("-L", "{list}", "--dry-run"), expect_out=("Targets (2):",)),
    Case("negative-no-args", (), expect_exit=1, expect_out=("No URL(s) or list URL provided",), needs_target=False),
    Case("negative-level", ("-u", "http://127.0.0.1:1/", "-l", "9"), expect_exit=2, expect_out=("invalid choice",), needs_target=False),
    Case("negative-format", ("-u", "http://127.0.0.1:1/", "-r", "xml"), expect_exit=2, expect_out=("invalid choice",), needs_target=False),
    Case("negative-timeout", ("-u", "http://127.0.0.1:1/", "-to", "0"), expect_exit=1, expect_out=("Timeout must be a positive integer",), needs_target=False),
    Case("negative-both-url-and-list", ("-u", "http://127.0.0.1:1/", "-L", "{list}"), expect_exit=1, expect_out=("Cannot use both",), needs_target=False),
    Case("negative-list-missing", ("-L", "{missing}",), expect_exit=1, expect_out=("not found",), needs_target=False),
)

BEHAVIOR_CASES: Tuple[Case, ...] = (
    Case("single-url", ("-u", "{target}", "-l", "1", "-o", "{out}", "-r", "json"), tier="behavior", output="single-url.json", validate=validate_one_completed),
    Case("two-urls", ("-u", "{target}", "{target}status.json", "-l", "1", "-o", "{out}", "-r", "json"), tier="behavior", output="two-urls.json", validate=validate_two_results),
    Case("level-1", ("-u", "{target}", "-l", "1", "-o", "{out}", "-r", "json"), tier="behavior", output="level-1.json", validate=validate_completed),
    Case("level-4", ("-u", "{target}", "-l", "4", "-o", "{out}", "-r", "json"), tier="behavior", output="level-4.json", validate=validate_completed),
    Case("report-csv", ("-u", "{target}", "-l", "1", "-o", "{out}", "-r", "csv"), tier="behavior", output="report.csv", validate=validate_csv),
    Case("report-html", ("-u", "{target}", "-l", "1", "-o", "{out}", "-r", "html"), tier="behavior", output="report.html", validate=validate_html),
    Case("external-default", ("-u", "{target}", "-l", "1", "-v", "-o", "{out}", "-r", "json"), tier="behavior", output="external-default.json", expect_out=("external JS for",), validate=validate_completed),
    Case("no-external", ("-u", "{target}", "-l", "1", "-v", "--no-external", "-o", "{out}", "-r", "json"), tier="behavior", output="no-external.json", expect_absent=("external JS for",), validate=validate_completed),
    Case("blacklist-target", ("-u", "{target}", "-l", "1", "-b", "{target}", "-o", "{out}", "-r", "json"), tier="behavior", output="blacklist.json", validate=validate_empty),
    Case("max-depth-2", ("-u", "{target}", "-l", "1", "--max-depth", "2", "-o", "{out}", "-r", "json"), tier="behavior", output="max-depth.json", expect_out=("page(s) to analyze",), validate=validate_completed),
    Case("threads-2", ("-u", "{target}", "{target}status.json", "-l", "1", "-t", "2", "-o", "{out}", "-r", "json"), tier="behavior", output="threads-2.json", validate=validate_two_results),
    Case("user-agent", ("-u", "{target}", "-l", "1", "--user-agent", "dsh-matrix-probe", "-o", "{out}", "-r", "json"), tier="behavior", output="user-agent.json", validate=validate_user_agent),
    Case("cookie", ("-u", "{target}", "-l", "1", "--cookie", "dsh=probe", "-o", "{out}", "-r", "json"), tier="behavior", output="cookie.json", validate=validate_cookie),
    Case("auto-update", ("-u", "{target}", "-l", "1", "--auto-update", "-o", "{out}", "-r", "json"), tier="behavior", output="auto-update.json", expect_out=("Placeholder",), validate=validate_completed),
    Case("quiet", ("-u", "{target}", "-l", "1", "-q", "-o", "{out}", "-r", "json"), tier="behavior", output="quiet.json", expect_out=("Vulnerability Report",), expect_absent=("started scanning",), validate=validate_completed),
    Case("verbose", ("-u", "{target}", "-l", "1", "-v", "-o", "{out}", "-r", "json"), tier="behavior", output="verbose.json", expect_out=("DEBUG",), validate=validate_completed),
    Case("unreachable", ("-u", "http://127.0.0.1:9/", "-o", "{out}", "-r", "json"), tier="behavior", output="unreachable.json", needs_target=False, validate=validate_error_status),
    Case("force-unreachable", ("-u", "http://127.0.0.1:9/", "-f", "-o", "{out}", "-r", "json"), tier="behavior", output="force-unreachable.json", needs_target=False, validate=validate_error_status),
    Case("proxy-dead", ("-u", "{target}", "-l", "1", "-p", "http://127.0.0.1:9", "-o", "{out}", "-r", "json"), tier="behavior", output="proxy-dead.json", validate=validate_error_status),
    Case("list-url", ("-L", "{list}", "-l", "1", "-o", "{out}", "-r", "json"), tier="behavior", output="list-url.json", validate=validate_two_results),
    Case("output-nested", ("-u", "{target}", "-l", "1", "-o", "{out}", "-r", "json"), tier="behavior", output="nested/deep/out.json", validate=validate_completed),
    Case("visible-window", ("-u", "{target}", "-l", "1", "--visible", "-o", "{out}", "-r", "json"), tier="behavior", output="visible.json", validate=validate_completed),
)


def all_cases() -> Tuple[Case, ...]:
    """Return every case, plan cases first."""
    return PLAN_CASES + BEHAVIOR_CASES


def format_args(case: Case, target: str, output_path: Path) -> List[str]:
    """Substitute the placeholders of one case."""
    values = {
        "target": target,
        "out": str(output_path),
        "list": str(LIST_FILE),
        "missing": str(MISSING_LIST_FILE),
    }
    return [argument.format(**values) for argument in case.args]


def check_case(case: Case, target: str) -> Result:
    """Run one case and evaluate its expectations."""
    output_path = OUTPUT_DIR / case.output if case.output else OUTPUT_DIR / f"{case.name}.json"
    args = format_args(case, target, output_path)
    if case.output and output_path.exists():
        output_path.unlink()
    if case.tier == "behavior" and RECORD_FILE.exists():
        RECORD_FILE.unlink()
    try:
        completed = run(
            [executable, str(DOMINATOR), *args],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=case.timeout,
        )
    except TimeoutExpired:
        return Result(case.name, case.tier, args, None, False, f"timed out after {case.timeout}s")
    combined = f"{completed.stdout}\n{completed.stderr}"
    result = Result(case.name, case.tier, args, completed.returncode, True)

    def fail(reason: str) -> None:
        result.passed = False
        result.reason = reason

    if completed.returncode != case.expect_exit:
        fail(f"exit {completed.returncode}, expected {case.expect_exit}")
    else:
        for marker in case.expect_out:
            if marker not in combined:
                fail(f"missing output marker {marker!r}")
                break
        else:
            for marker in case.expect_absent:
                if marker in combined:
                    fail(f"unexpected output marker {marker!r}")
                    break
            else:
                if case.output and not output_path.is_file():
                    fail(f"report file not written: {output_path.name}")
                elif case.validate is not None:
                    payload = parse_results(output_path) if output_path.suffix == ".json" else None
                    try:
                        case.validate(payload, output_path, read_records(RECORD_FILE))
                    except AssertionError as error:
                        fail(str(error))
    return result


def prepare() -> None:
    """Create the output directory and the list files the cases need."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if RECORD_FILE.exists():
        RECORD_FILE.unlink()


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the requested tier and print a pass or fail row per case."""
    parser = ArgumentParser(description="Run every DOMinator command line parameter and check the outcome")
    parser.add_argument("--tier", choices=["plan", "behavior", "all"], default="all", help="Which cases to run")
    parser.add_argument("--only", action="append", default=[], help="Run only these case names (repeatable)")
    parser.add_argument("--dry-run", action="store_true", help="Print the cases without running them")
    parser.add_argument("--json", type=str, help="Write the results as JSON to this path")
    args = parser.parse_args(argv)

    prepare()
    selected = [
        case for case in all_cases()
        if (args.tier == "all" or case.tier == args.tier) and (not args.only or case.name in args.only)
    ]
    if not selected:
        print("No case matches the filter.")
        return 2

    if args.dry_run:
        for case in selected:
            needs = "" if not case.needs_target else "  (needs target)"
            print(f"{case.tier:8} {case.name:26} {' '.join(case.args)}{needs}")
        print(f"{len(selected)} case(s), nothing executed")
        return 0

    results: List[Result] = []
    with serve(LAB_DIR, record_file=RECORD_FILE) as target:
        LIST_FILE.write_text(f"{target}\n{target}status.json\n", encoding="utf-8")
        for case in selected:
            outcome = check_case(case, target)
            results.append(outcome)
            status = "PASS" if outcome.passed else "FAIL"
            detail = f"  {outcome.reason}" if outcome.reason else ""
            print(f"{status}  {outcome.tier:8} {outcome.name:26}{detail}")

    passed = sum(1 for result in results if result.passed)
    print(f"\n{len(results)} case(s), {passed} passed, {len(results) - passed} failed")

    if args.json:
        destination = Path(args.json)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8") as handle:
            dump([result.__dict__ for result in results], handle, indent=2)
        print(f"Results written to {destination}")

    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
