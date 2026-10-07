#!/usr/bin/env python3
"""Run every lab fixture through DOMinator and score the findings.

Ground truth lives in labs/manifest.json. For each lab the runner serves the
fixtures, scans one page, normalises every reported pattern and compares it
with the manifest: an expected pattern that never appears is a false negative,
a pattern that must not appear is a false positive. The lab log and the raw
JSON of every scan stay in .tmp/lab-results for inspection.

Run it with full access: Playwright opens the named pipes that the DSH sandbox
blocks.
"""

from argparse import ArgumentParser
from dataclasses import asdict, dataclass, field
from json import dump, load
from pathlib import Path
from subprocess import TimeoutExpired, run
from sys import executable, path as sys_path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys_path:
    sys_path.insert(0, str(ROOT))

from tools.lab_server import serve

DOMINATOR = ROOT / "dominator.py"
LABS_DIR = ROOT / "labs"
MANIFEST = LABS_DIR / "manifest.json"
OUTPUT_DIR = ROOT / ".tmp" / "lab-results"
SCAN_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class Lab:
    """One fixture and what the scanner must report for it."""

    slug: str
    level: int = 3
    query: str = ""
    expect: Tuple[str, ...] = ()
    expect_dynamic: Tuple[str, ...] = ()
    expect_event_handlers: Tuple[str, ...] = ()
    forbid_any: Tuple[str, ...] = ()
    forbid_dynamic: Tuple[str, ...] = ()
    expect_clean: bool = False
    expect_status: str = "completed"
    extra_args: Tuple[str, ...] = ()
    notes: str = ""


@dataclass
class Outcome:
    """The scored result of one lab."""

    slug: str
    status: str
    results: int
    missing: List[str] = field(default_factory=list)
    unexpected: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """A lab passes when nothing is missing and nothing is unexpected."""
        return not self.missing and not self.unexpected


def load_labs(path: Path) -> List[Lab]:
    """Read the manifest into Lab objects."""
    payload = load(path.open(encoding="utf-8"))
    labs: List[Lab] = []
    for entry in payload["labs"]:
        labs.append(
            Lab(
                slug=entry["slug"],
                level=entry.get("level", 3),
                query=entry.get("query", ""),
                expect=tuple(entry.get("expect", ())),
                expect_dynamic=tuple(entry.get("expect_dynamic", ())),
                expect_event_handlers=tuple(entry.get("expect_event_handlers", ())),
                forbid_any=tuple(entry.get("forbid_any", ())),
                forbid_dynamic=tuple(entry.get("forbid_dynamic", ())),
                expect_clean=entry.get("expect_clean", False),
                expect_status=entry.get("expect_status", "completed"),
                extra_args=tuple(entry.get("extra_args", ())),
                notes=entry.get("notes", ""),
            )
        )
    return labs


def normalise(name: str) -> str:
    """Reduce a reported pattern to lowercase letters and digits.

    A dynamic pattern carries its source annotation, for example
    "innerHTML (source: location.hash (exact))". The annotation is cut off
    first, otherwise the sink name never matches the manifest.
    """
    head = name.split(" (source:")[0]
    return "".join(character for character in head.lower() if character.isalnum())


def collect_names(results: List[Dict[str, Any]]) -> Tuple[Set[str], Set[str], Set[str]]:
    """Return the normalised names found anywhere, in dynamic results and in handlers."""
    everywhere: Set[str] = set()
    dynamic: Set[str] = set()
    handlers: Set[str] = set()

    for result in results:
        for key in ("static_occurrences", "dynamic_occurrences", "external_script_risks"):
            for occurrence in result.get(key, []) or []:
                name = normalise(str(occurrence.get("pattern", "")))
                if name:
                    everywhere.add(name)
                    if key == "dynamic_occurrences":
                        dynamic.add(name)
        for handler_list in (result.get("event_handlers", {}) or {}).values():
            for handler in handler_list:
                name = normalise(str(handler.get("attribute", "")))
                if name:
                    handlers.add(name)
                    everywhere.add(name)

    return everywhere, dynamic, handlers


def evaluate(lab: Lab, results: List[Dict[str, Any]]) -> Outcome:
    """Compare the scan results with the manifest of one lab."""
    everywhere, dynamic, handlers = collect_names(results)
    missing: List[str] = []
    unexpected: List[str] = []

    for name in lab.expect:
        if name not in everywhere:
            missing.append(name)
    for name in lab.expect_dynamic:
        if name not in dynamic:
            missing.append(f"dynamic:{name}")
    for name in lab.expect_event_handlers:
        if name not in handlers:
            missing.append(f"handler:{name}")
    for name in lab.forbid_any:
        if name in everywhere:
            unexpected.append(name)
    for name in lab.forbid_dynamic:
        if name in dynamic:
            unexpected.append(f"dynamic:{name}")
    if lab.expect_clean:
        unexpected.extend(sorted(everywhere))

    status = str(results[0].get("status")) if results else "missing"
    if status != lab.expect_status:
        missing.append(f"status:{status}")

    return Outcome(
        slug=lab.slug,
        status=status,
        results=len(results),
        missing=sorted(set(missing)),
        unexpected=sorted(set(unexpected)),
    )


def scan(lab: Lab, base_url: str, reuse: bool = False) -> List[Dict[str, Any]]:
    """Scan one fixture and return its result objects.

    With reuse the saved JSON of a previous run is scored again, which makes
    fixing a detector cheap: no scan, no browser.
    """
    target = f"{base_url}{lab.slug}/{lab.query}"
    output = OUTPUT_DIR / f"{lab.slug}.json"
    log = OUTPUT_DIR / f"{lab.slug}.log"
    if reuse:
        if not output.is_file():
            return []
        payload = load(output.open(encoding="utf-8"))
        return payload if isinstance(payload, list) else [payload]
    if output.exists():
        output.unlink()
    args = [
        "-u", target,
        "-l", str(lab.level),
        "-o", str(output),
        "-r", "json",
        *lab.extra_args,
    ]
    try:
        completed = run(
            [executable, str(DOMINATOR), *args],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SCAN_TIMEOUT_SECONDS,
        )
    except TimeoutExpired:
        log.write_text(f"scan timed out after {SCAN_TIMEOUT_SECONDS}s\n", encoding="utf-8")
        return []
    log.write_text(f"{completed.stdout}\n{completed.stderr}", encoding="utf-8")
    if not output.is_file():
        return []
    payload = load(output.open(encoding="utf-8"))
    return payload if isinstance(payload, list) else [payload]


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Scan every lab and print one scored row per fixture."""
    parser = ArgumentParser(description="Scan the lab fixtures and score false positives and false negatives")
    parser.add_argument("--only", action="append", default=[], help="Run only these lab slugs (repeatable)")
    parser.add_argument("--manifest", type=str, default=str(MANIFEST), help="Path to the ground truth manifest")
    parser.add_argument("--dry-run", action="store_true", help="List the labs without scanning them")
    parser.add_argument("--reuse", action="store_true", help="Score the saved JSON of the last run instead of scanning")
    parser.add_argument("--json", type=str, help="Write the outcome of every lab as JSON to this path")
    args = parser.parse_args(argv)

    all_labs = load_labs(Path(args.manifest))
    selected = [lab for lab in all_labs if not args.only or lab.slug in args.only]
    if not selected:
        print("No lab matches the filter.")
        return 2

    if args.dry_run:
        for lab in selected:
            extras = " ".join(lab.extra_args)
            print(f"{lab.slug:32} level={lab.level} query={lab.query or '-'} {extras}".rstrip())
        print(f"{len(selected)} lab(s), nothing executed")
        return 0

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    outcomes: List[Outcome] = []
    with serve(LABS_DIR) as base_url:
        for lab in selected:
            outcome = evaluate(lab, scan(lab, base_url, reuse=args.reuse))
            outcomes.append(outcome)
            status = "PASS" if outcome.passed else "FAIL"
            details: List[str] = []
            if outcome.missing:
                details.append(f"FN={outcome.missing}")
            if outcome.unexpected:
                details.append(f"FP={outcome.unexpected}")
            print(f"{status}  {lab.slug:32} {' '.join(details)}".rstrip())

    passed = sum(1 for outcome in outcomes if outcome.passed)
    negatives = sum(len(outcome.missing) for outcome in outcomes)
    positives = sum(len(outcome.unexpected) for outcome in outcomes)
    print(
        f"\n{len(outcomes)} lab(s), {passed} passed, {len(outcomes) - passed} failed, "
        f"{negatives} false negative(s), {positives} false positive(s)"
    )

    if args.json:
        destination = Path(args.json)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8") as handle:
            dump([asdict(outcome) for outcome in outcomes], handle, indent=2)
        print(f"Results written to {destination}")

    return 0 if passed == len(outcomes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
