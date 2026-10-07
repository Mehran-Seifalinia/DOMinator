"""Tests for the command line surface and the dry-run path."""

from asyncio import run
from io import BytesIO, TextIOWrapper
from pytest import CaptureFixture, MonkeyPatch, raises
from dominator import configure_console_encoding, main, normalize_url, parse_args, validate_timeout


def test_parses_targets_and_options(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "dominator.py",
            "-u", "http://127.0.0.1/", "http://127.0.0.1/a",
            "-l", "4",
            "-t", "3",
            "--max-depth", "2",
            "-r", "csv",
            "-o", "out.csv",
            "--dry-run",
        ],
    )
    args = parse_args()
    assert args.url == ["http://127.0.0.1/", "http://127.0.0.1/a"]
    assert args.level == 4
    assert args.threads == 3
    assert args.max_depth == 2
    assert args.report_format == "csv"
    assert args.output == "out.csv"
    assert args.dry_run is True
    assert args.visible is False


def test_default_values(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["dominator.py", "-u", "http://127.0.0.1/"])
    args = parse_args()
    assert args.level == 2
    assert args.threads == 1
    assert args.timeout == 10
    assert args.report_format == "json"
    assert args.dry_run is False
    assert args.no_external is False


def test_invalid_level_is_rejected(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["dominator.py", "-u", "http://127.0.0.1/", "-l", "9"])
    with raises(SystemExit):
        parse_args()


def test_validate_timeout() -> None:
    assert validate_timeout(5) == 5
    with raises(ValueError):
        validate_timeout(0)


def test_normalize_url_strips_only_the_fragment() -> None:
    assert normalize_url("http://127.0.0.1/a?b=1#frag") == "http://127.0.0.1/a?b=1"
    assert normalize_url("http://127.0.0.1/a") == "http://127.0.0.1/a"


def test_report_survives_a_legacy_code_page() -> None:
    buffer = BytesIO()
    stream = TextIOWrapper(buffer, encoding="cp1252")
    configure_console_encoding([stream])
    stream.write("fire \U0001f525 and lock \U0001f512")
    stream.flush()
    assert buffer.getvalue() == b"fire ? and lock ?"


def test_main_requires_a_target(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["dominator.py"])
    with raises(SystemExit):
        run(main())


def test_dry_run_never_touches_the_network(monkeypatch: MonkeyPatch, capsys: CaptureFixture) -> None:
    monkeypatch.setattr("sys.argv", ["dominator.py", "-u", "http://127.0.0.1:9/", "--dry-run", "-l", "3"])
    run(main())
    out = capsys.readouterr().out
    assert "Dry run" in out
    assert "http://127.0.0.1:9/" in out
    assert "Analysis level   : 3" in out
