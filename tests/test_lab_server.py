"""Tests for the local lab server used by the CLI matrix and the lab runner."""

from pathlib import Path
from urllib.request import urlopen
from tools.lab_server import read_records, serve


def test_records_every_request(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<html><body>lab</body></html>", encoding="utf-8")
    record_file = tmp_path / "requests.jsonl"

    with serve(tmp_path, record_file=record_file) as base:
        with urlopen(base, timeout=10) as response:
            assert response.status == 200
            assert b"lab" in response.read()

    records = read_records(record_file)
    assert len(records) == 1
    assert records[0]["path"] == "/"
    assert "user-agent" in records[0]["headers"]


def test_a_missing_record_file_reads_as_empty(tmp_path: Path) -> None:
    assert read_records(tmp_path / "absent.jsonl") == []


def test_server_uses_a_free_port_per_run(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<html><body>lab</body></html>", encoding="utf-8")
    first = None
    with serve(tmp_path) as base:
        first = base
        assert base.startswith("http://127.0.0.1:")
    with serve(tmp_path) as second:
        assert first != second
