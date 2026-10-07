#!/usr/bin/env python3
"""Local HTTP server for the lab fixtures and the CLI matrix.

Serves a directory on 127.0.0.1 and, when a record file is given, appends one
JSON line per request with its path and headers. That lets a test prove that
flags such as --user-agent and --cookie really reached the target.
"""

from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from json import dumps, loads
from pathlib import Path
from threading import Lock, Thread
from typing import Any, Dict, Iterator, List, Optional

_WRITE_LOCK = Lock()


def read_records(path: Path) -> List[Dict[str, Any]]:
    """Return the recorded requests in arrival order."""
    if not path.is_file():
        return []
    records: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(loads(line))
    return records


class RecordingHandler(SimpleHTTPRequestHandler):
    """Static file handler that records every request."""

    record_file: Optional[Path] = None

    def do_GET(self) -> None:  # noqa: N802 - the base class fixes this name
        if self.record_file is not None:
            entry = {
                "path": self.path,
                "headers": {key.lower(): value for key, value in self.headers.items()},
            }
            line = dumps(entry) + "\n"
            # ThreadingHTTPServer serves requests in parallel: without the lock
            # two writers interleave and every later line fails to parse.
            with _WRITE_LOCK:
                with self.record_file.open("a", encoding="utf-8") as handle:
                    handle.write(line)
        super().do_GET()

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the default stderr logging."""


@contextmanager
def serve(
    directory: Path,
    port: int = 0,
    record_file: Optional[Path] = None,
) -> Iterator[str]:
    """Serve a directory on 127.0.0.1 and yield the base URL.

    Port 0 lets the operating system pick a free port, so cases never collide.
    """
    handler_class = type("BoundRecordingHandler", (RecordingHandler,), {"record_file": record_file})
    httpd = ThreadingHTTPServer(
        ("127.0.0.1", port),
        partial(handler_class, directory=str(directory)),
    )
    thread = Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
