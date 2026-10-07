"""Pytest configuration: makes the repository root importable for the test suite."""

from pathlib import Path
from sys import path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in path:
    path.insert(0, str(ROOT))
