"""Small SHA-256 file integrity monitor."""

from .core import (
    DEFAULT_EXCLUDES,
    create_baseline,
    load_baseline,
    scan_against_baseline,
    write_json,
)

__all__ = [
    "DEFAULT_EXCLUDES",
    "create_baseline",
    "load_baseline",
    "scan_against_baseline",
    "write_json",
]

__version__ = "1.0.0"
