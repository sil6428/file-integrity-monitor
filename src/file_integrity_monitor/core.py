"""Baseline creation and file-integrity comparison logic."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import hashlib
import json
import os
from pathlib import Path
from time import perf_counter
from typing import Any, Iterable

SCHEMA_VERSION = 1
HASH_ALGORITHM = "sha256"
READ_CHUNK_SIZE = 1024 * 1024

DEFAULT_EXCLUDES = (
    ".git",
    ".git/**",
    "__pycache__",
    "__pycache__/**",
    "*.pyc",
    "*.tmp",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalize_patterns(patterns: Iterable[str] | None) -> tuple[str, ...]:
    values = list(DEFAULT_EXCLUDES)
    if patterns:
        values.extend(pattern.strip().replace("\\", "/") for pattern in patterns if pattern.strip())
    return tuple(dict.fromkeys(values))


def _is_excluded(relative_path: Path, patterns: tuple[str, ...]) -> bool:
    candidate = relative_path.as_posix()
    name = relative_path.name
    for pattern in patterns:
        normalized = pattern.rstrip("/")
        if fnmatchcase(candidate, pattern) or fnmatchcase(name, pattern):
            return True
        if normalized and (candidate == normalized or candidate.startswith(f"{normalized}/")):
            return True
    return False


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(READ_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inventory(root: Path, patterns: tuple[str, ...]) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    entries: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, str]] = []

    for current_root, directory_names, file_names in os.walk(root):
        current = Path(current_root)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if not _is_excluded((current / name).relative_to(root), patterns)
            and not (current / name).is_symlink()
        )

        for file_name in sorted(file_names):
            path = current / file_name
            relative = path.relative_to(root)
            if _is_excluded(relative, patterns) or path.is_symlink():
                continue

            try:
                digest = _hash_file(path)
                stat = path.stat()
            except (OSError, PermissionError) as error:
                errors.append({"path": relative.as_posix(), "error": str(error)})
                continue

            entries[relative.as_posix()] = {
                "sha256": digest,
                "size": stat.st_size,
            }

    return dict(sorted(entries.items())), sorted(errors, key=lambda item: item["path"])


def create_baseline(root: str | Path, excludes: Iterable[str] | None = None) -> dict[str, Any]:
    """Create an in-memory baseline for every readable regular file under root."""
    started = perf_counter()
    root_path = Path(root).expanduser().resolve()
    if not root_path.is_dir():
        raise ValueError(f"Monitored root is not a directory: {root_path}")

    patterns = _normalize_patterns(excludes)
    entries, errors = _inventory(root_path, patterns)
    total_bytes = sum(int(entry["size"]) for entry in entries.values())

    return {
        "schema_version": SCHEMA_VERSION,
        "algorithm": HASH_ALGORITHM,
        "created_at": _utc_now(),
        "root": str(root_path),
        "excludes": list(patterns),
        "summary": {
            "files": len(entries),
            "bytes": total_bytes,
            "errors": len(errors),
            "duration_seconds": round(perf_counter() - started, 6),
        },
        "entries": entries,
        "errors": errors,
    }


def write_json(data: dict[str, Any], destination: str | Path) -> Path:
    """Write a baseline or report as deterministic, human-readable JSON."""
    destination_path = Path(destination).expanduser().resolve()
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    destination_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination_path


def load_baseline(path: str | Path) -> dict[str, Any]:
    """Load and validate a baseline JSON document."""
    baseline_path = Path(path).expanduser().resolve()
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Unable to load baseline {baseline_path}: {error}") from error

    if baseline.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"Unsupported baseline schema: {baseline.get('schema_version')!r}")
    if baseline.get("algorithm") != HASH_ALGORITHM:
        raise ValueError(f"Unsupported hash algorithm: {baseline.get('algorithm')!r}")
    if not isinstance(baseline.get("entries"), dict):
        raise ValueError("Baseline entries must be a JSON object")
    if not isinstance(baseline.get("root"), str):
        raise ValueError("Baseline root must be a string")
    return baseline


def _match_moves(
    added_paths: set[str],
    deleted_paths: set[str],
    current: dict[str, dict[str, Any]],
    previous: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[str], set[str]]:
    added_by_hash: dict[str, list[str]] = defaultdict(list)
    deleted_by_hash: dict[str, list[str]] = defaultdict(list)

    for path in added_paths:
        added_by_hash[str(current[path]["sha256"])].append(path)
    for path in deleted_paths:
        deleted_by_hash[str(previous[path]["sha256"])].append(path)

    moved: list[dict[str, Any]] = []
    unmatched_added = set(added_paths)
    unmatched_deleted = set(deleted_paths)
    for digest in sorted(set(added_by_hash) & set(deleted_by_hash)):
        new_paths = sorted(added_by_hash[digest])
        old_paths = sorted(deleted_by_hash[digest])
        for old_path, new_path in zip(old_paths, new_paths):
            moved.append(
                {
                    "from": old_path,
                    "to": new_path,
                    "sha256": digest,
                    "size": current[new_path]["size"],
                }
            )
            unmatched_added.discard(new_path)
            unmatched_deleted.discard(old_path)

    return moved, unmatched_added, unmatched_deleted


def scan_against_baseline(
    baseline: dict[str, Any],
    root: str | Path | None = None,
    excludes: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Compare current files with a previously generated baseline."""
    started = perf_counter()
    root_path = Path(root or baseline["root"]).expanduser().resolve()
    if not root_path.is_dir():
        raise ValueError(f"Monitored root is not a directory: {root_path}")

    baseline_patterns = baseline.get("excludes") or []
    patterns = _normalize_patterns([*baseline_patterns, *(excludes or [])])
    current, errors = _inventory(root_path, patterns)
    previous = baseline["entries"]

    current_paths = set(current)
    previous_paths = set(previous)
    common_paths = current_paths & previous_paths
    added_paths = current_paths - previous_paths
    deleted_paths = previous_paths - current_paths

    modified = [
        {
            "path": path,
            "before_sha256": previous[path]["sha256"],
            "after_sha256": current[path]["sha256"],
            "before_size": previous[path]["size"],
            "after_size": current[path]["size"],
        }
        for path in sorted(common_paths)
        if previous[path]["sha256"] != current[path]["sha256"]
    ]

    moved, unmatched_added, unmatched_deleted = _match_moves(
        added_paths, deleted_paths, current, previous
    )
    added = [
        {"path": path, **current[path]}
        for path in sorted(unmatched_added)
    ]
    deleted = [
        {"path": path, **previous[path]}
        for path in sorted(unmatched_deleted)
    ]

    summary = {
        "scanned_files": len(current),
        "unchanged": len(common_paths) - len(modified),
        "added": len(added),
        "modified": len(modified),
        "deleted": len(deleted),
        "moved": len(moved),
        "errors": len(errors),
    }
    summary["changed"] = summary["added"] + summary["modified"] + summary["deleted"] + summary["moved"]
    summary["duration_seconds"] = round(perf_counter() - started, 6)

    return {
        "schema_version": SCHEMA_VERSION,
        "algorithm": HASH_ALGORITHM,
        "generated_at": _utc_now(),
        "baseline_created_at": baseline["created_at"],
        "root": str(root_path),
        "summary": summary,
        "changes": {
            "added": added,
            "modified": modified,
            "deleted": deleted,
            "moved": moved,
        },
        "errors": errors,
    }
