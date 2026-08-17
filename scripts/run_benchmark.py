"""Run a deterministic, controlled tampering benchmark."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import shutil
import sys
import tempfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from file_integrity_monitor.core import create_baseline, scan_against_baseline

FIXTURE_COUNT = 500
EXPECTED = {"added": 10, "modified": 20, "deleted": 10, "moved": 5}


def _content(index: int, marker: str = "A") -> str:
    return f"fixture-{index:04d}-" + marker * 128


def run() -> dict[str, object]:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "monitored"
        root.mkdir()
        for index in range(FIXTURE_COUNT):
            (root / f"file-{index:04d}.txt").write_text(_content(index), encoding="utf-8")

        baseline = create_baseline(root)

        for index in range(20):
            (root / f"file-{index:04d}.txt").write_text(_content(index, "B"), encoding="utf-8")
        for index in range(20, 30):
            (root / f"file-{index:04d}.txt").unlink()
        moved_directory = root / "moved"
        moved_directory.mkdir()
        for index in range(30, 35):
            shutil.move(
                root / f"file-{index:04d}.txt",
                moved_directory / f"renamed-{index:04d}.txt",
            )
        for index in range(10):
            (root / f"added-{index:04d}.txt").write_text(f"new-{index}", encoding="utf-8")

        report = scan_against_baseline(baseline)
        detected = {name: int(report["summary"][name]) for name in EXPECTED}
        expected_total = sum(EXPECTED.values())
        detected_total = sum(detected.values())
        passed = detected == EXPECTED

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "fixture_files": FIXTURE_COUNT,
            "hash_algorithm": "sha256",
            "expected_events": EXPECTED,
            "detected_events": detected,
            "expected_total": expected_total,
            "detected_total": detected_total,
            "detection_rate_percent": round((detected_total / expected_total) * 100, 2),
            "passed": passed,
            "baseline_duration_seconds": baseline["summary"]["duration_seconds"],
            "scan_duration_seconds": report["summary"]["duration_seconds"],
            "scan_errors": report["summary"]["errors"],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "results" / "tampering-benchmark.json"),
        help="Destination JSON file",
    )
    args = parser.parse_args()
    result = run()
    destination = Path(args.output).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    print(f"Saved to: {destination}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
