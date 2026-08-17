from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from file_integrity_monitor.cli import main
from file_integrity_monitor.core import (
    create_baseline,
    load_baseline,
    scan_against_baseline,
    write_json,
)


class IntegrityMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "monitored"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, content: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_baseline_is_deterministic_and_respects_excludes(self) -> None:
        self.write("b.txt", "bravo")
        self.write("a.txt", "alpha")
        self.write("cache.tmp", "ignored")
        self.write("private/secret.txt", "ignored")

        baseline = create_baseline(self.root, ["private/**"])

        self.assertEqual(list(baseline["entries"]), ["a.txt", "b.txt"])
        self.assertEqual(baseline["summary"]["files"], 2)
        self.assertEqual(baseline["summary"]["errors"], 0)

    def test_clean_scan_reports_no_changes(self) -> None:
        self.write("document.txt", "trusted")
        baseline = create_baseline(self.root)

        report = scan_against_baseline(baseline)

        self.assertEqual(report["summary"]["changed"], 0)
        self.assertEqual(report["summary"]["unchanged"], 1)

    def test_detects_added_modified_and_deleted_files(self) -> None:
        self.write("modified.txt", "before")
        self.write("deleted.txt", "remove me")
        baseline = create_baseline(self.root)

        self.write("modified.txt", "after")
        (self.root / "deleted.txt").unlink()
        self.write("added.txt", "new")
        report = scan_against_baseline(baseline)

        self.assertEqual(report["summary"]["added"], 1)
        self.assertEqual(report["summary"]["modified"], 1)
        self.assertEqual(report["summary"]["deleted"], 1)
        self.assertEqual(report["summary"]["moved"], 0)
        self.assertEqual(report["summary"]["changed"], 3)

    def test_detects_a_move_without_double_counting(self) -> None:
        original = self.write("old/location.txt", "same content")
        baseline = create_baseline(self.root)
        destination = self.root / "new/location.txt"
        destination.parent.mkdir(parents=True)
        original.rename(destination)

        report = scan_against_baseline(baseline)

        self.assertEqual(report["summary"]["moved"], 1)
        self.assertEqual(report["summary"]["added"], 0)
        self.assertEqual(report["summary"]["deleted"], 0)
        self.assertEqual(report["changes"]["moved"][0]["from"], "old/location.txt")
        self.assertEqual(report["changes"]["moved"][0]["to"], "new/location.txt")

    def test_hash_detects_same_size_tampering(self) -> None:
        path = self.write("same-size.bin", "AAAA")
        baseline = create_baseline(self.root)
        path.write_text("BBBB", encoding="utf-8")

        report = scan_against_baseline(baseline)

        change = report["changes"]["modified"][0]
        self.assertEqual(change["before_size"], change["after_size"])
        self.assertNotEqual(change["before_sha256"], change["after_sha256"])

    def test_baseline_round_trip(self) -> None:
        self.write("record.txt", "evidence")
        destination = Path(self.temporary.name) / "baseline.json"
        baseline = create_baseline(self.root)

        write_json(baseline, destination)
        loaded = load_baseline(destination)

        self.assertEqual(loaded["entries"], baseline["entries"])
        self.assertEqual(loaded["algorithm"], "sha256")

    def test_cli_exit_codes_distinguish_clean_and_changed_scans(self) -> None:
        self.write("watched.txt", "trusted")
        baseline_path = Path(self.temporary.name) / "baseline.json"
        report_path = Path(self.temporary.name) / "report.json"

        with redirect_stdout(io.StringIO()):
            baseline_exit = main(["baseline", str(self.root), "--output", str(baseline_path)])
            clean_exit = main(["scan", str(baseline_path), "--output", str(report_path)])
        self.write("watched.txt", "tampered")
        with redirect_stdout(io.StringIO()):
            changed_exit = main(["scan", str(baseline_path), "--output", str(report_path)])

        self.assertEqual(baseline_exit, 0)
        self.assertEqual(clean_exit, 0)
        self.assertEqual(changed_exit, 2)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["modified"], 1)


if __name__ == "__main__":
    unittest.main()
