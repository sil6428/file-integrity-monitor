"""Command-line interface for the file integrity monitor."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .core import create_baseline, load_baseline, scan_against_baseline, write_json


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="Create SHA-256 file baselines and report integrity changes.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline = subparsers.add_parser("baseline", help="Create a trusted baseline")
    baseline.add_argument("root", help="Directory to monitor")
    baseline.add_argument("--output", default="fim-baseline.json", help="Baseline JSON path")
    baseline.add_argument("--exclude", action="append", default=[], help="Additional glob to ignore")

    scan = subparsers.add_parser("scan", help="Compare files with a baseline")
    scan.add_argument("baseline", help="Baseline JSON path")
    scan.add_argument("--root", help="Optional directory override")
    scan.add_argument("--output", default="fim-report.json", help="Report JSON path")
    scan.add_argument("--exclude", action="append", default=[], help="Additional glob to ignore")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "baseline":
            baseline = create_baseline(args.root, args.exclude)
            destination = write_json(baseline, args.output)
            summary = baseline["summary"]
            print(
                f"Baseline created: {summary['files']} files, "
                f"{summary['bytes']} bytes, {summary['errors']} errors"
            )
            print(f"Saved to: {destination}")
            return 0 if summary["errors"] == 0 else 1

        baseline = load_baseline(args.baseline)
        report = scan_against_baseline(baseline, args.root, args.exclude)
        destination = write_json(report, args.output)
        summary = report["summary"]
        print(
            "Integrity scan: "
            f"{summary['added']} added, {summary['modified']} modified, "
            f"{summary['deleted']} deleted, {summary['moved']} moved, "
            f"{summary['errors']} errors"
        )
        print(f"Saved to: {destination}")
        if summary["errors"]:
            return 1
        return 2 if summary["changed"] else 0
    except ValueError as error:
        print(f"Error: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
