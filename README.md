<div align="center">
  <h1>File Integrity Monitor</h1>
  <p><strong>Create a trusted SHA-256 baseline, scan again, and produce deterministic evidence of filesystem changes.</strong></p>
  <p>A dependency-free Python security tool with a script-friendly CLI and a local browser dashboard.</p>

  <p>
    <a href="https://github.com/sil6428/file-integrity-monitor/actions/workflows/quality.yml"><img alt="Quality checks" src="https://github.com/sil6428/file-integrity-monitor/actions/workflows/quality.yml/badge.svg"></a>
    <img alt="Python 3.11 or newer" src="https://img.shields.io/badge/Python-3.11%2B-3776ab?logo=python&amp;logoColor=white">
    <img alt="Standard library runtime" src="https://img.shields.io/badge/Runtime-Standard_library_only-0f766e">
  </p>

  <p>
    <a href="docs/sample-report.json">Sample evidence</a> ·
    <a href="results/tampering-benchmark.json">Benchmark result</a> ·
    <a href="LICENSE">Licence</a>
  </p>
</div>

## What it detects

- **Added files**
- **Modified files**, including same-size content changes
- **Deleted files**
- **Moved or renamed files** when the SHA-256 content hash remains the same
- **Read failures** that prevented a complete scan

Symbolic links and common development artifacts are ignored by default. Additional exclusion globs can be supplied from the command line.

## How it works

```text
Chosen directory
      ↓ hash readable regular files
Trusted baseline.json
      ↓ compare a later inventory
Deterministic report.json
      ↓
Added · modified · deleted · moved · errors
```

Reports include paths, SHA-256 values, byte sizes, summary counts, the baseline timestamp, and scan errors. Entries are sorted before serialization so repeated runs are easy to inspect and diff.

## Use the local dashboard

Requires Python 3.11 or newer.

```powershell
git clone https://github.com/sil6428/file-integrity-monitor.git
cd file-integrity-monitor
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
fim dashboard
```

**Integrity Desk** opens at `http://127.0.0.1:8765`. Choose the directory to monitor, select where the baseline and report should be saved, and review changes by category.

- The dashboard binds only to the local computer.
- It does not upload monitored files or scan results.
- Every write action requires a random token created for that dashboard session.
- It presents the same deterministic evidence as the CLI.

## Use the CLI

Create a trusted baseline:

```powershell
fim baseline C:\path\to\monitored-folder --output baseline.json
```

Add an exclusion when needed:

```powershell
fim baseline C:\path\to\monitored-folder --output baseline.json --exclude "logs/**"
```

Scan for changes:

```powershell
fim scan baseline.json --output report.json
```

Exit codes make the scan usable in automation:

| Code | Meaning |
| --- | --- |
| `0` | Scan completed with no detected changes |
| `1` | Configuration, read, or scan error |
| `2` | One or more integrity changes were detected |

## Verified evidence

### Automated tests

```powershell
python -m unittest discover -s tests -v
```

The nine-test suite covers exclusions, clean scans, additions, content changes, deletions, moves, same-size tampering, JSON round trips, dashboard safeguards, and command exit codes.

### Controlled tampering benchmark

```powershell
python scripts/run_benchmark.py
```

The verified benchmark created **500** fixture files, applied **45** controlled events, and detected every expected change with **zero scan errors**:

| Change | Expected | Detected |
| --- | ---: | ---: |
| Modified | 20 | 20 |
| Deleted | 10 | 10 |
| Moved | 5 | 5 |
| Added | 10 | 10 |

Machine-readable evidence is stored in [`results/tampering-benchmark.json`](results/tampering-benchmark.json). A smaller example showing each change type is available in [`docs/sample-report.json`](docs/sample-report.json).

## Security boundaries

This project demonstrates integrity monitoring; it is not malware prevention or endpoint detection.

- The baseline must be created while the files are trusted.
- Someone who can replace both the monitored files and the baseline can bypass the comparison.
- Files may change while a user-space scan is reading them.
- Symbolic links are skipped rather than followed.
- Moves are inferred from matching content hashes; identical files cannot prove which path was renamed.
- SHA-256 confirms content equality, not who made a change or why.
- There is no kernel-level real-time collection or remote alert delivery.

For a production design, protect the baseline separately, sign reports, restrict permissions, and forward evidence to centralized logging.

## Development

### Repository map

| Path | Purpose |
| --- | --- |
| `src/file_integrity_monitor/core.py` | Directory walking, hashing, comparison, and deterministic move inference |
| `src/file_integrity_monitor/cli.py` | Argument validation, evidence writing, summaries, and exit codes |
| `src/file_integrity_monitor/web.py` | Loopback-only Integrity Desk dashboard |
| `tests/test_monitor.py` | Core, CLI, dashboard, evidence, and error-path coverage |
| `scripts/run_benchmark.py` | Reproducible controlled-change benchmark |
| `docs/sample-report.json` | Compact example of the evidence format |

The runtime uses only the Python standard library.

## Status and licence

Version 1.1.0 is a portfolio and learning release. It is useful for controlled local monitoring and evidence generation, with the limitations above kept explicit.

Copyright © 2026 Affan Shaikh. All rights reserved. The source is public for portfolio review. See [`LICENSE`](LICENSE).
