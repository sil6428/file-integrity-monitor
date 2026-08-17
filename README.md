# File Integrity Monitor

A small Python security project that records trusted SHA-256 file hashes and reports later filesystem changes. It is designed to make the core idea behind file integrity monitoring easy to inspect and reproduce.

## What it detects

- Added files
- Modified files, including same-size content changes
- Deleted files
- Moved or renamed files when the SHA-256 content hash remains the same
- Files that could not be read during a scan

The monitor ignores symbolic links and common development artifacts by default. Additional glob patterns can be supplied from the command line.

## Installation

Python 3.11 or newer is required. The runtime uses only the Python standard library.

```powershell
python -m pip install -e .
```

## Create a trusted baseline

```powershell
fim baseline C:\path\to\monitored-folder --output baseline.json
```

Add an exclusion when needed:

```powershell
fim baseline C:\path\to\monitored-folder --output baseline.json --exclude "logs/**"
```

## Scan for changes

```powershell
fim scan baseline.json --output report.json
```

Exit codes make the command usable in simple scripts:

- `0`: scan completed and no changes were found
- `1`: configuration, read, or scan error
- `2`: one or more integrity changes were found

## Tests

```powershell
python -m unittest discover -s tests -v
```

The test suite covers exclusions, clean scans, additions, content changes, deletions, moves, same-size tampering, JSON round trips, and command exit codes.

## Controlled benchmark

```powershell
python scripts/run_benchmark.py
```

The benchmark creates 500 temporary fixture files, applies 45 controlled events, and compares detected counts with expected counts:

- 20 modified files
- 10 deleted files
- 5 moved files
- 10 added files

The generated evidence is written to `results/tampering-benchmark.json`.

The verified run on Python 3.12.13 detected all 45 expected events across 500 fixture files with zero scan errors. Seven automated tests also passed. Runtime measurements are recorded in the JSON evidence because they vary by computer and storage device.

## Security limitations

This project demonstrates integrity monitoring, not malware prevention.

- A trusted baseline must be created before monitoring begins.
- Anyone who can replace both the files and the baseline can bypass the comparison.
- Files can change while a user-space scan is reading them.
- Symbolic links are skipped rather than followed.
- Moves are inferred by matching identical hashes. When several files share the same content, the monitor pairs matching paths deterministically but cannot prove which file was renamed.
- There is no real-time kernel event collection or remote alert delivery.
- SHA-256 confirms content equality. It does not identify who changed a file or why.

For production use, protect the baseline separately, sign reports, restrict permissions, and combine integrity checks with centralized logging and endpoint monitoring.
