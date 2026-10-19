# Release Uploader — Project Report

## Overview

Release Uploader is a local web application for reviewing numbered `Codedrop` releases before an SVN commit. It compares an uploaded release ZIP with earlier releases, checks binary versions, validates and compares configuration files, scans JSON values for configured dummy data, and generates Excel reports.

The comparison source can be either a remote SVN repository URL or an existing absolute local folder containing earlier code drops. Local-folder comparisons are read-only and do not require SVN metadata or credentials.

## Technology stack

| Area | Technology |
| --- | --- |
| Backend | Python 3.10+ and Flask |
| Frontend | HTML, CSS, and vanilla JavaScript |
| Database | SQLite |
| Source control integration | Apache Subversion command-line client (`svn.exe`) |
| Excel reports | openpyxl |
| Windows executable metadata | pefile |
| Report images | Pillow |
| Automated tests | Python `unittest` |

Python package requirements are listed in [`requirements.txt`](requirements.txt). Dummy-value scan rules are maintained in [`config/dummy_rules.json`](config/dummy_rules.json).

## Prerequisites

- Windows with PowerShell, or another environment capable of running Python and the Subversion CLI.
- Python 3.10 or newer.
- Network access and a reachable SVN repository when using a remote SVN URL.
- Apache Subversion client installed and `svn.exe` on `PATH` for remote comparisons and uploads. SVN 1.12+ is needed when password authentication uses `--password-from-stdin`.
- SVN read access to earlier releases for comparisons. SVN write access is needed only to commit a reviewed release.
- An existing local folder containing earlier `Codedrop##` folders or archives when running an offline/local comparison.
- A release ZIP containing at least one `Binaries/` or `Configs/` directory. A `Codedrop##` parent directory in the ZIP is optional.

## Installation and startup

Run these commands in PowerShell from the project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000> in a browser. If `svn.exe` is not on `PATH`, configure `SVN_EXECUTABLE` to the full path to the Subversion executable before starting the app.

The app is configured to bind to loopback. It is an unauthenticated local tool and should not be exposed to a network.

## Release input format

The upload is a ZIP file for a release named `Codedrop##` (for example, `Codedrop10`). The ZIP can include the release folder as its top-level directory or contain `Binaries/` and/or `Configs/` at its root.

```text
Codedrop10/
  Binaries/
    TMACServer/
      TMACServer.exe
  Configs/
    TMACServer/
      appsettings.json
```

The application supports an expanded ZIP size up to 2 GB. JSON files are parsed strictly: a UTF-8 BOM is accepted, while comments and trailing commas are rejected. Duplicate JSON object keys are reported. Non-JSON configuration files are compared using SHA-256; their contents are not interpreted by the dummy scan.

## Workflow

1. Enter an SVN parent URL or an absolute local path containing historical code drops.
2. For an SVN URL, provide SVN username and password. Credentials are required for remote repository operations only.
3. Select the `Codedrop##` folder name and upload the release ZIP.
4. The application discovers earlier numbered code drops, resolves component baselines, and analyzes the release.
5. Review binary comparisons and configuration changes, inspect the dummy-value scan, and confirm any review areas that are missing from the ZIP.
6. Download `Binaries.xlsx`, `Configs.xlsx`, or the complete `Release-Review.zip` report bundle.
7. For remote SVN targets, complete the review checklist and explicitly approve the upload before the application imports the release. Local-folder comparisons cannot be committed.

Missing files or components from earlier baselines are intentionally omitted from the website and Excel reports. This means the reports focus on files present in the current release; absence of an earlier file is not presented as a `Removed` row.

## Comparison and scan behavior

### Binaries

- EXE and DLL version resources are read when available.
- SHA-256 hashes identify changed/rebuilt files, including files whose embedded version did not change.
- Lower versions are flagged for review.
- Binary comparison workbooks include baseline comparisons, version history, historical comparisons, and release coverage.

### Configurations

- Current configuration files are compared with the selected baseline for their component.
- JSON files receive semantic key comparison and a masked line-by-line diff.
- Secret-like JSON values are masked in displayed differences and reports.
- Non-JSON files receive file-level SHA-256 comparison.
- Files that exist only in an earlier release are omitted from the UI and Excel output.

### Dummy-value scan

The scan checks JSON configuration values against rules in `config/dummy_rules.json`. It can report blockers and warnings. Invalid JSON prevents a complete scan; without a `Configs/` directory the scan is skipped and is not considered a pass. Blockers prevent upload, and warnings must be acknowledged.

## Generated reports and stored data

- **`Binaries.xlsx`** — binary comparison, version history, historical comparisons, and release coverage. It does not include a separate Baselines worksheet.
- **`Configs.xlsx`** — configuration summaries and diffs, validation issues, dummy findings, historical comparisons, and release coverage.
- **`Release-Review.zip`** — both workbooks and a short release review summary.

SQLite stores session state, audit events, baseline/version indexes, and cached binary metadata. Work files and generated reports are kept under the configured instance workspace, normally `instance/`.

## Security notes

- SVN credentials are supplied only for the current operation and are not stored in SQLite or Subversion's authentication cache.
- Passwords are passed to Subversion through standard input when supported by the installed client.
- SVN certificate checks are not disabled by the application; configure trust using the normal Subversion client settings.
- SVN URLs must not contain embedded username or password credentials.
- The application rejects upload when the destination code-drop folder already exists.
- The application binds to localhost by default. Do not expose this unauthenticated tool to untrusted users or networks.

## Testing

Run the automated workflow tests from the project directory:

```powershell
python -m unittest discover -s tests -v
```
