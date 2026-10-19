# SVN Release Uploader

A local web application for reviewing a `Codedrop` release (for example, `Codedrop8` or `Codedrop10`) before committing it to SVN. The app uses Flask, SQLite, Apache Subversion's open-source command-line client, openpyxl, pefile, and Pillow.

## Requirements

- Python 3.10 or newer
- Apache Subversion command-line client (`svn.exe`) on `PATH`
- A reachable SVN repository with read access to earlier code drops and write access to the destination

Install and run from this folder in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. If `svn.exe` is not on `PATH`, set `SVN_EXECUTABLE` to its full path before starting the app. The server binds to loopback only; do not expose this unauthenticated first-version application to a network.

## Workflow

1. Enter either the remote SVN repository parent URL containing earlier `Codedrop##` releases or an existing absolute local folder path containing those releases, then upload the release ZIP. SVN credentials are required only for repository URLs, passed to SVN commands for this review, and not stored. Local-folder comparisons are read-only and do not require SVN metadata.
2. The app lists earlier code drops from the remote SVN URL, newest-first, from `Codedrop##/` folders, `Codedrop##.zip` archives, and qualifying ZIPs nested inside historical folders (named for a code drop or containing a `Codedrop##/` folder). Archives are safely extracted into the session workspace and never changed in SVN. It resolves a detailed baseline separately for every component, includes components removed entirely from the new ZIP, and selects the latest matching baseline by default. Both Excel reports include file-by-file comparisons against every earlier code drop found. A `Release Coverage` sheet also reports each component's coverage for the five immediately preceding numbered drops and explicitly marks unavailable releases or missing components.
3. Review the binary comparison and mark it reviewed. The on-screen comparison uses the selected baseline and omits files that exist only in the baseline. EXE/DLL file versions are read from PE version resources; files without one show `N/A`. A dash means that side has no matching file. Hashes detect rebuilds with unchanged versions, and lower versions are flagged. The `All Release Comparisons` report tab compares files against every discovered historical drop, excluding files missing from the current release.
4. Review the config changes list. The page shows only current new/changed files (plus files with JSON validation issues); unchanged files and files present only in an earlier release are omitted from the UI and Excel reports. JSON gets semantic key changes and a redacted optional line diff; non-JSON files are compared by SHA-256 without exposing content. JSON values under secret-like keys are masked in UI and reports.
5. If the uploaded ZIP has no `Binaries/` or `Configs/` folder, that review cannot run. The UI explains which check is unavailable and asks you to confirm skipping it. A missing `Configs/` folder means dummy scanning did not run; it is never reported as a clean scan. The release checklist requires explicit confirmation before approval. If configs are present, upload a fresh Configs ZIP for final validation and scanning; blockers prevent upload and warnings must be acknowledged.
6. Download the complete `Release-Review.zip` bundle on the final review step. It contains both detailed Excel workbooks and a short release summary. Individual `Binaries.xlsx` and `Configs.xlsx` downloads remain available.

Reports are generated as `Binaries.xlsx`, `Configs.xlsx`, and `Release-Review.zip`. The bundle contains both workbooks plus review notes. Each workbook contains an `All Release Comparisons` sheet with file statuses and SHA-256 values for earlier drops found, excluding files missing from the current release; the config report also includes JSON key-change counts where both versions parse. Each report's `Release Coverage` sheet lists the five immediately preceding numbered drops per component, including gaps and components missing from otherwise available releases. Binary version history covers every earlier drop found for each component, plus the current release, including EXE and DLL files. Historical versions and hashes are cached in SQLite and populated once per drop. Scan and approval actions are recorded in the audit log. The folder hash is verified again immediately before SVN import.

## SVN credentials and safety

Credentials are accepted only for the current SVN operation and are never saved to SQLite or Subversion's auth cache. Passwords are passed to Subversion using its `--password-from-stdin` option. Configure the repository's certificate trust using normal Subversion client settings; the application does not disable certificate checks. SVN targets must not contain credentials in the URL, and a destination code-drop folder that already exists is rejected.

Install a Subversion 1.12+ client if password authentication is needed (for `--password-from-stdin`). The application invokes `svn list`, `svn export`, and `svn import`; an SVN failure is shown in the UI rather than treated as success.

## Input format

A ZIP may contain a top-level `Codedrop##` folder or the release contents at the archive root. At least one of `Binaries/` or `Configs/` is required. Example:

```text
Codedrop10/
  Binaries/TMACServer/TMACServer.exe
  Configs/TMACServer/app/template.json
```

JSON files receive strict syntax validation, semantic comparison, and dummy-value scanning. Duplicate JSON keys are reported as warnings. A UTF-8 BOM is accepted. Comments and trailing commas are rejected by the strict parser. Non-JSON config files are compared by SHA-256 and file status, but are not interpreted or scanned for dummy values.

## Dummy-value rules

Rules live in [`config/dummy_rules.json`](config/dummy_rules.json). Supported match types are `contains`, `wholeWord`, `exact`, and `regex`. Each rule sets `Blocker` or `Warning` severity and may include `enabled` and `component` fields. The shipped rules scan JSON values, not property names; empty values are not flagged based on key names. Files named `template.json` are excluded from dummy-value matching because they contain configuration-key references; JSON values in `TMC_Data.json` and other config files are scanned. All current-release JSON files are syntax-validated, and selected component baseline files are checked for parse errors when compared. Validation details identify the release, file, line, and column; unrelated historical releases are not reported as JSON validation errors. Findings identify the release and current file containing the value, plus the selected baseline code drop and matching file (or indicate when no matching baseline file exists). `allowlist` entries accept `file`, `keyPath`, `pattern`, and an optional reason. The settings file is read and validated at scan time, and its SHA-256 is included in `Configs.xlsx`.

The admin editor for these rules, two-person approval, dashboard, dry-run mode, and notifications are intentionally left as later-phase features in the brainstorming document. The rules file itself is editable and validated at scan time.

## Validation

Run the automated tests with:

```powershell
python -m unittest discover -s tests -v
```
