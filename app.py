from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import uuid
import filecmp
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, abort, current_app, g, jsonify, render_template, request, send_file

from release_uploader import (
    WorkflowError,
    archived_code_drop_roots,
    extract_zip_contents,
    binary_version_details,
    compare_binaries,
    compare_release_history,
    config_diffs,
    extract_configs_zip,
    extract_zip,
    folder_hash,
    safe_url_child,
    scan_configs,
    svn_component_revision,
    svn_directory_entries,
    svn_export,
    svn_import,
    validate_configs,
    validate_folder_name,
    validate_svn_url,
)
from reporting import build_binaries_report, build_configs_report


ROOT = Path(__file__).resolve().parent
_SVN_MISSING_PATH_CODES = ("E160013", "E200009", "E170000")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _svn_path_is_missing(error: WorkflowError) -> bool:
    return any(code in str(error) for code in _SVN_MISSING_PATH_CODES)


def _comparison_target(value: str) -> tuple[str, str]:
    try:
        return validate_svn_url(value), "svn_url"
    except WorkflowError:
        candidate = Path(value.strip()).expanduser()
        if not candidate.is_absolute():
            raise
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise WorkflowError("The local folder path does not exist or cannot be accessed.") from error
        if not resolved.is_dir():
            raise WorkflowError("Use an SVN URL or an existing local folder path.")
        return str(resolved), "local_folder"


def _local_folder(value: str) -> Path | None:
    candidate = Path(value)
    if candidate.is_absolute() and candidate.is_dir():
        return candidate
    return None


def _add_finding_comparison_context(
    folder_name: str,
    findings: list[dict[str, Any]],
    configs: list[dict[str, Any]],
) -> None:
    configs_by_file = {config["file"]: config for config in configs}
    for finding in findings:
        config = configs_by_file.get(finding["file"])
        baseline = config.get("baseline") if config else None
        relative = finding["file"].split("/", 1)
        relative_inside_component = relative[1] if len(relative) == 2 else ""
        baseline_file = (
            f"{baseline['code_drop']}/{baseline['path']}/{relative_inside_component}"
            if baseline and relative_inside_component else None
        )
        baseline_exists = bool(
            baseline and config and config["status"] != "New"
        )
        finding.update({
            "release": folder_name,
            "current_file": f"{folder_name}/Configs/{finding['file']}",
            "baseline_code_drop": baseline["code_drop"] if baseline else None,
            "baseline_file": baseline_file,
            "baseline_file_exists": baseline_exists,
        })


def create_app(config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=str(Path(app.instance_path) / "release_uploader.sqlite3"),
        WORKSPACE=str(Path(app.instance_path) / "work"),
        RULES_FILE=str(ROOT / "config" / "dummy_rules.json"),
        MAX_CONTENT_LENGTH=2 * 1024**3,
        TESTING=False,
    )
    if config:
        app.config.update(config)
    executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="release-review")
    app.extensions["release_review_executor"] = executor
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["WORKSPACE"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    def connect_db() -> sqlite3.Connection:
        connection = sqlite3.connect(app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    connection = connect_db()
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                folder_name TEXT NOT NULL,
                target_url TEXT NOT NULL,
                source_url TEXT NOT NULL DEFAULT '',
                workdir TEXT NOT NULL,
                status TEXT NOT NULL,
                state_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS baseline_cache (
                base_url TEXT NOT NULL,
                code_drop TEXT NOT NULL,
                rel_path TEXT NOT NULL,
                present INTEGER NOT NULL,
                revision TEXT NOT NULL DEFAULT '',
                fetched_at TEXT NOT NULL,
                PRIMARY KEY (base_url, code_drop, rel_path)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                event TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS binary_version_cache (
                base_url TEXT NOT NULL,
                code_drop TEXT NOT NULL,
                component_path TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                revision TEXT NOT NULL DEFAULT '',
                version TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                PRIMARY KEY (base_url, code_drop, component_path, relative_path)
            );
            CREATE TABLE IF NOT EXISTS binary_version_index (
                base_url TEXT NOT NULL,
                code_drop TEXT NOT NULL,
                component_path TEXT NOT NULL,
                revision TEXT NOT NULL DEFAULT '',
                fetched_at TEXT NOT NULL,
                PRIMARY KEY (base_url, code_drop, component_path)
            );
            """
        )
    finally:
        connection.close()

    @app.teardown_appcontext
    def close_db(_error=None) -> None:
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    def db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = connect_db()
        return g.db

    def audit(session_id: str, event: str, detail: dict[str, Any]) -> None:
        db().execute(
            "INSERT INTO audit_log (session_id, event, detail_json, created_at) VALUES (?, ?, ?, ?)",
            (session_id, event, json.dumps(detail, ensure_ascii=False), _utc_now()),
        )
        db().commit()

    def get_session(session_id: str) -> sqlite3.Row:
        row = db().execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if row is None:
            abort(404, description="Release session not found.")
        return row

    def update_session(session_id: str, state: dict[str, Any], status: str | None = None) -> None:
        current = get_session(session_id)
        db().execute(
            "UPDATE sessions SET state_json = ?, status = ?, updated_at = ? WHERE id = ?",
            (
                json.dumps(state, ensure_ascii=False),
                status or current["status"],
                _utc_now(),
                session_id,
            ),
        )
        db().commit()

    def read_state(row: sqlite3.Row) -> dict[str, Any]:
        return json.loads(row["state_json"] or "{}")

    def public_state(state: dict[str, Any]) -> dict[str, Any]:
        result = json.loads(json.dumps(state))
        result.pop("source_root", None)
        for baseline in result.get("baselines", {}).values():
            baseline.pop("local_path", None)
        for group in result.get("baseline_options", {}).values():
            for baseline in group:
                baseline.pop("local_path", None)
        for row in result.get("binaries", []):
            row.pop("baseline_local_path", None)
        for config in result.get("configs", []):
            if config.get("baseline"):
                config["baseline"].pop("local_path", None)
        return result

    def component_paths(current_root: Path) -> list[str]:
        result = []
        for area in ("Binaries", "Configs"):
            directory = current_root / area
            if directory.is_dir():
                result.extend(
                    f"{area}/{path.name}"
                    for path in sorted(directory.iterdir())
                    if path.is_dir()
                )
        return result

    def release_content_root(root: Path, drop_name: str) -> Path:
        candidate = root
        while not any((candidate / area).is_dir() for area in ("Binaries", "Configs")):
            nested = candidate / drop_name
            if not nested.is_dir():
                break
            candidate = nested
        return candidate

    def resolve_baselines(
        session_id: str,
        current_root: Path,
        folder_name: str,
        target_url: str,
        username: str,
        password: str,
        previous: dict[str, Any] | None = None,
        overrides: dict[str, str] | None = None,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]], list[str]]:
        current_match = re.fullmatch(r"Codedrop(\d+)", folder_name, re.IGNORECASE)
        if not current_match:
            raise WorkflowError("Folder name must match Codedrop followed by a number (for example, Codedrop8 or Codedrop10).")
        current_number = int(current_match.group(1))
        local_root = _local_folder(target_url)
        old_baselines = (previous or {}).get("baselines", {})
        old_options = (previous or {}).get("baseline_options", {})
        overrides = overrides or {}
        current_paths = component_paths(current_root)
        session_dir = Path(get_session(session_id)["workdir"])
        reuse_index = bool(
            previous
            and previous.get("target_url") == target_url
            and all(rel_path in old_options for rel_path in current_paths)
            and all(
                "local_path" in choice
                for choices in old_options.values()
                for choice in choices
            )
        )
        if reuse_index:
            code_drops = []
        elif local_root:
            code_drops = []
            for path in local_root.iterdir():
                is_archive = path.is_file() and path.suffix.casefold() == ".zip"
                match = re.fullmatch(
                    r"(Codedrop\d+)(?:\.zip)?", path.name, re.IGNORECASE
                )
                if not match or not (path.is_dir() or is_archive):
                    continue
                if int(re.search(r"\d+", match.group(1)).group()) < current_number:
                    code_drops.append({
                        "name": match.group(1),
                        "entry_name": path.name,
                        "kind": "file" if is_archive else "dir",
                        "revision": "",
                        "local_root": str(path),
                    })
        else:
            code_drops = []
            for entry in svn_directory_entries(target_url, username, password):
                is_archive = entry["kind"] == "file" and entry["name"].casefold().endswith(".zip")
                match = re.fullmatch(
                    r"(Codedrop\d+)(?:\.zip)?", entry["name"], re.IGNORECASE
                )
                if not match or not (entry["kind"] == "dir" or is_archive):
                    continue
                if int(re.search(r"\d+", match.group(1)).group()) < current_number:
                    code_drops.append({
                        **entry,
                        "name": match.group(1),
                        "entry_name": entry["name"],
                    })
        direct_names = {drop["name"].casefold() for drop in code_drops}
        nested_archives = []
        if not reuse_index:
            directory_drops = [drop for drop in code_drops if drop["kind"] == "dir"]
            for parent_drop in directory_drops:
                if local_root:
                    parent_root = local_root / parent_drop["entry_name"]
                    archive_entries = [
                        (path, path.relative_to(parent_root).as_posix())
                        for path in parent_root.rglob("*")
                        if path.is_file() and path.suffix.casefold() == ".zip"
                    ]
                else:
                    parent_url = safe_url_child(target_url, parent_drop["entry_name"])
                    recursive_entries = svn_directory_entries(
                        parent_url, username, password, recursive=True
                    )
                    archive_entries = [
                        (None, entry["name"])
                        for entry in recursive_entries
                        if entry["kind"] == "file"
                        and entry["name"].casefold().endswith(".zip")
                    ]
                    has_wrapped_components = any(
                        entry["kind"] == "dir"
                        and any(
                            part.casefold() in {"binaries", "configs"}
                            and index > 0
                            and index + 1 < len(parts)
                            for index, part in enumerate(parts[:-1])
                        )
                        for entry in recursive_entries
                        for parts in [entry["name"].replace("\\", "/").strip("/").split("/")]
                    )
                    if has_wrapped_components:
                        parent_root = (
                            session_dir / "baseline-archives"
                            / f"{parent_drop['name']}-working-copy"
                        )
                        if parent_root.exists():
                            shutil.rmtree(parent_root)
                        svn_export(
                            parent_url, parent_root, "HEAD", username, password
                        )
                        parent_drop["archive_scan_root"] = str(parent_root)
                        parent_drop["local_root"] = str(
                            release_content_root(parent_root, parent_drop["name"])
                        )
                        archive_entries = [
                            (path, path.relative_to(parent_root).as_posix())
                            for path in parent_root.rglob("*")
                            if path.is_file() and path.suffix.casefold() == ".zip"
                        ]
                if local_root:
                    parent_drop["archive_scan_root"] = str(parent_root)
                    parent_drop["local_root"] = str(
                        release_content_root(parent_root, parent_drop["name"])
                    )
                for archive_path, relative_archive in archive_entries:
                    declared_match = re.fullmatch(
                        r"(Codedrop\d+)\.zip",
                        Path(relative_archive).name,
                        re.IGNORECASE,
                    )
                    staged_archive = archive_path or (
                        session_dir / "baseline-archives" / parent_drop["name"]
                        / Path(relative_archive)
                    )
                    if not local_root and archive_path is None:
                        staged_archive.parent.mkdir(parents=True, exist_ok=True)
                        svn_export(
                            safe_url_child(
                                target_url,
                                parent_drop["entry_name"],
                                *relative_archive.replace("\\", "/").split("/"),
                            ),
                            staged_archive,
                            "HEAD",
                            username,
                            password,
                        )
                    root_names = archived_code_drop_roots(
                        staged_archive,
                        declared_match.group(1) if declared_match else None,
                    )
                    extraction_name = (
                        f"{parent_drop['name']}-"
                        f"{Path(relative_archive).as_posix().replace('/', '_')}-contents"
                    )
                    try:
                        extracted_contents = extract_zip_contents(
                            staged_archive,
                            session_dir / "baseline-archives" / extraction_name,
                        )
                    except WorkflowError as error:
                        raise WorkflowError(
                            f"Could not inspect nested archive "
                            f"{parent_drop['name']}/{relative_archive}: {error}"
                        ) from error
                    for root_name in root_names:
                        normalized_name = root_name.casefold()
                        extracted_root = (
                            extracted_contents / root_name
                            if (extracted_contents / root_name).is_dir()
                            else extracted_contents
                        )
                        if normalized_name in direct_names:
                            existing = next(
                                item for item in code_drops
                                if item["name"].casefold() == normalized_name
                            )
                            if existing["kind"] != "dir":
                                continue
                            direct_root = (
                                Path(existing["local_root"])
                                if existing.get("local_root") else
                                local_root / existing["entry_name"]
                                if local_root else
                                session_dir / "baseline-archives"
                                / f"{existing['name']}-working-copy"
                            )
                            if not local_root and not direct_root.exists():
                                svn_export(
                                    safe_url_child(target_url, existing["entry_name"]),
                                    direct_root,
                                    "HEAD",
                                    username,
                                    password,
                                )
                            direct_root = release_content_root(
                                direct_root, existing["name"]
                            )
                            combined_root = (
                                session_dir / "baseline-archives"
                                / f"{existing['name']}-combined"
                            )
                            if combined_root.exists():
                                shutil.rmtree(combined_root)
                            combined_root.mkdir(parents=True)
                            for source_root in (direct_root, extracted_root):
                                for area in ("Binaries", "Configs"):
                                    source_area = source_root / area
                                    if not source_area.is_dir():
                                        continue
                                    for source_file in source_area.rglob("*"):
                                        if not source_file.is_file():
                                            continue
                                        relative_file = source_file.relative_to(source_root)
                                        target_file = combined_root / relative_file
                                        if target_file.is_file():
                                            if (
                                                target_file.stat().st_size != source_file.stat().st_size
                                                or not filecmp.cmp(
                                                    target_file, source_file, shallow=False
                                                )
                                            ):
                                                raise WorkflowError(
                                                    f"Nested archive {parent_drop['name']}/{relative_archive} "
                                                    f"conflicts with {existing['name']}/{relative_file.as_posix()}."
                                                )
                                            continue
                                        target_file.parent.mkdir(parents=True, exist_ok=True)
                                        shutil.copy2(source_file, target_file)
                            existing["kind"] = "archive"
                            existing["local_root"] = str(combined_root)
                            existing["revision"] = (
                                "local folder" if local_root else "archive"
                            )
                            continue
                        direct_names.add(normalized_name)
                        nested_archives.append({
                            "name": root_name,
                            "entry_name": f"{parent_drop['name']}/{relative_archive}",
                            "kind": "archive",
                            "revision": "local folder" if local_root else "archive",
                            "local_root": str(extracted_root),
                        })
            code_drops.extend(nested_archives)
        code_drops.sort(
            key=lambda item: int(re.search(r"\d+", item["name"]).group()),
            reverse=True,
        )
        seen_drops: set[str] = set()
        for drop in code_drops:
            normalized = drop["name"].casefold()
            if normalized in seen_drops:
                raise WorkflowError(
                    f"SVN comparison path contains both a folder and ZIP for {drop['name']}; "
                    "remove the duplicate or keep only one."
                )
            seen_drops.add(normalized)
            if drop["kind"] == "file":
                archive_path = Path(drop["local_root"]) if local_root else (
                    session_dir / "baseline-archives" / drop["entry_name"]
                )
                if not local_root:
                    archive_path.parent.mkdir(parents=True, exist_ok=True)
                    svn_export(
                        safe_url_child(target_url, drop["entry_name"]),
                        archive_path,
                        "HEAD",
                        username,
                        password,
                    )
                extracted = session_dir / "baseline-archives" / f"{drop['name']}-contents"
                try:
                    drop["local_root"] = str(extract_zip(archive_path, extracted))
                except WorkflowError as error:
                    raise WorkflowError(
                        f"Could not inspect archived baseline {drop['entry_name']}: {error}"
                    ) from error
                if not local_root:
                    drop["revision"] = drop.get("revision") or ""
        for drop in code_drops:
            if local_root and drop["kind"] == "dir" and not drop.get("local_root"):
                outer_root = local_root / drop["entry_name"]
                drop["archive_scan_root"] = str(outer_root)
                drop["local_root"] = str(
                    release_content_root(outer_root, drop["name"])
                )
        paths = set(current_paths)
        if reuse_index:
            paths.update(old_options)
        else:
            for drop in code_drops:
                drop_root = Path(drop["local_root"]) if (
                    local_root or drop.get("local_root")
                    or drop["kind"] in {"file", "archive"}
                ) else None
                for area in ("Binaries", "Configs"):
                    area_root = drop_root / area if drop_root else None
                    if area_root is not None:
                        if area_root.is_dir():
                            paths.update(
                                f"{area}/{entry.name}"
                                for entry in area_root.iterdir()
                                if entry.is_dir()
                            )
                        continue
                    area_url = safe_url_child(target_url, drop["name"], area)
                    try:
                        entries = svn_directory_entries(area_url, username, password)
                    except WorkflowError as error:
                        if _svn_path_is_missing(error):
                            continue
                        raise
                    paths.update(
                        f"{area}/{entry['name']}"
                        for entry in entries
                        if entry["kind"] == "dir"
                    )
        release_inventory = (previous or {}).get("release_inventory") or sorted(
            {
                choice["code_drop"]
                for choices in old_options.values()
                for choice in choices
            } | {drop["name"] for drop in code_drops},
            key=lambda name: int(re.search(r"\d+", name).group()),
            reverse=True,
        )
        baselines: dict[str, dict[str, Any]] = {}
        options: dict[str, list[dict[str, Any]]] = {}

        for rel_path in sorted(paths):
            area, component = rel_path.split("/", 1)
            choices = []
            if reuse_index:
                choices = [
                    {key: item[key] for key in (
                        "code_drop", "path", "revision", "local_path"
                    ) if key in item}
                    for item in old_options[rel_path]
                ]
            for drop in code_drops:
                candidate_path = (
                    Path(drop["local_root"]) / area / component
                    if local_root or drop.get("local_root")
                    or drop["kind"] == "file" else None
                )
                if local_root or drop.get("local_root") or drop["kind"] in {"file", "archive"}:
                    revision = (
                        "local folder" if local_root
                        else drop.get("revision") or "archive"
                    ) if candidate_path and candidate_path.is_dir() else None
                else:
                    cached = db().execute(
                        "SELECT present, revision FROM baseline_cache "
                        "WHERE base_url = ? AND code_drop = ? AND rel_path = ?",
                        (target_url, drop["name"], rel_path),
                    ).fetchone()
                    if cached is None:
                        area_url = safe_url_child(target_url, drop["name"], area)
                        try:
                            revision = svn_component_revision(area_url, component, username, password)
                        except WorkflowError as error:
                            if _svn_path_is_missing(error):
                                revision = None
                            else:
                                raise
                        db().execute(
                            "INSERT OR REPLACE INTO baseline_cache "
                            "(base_url, code_drop, rel_path, present, revision, fetched_at) VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                target_url, drop["name"], rel_path, int(revision is not None),
                                revision or "", _utc_now(),
                            ),
                        )
                        db().commit()
                    else:
                        revision = cached["revision"] if cached["present"] else None
                if revision is not None:
                    choice = {
                        "code_drop": drop["name"],
                        "path": rel_path,
                        "revision": revision,
                    }
                    if local_root or drop["kind"] in {"file", "archive"}:
                        choice["local_path"] = str(candidate_path)
                    else:
                        local_path = session_dir / "baselines" / drop["name"] / area / component
                        if not local_path.is_dir():
                            local_path.parent.mkdir(parents=True, exist_ok=True)
                            source_url = safe_url_child(
                                target_url, drop["entry_name"], area, component
                            )
                            try:
                                svn_export(source_url, local_path, "HEAD", username, password)
                            except WorkflowError as error:
                                if not _svn_path_is_missing(error):
                                    raise
                                db().execute(
                                    "INSERT OR REPLACE INTO baseline_cache "
                                    "(base_url, code_drop, rel_path, present, revision, fetched_at) "
                                    "VALUES (?, ?, ?, 0, '', ?)",
                                    (target_url, drop["name"], rel_path, _utc_now()),
                                )
                                db().commit()
                                continue
                        choice["local_path"] = str(local_path)
                    choices.append(choice)
            options[rel_path] = choices
            selected_name = overrides.get(rel_path)
            old = old_baselines.get(rel_path)
            if selected_name is None and old and any(
                item["code_drop"] == old["code_drop"] for item in choices
            ):
                selected_name = old["code_drop"]
            selected = next(
                (item for item in choices if item["code_drop"] == selected_name),
                choices[0] if choices else None,
            )
            if selected is None:
                continue
            baselines[rel_path] = {
                **selected,
            }
        return baselines, options, release_inventory

    def build_version_history(
        session_id: str,
        current_root: Path,
        folder_name: str,
        target_url: str,
        baselines: dict[str, dict[str, Any]],
        options: dict[str, list[dict[str, Any]]],
        username: str,
        password: str,
    ) -> tuple[list[str], list[dict[str, Any]]]:
        selected_drops: dict[str, list[str]] = {}
        release_names = set()
        for component_path, choices in options.items():
            if not component_path.startswith("Binaries/"):
                continue
            selected = [item["code_drop"] for item in choices]
            baseline = baselines.get(component_path, {}).get("code_drop")
            if baseline and baseline not in selected:
                selected.append(baseline)
            selected_drops[component_path] = selected
            release_names.update(selected)
        releases = sorted(
            release_names,
            key=lambda name: int(re.search(r"\d+", name).group()),
            reverse=True,
        )
        releases.append(folder_name)
        workdir = Path(get_session(session_id)["workdir"])
        local_root = _local_folder(target_url)
        history: list[dict[str, Any]] = []

        for component_path, drops in selected_drops.items():
            area, component = component_path.split("/", 1)
            current_component = current_root / area / component
            if not current_component.is_dir():
                continue
            current_executables = sorted(
                path for path in current_component.rglob("*")
                if path.is_file() and path.suffix.casefold() in {".exe", ".dll"}
            )
            for drop in drops:
                option = next(
                    item for item in options[component_path] if item["code_drop"] == drop
                )
                indexed = db().execute(
                    "SELECT 1 FROM binary_version_index "
                    "WHERE base_url = ? AND code_drop = ? AND component_path = ?",
                    (target_url, drop, component_path),
                ).fetchone()
                if indexed and not local_root and not option.get("local_path"):
                    continue
                baseline = baselines.get(component_path)
                reusable_baseline = bool(
                    baseline
                    and baseline["code_drop"] == drop
                    and Path(baseline["local_path"]).is_dir()
                )
                scratch = workdir / "version-index" / drop / component
                if not reusable_baseline and not local_root and not option.get("local_path"):
                    if scratch.exists():
                        shutil.rmtree(scratch)
                    scratch.parent.mkdir(parents=True, exist_ok=True)
                    url = safe_url_child(target_url, drop, area, component)
                try:
                    if option.get("local_path") and Path(option["local_path"]).is_dir():
                        source = Path(option["local_path"])
                    elif local_root:
                        source = local_root / drop / area / component
                    elif not reusable_baseline:
                        svn_export(url, scratch, "HEAD", username, password)
                        source = scratch
                    else:
                        source = Path(baseline["local_path"])
                    cached_files = []
                    for path in source.rglob("*"):
                        if path.is_file() and path.suffix.casefold() in {".exe", ".dll"}:
                            metadata = binary_version_details(path)
                            cached_files.append((
                                target_url,
                                drop,
                                component_path,
                                path.relative_to(source).as_posix(),
                                option["revision"],
                                metadata["version"],
                                metadata["sha256"],
                            ))
                    db().executemany(
                        "INSERT OR REPLACE INTO binary_version_cache "
                        "(base_url, code_drop, component_path, relative_path, revision, version, sha256) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        cached_files,
                    )
                    db().execute(
                        "INSERT OR REPLACE INTO binary_version_index "
                        "(base_url, code_drop, component_path, revision, fetched_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (target_url, drop, component_path, option["revision"], _utc_now()),
                    )
                    db().commit()
                finally:
                    if not local_root and not reusable_baseline and scratch.exists():
                        shutil.rmtree(scratch, ignore_errors=True)

            for executable in current_executables:
                relative = executable.relative_to(current_component).as_posix()
                current_version = binary_version_details(executable)["version"]
                versions = {}
                for drop in drops:
                    cached = db().execute(
                        "SELECT version FROM binary_version_cache "
                        "WHERE base_url = ? AND code_drop = ? AND component_path = ? AND relative_path = ?",
                        (target_url, drop, component_path, relative),
                    ).fetchone()
                    versions[drop] = cached["version"] if cached else "–"
                versions[folder_name] = current_version
                history.append({
                    "component": component,
                    "file": relative,
                    "baseline_drop": baselines.get(component_path, {}).get("code_drop", ""),
                    "versions": versions,
                })
        return releases, history

    def validate_structure(folder_name: str) -> list[dict[str, str]]:
        return [{
            "name": "Folder name matches Codedrop + number pattern",
            "passed": bool(re.fullmatch(r"Codedrop\d+", folder_name, re.IGNORECASE)),
        }]

    def build_report_bundle(report_dir: Path, folder_name: str, state: dict[str, Any]) -> None:
        bundle_path = report_dir / "Release-Review.zip"
        missing = set(state["areas_missing"])
        skipped = set(state.get("skipped_areas", []))
        pending = missing - skipped
        binary_status = (
            "included" if "Binaries" not in missing else
            "not included; skip confirmed" if "Binaries" in skipped else
            "not included; skip confirmation pending"
        )
        config_status = (
            "included" if "Configs" not in missing else
            "not included; skip confirmed" if "Configs" in skipped else
            "not included; skip confirmation pending"
        )
        notes = [
            f"Release review: {folder_name}",
            "",
            f"- Binary comparison: {binary_status}",
            f"- Config comparison: {config_status}",
            f"- Dummy scan: {state['config_scan_status']}",
            f"- Historical file comparisons: {state['historical_comparison_rows']}",
            "",
            "Included workbooks:",
            "- Binaries.xlsx: binary versions, history, baseline, and release coverage.",
            "- Configs.xlsx: config comparisons, validation, dummy scan, and release coverage.",
            "",
            (
                "Confirm missing review-area skips in the application before approval."
                if pending else "All missing review-area skips have been confirmed."
            ),
        ]
        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for report_name in ("Binaries.xlsx", "Configs.xlsx"):
                bundle.write(report_dir / report_name, report_name)
            bundle.writestr(f"{folder_name}-Review-Notes.txt", "\n".join(notes) + "\n")

    def analyze(
        session_id: str,
        row: sqlite3.Row,
        source_root: Path,
        username: str,
        password: str,
        previous: dict[str, Any] | None = None,
        overrides: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        folder_name = row["folder_name"]
        target_url, target_type = _comparison_target(row["target_url"])
        checks = validate_structure(folder_name)
        if not all(item["passed"] for item in checks):
            raise WorkflowError("The release folder name must use Codedrop followed by its number.")
        validation = validate_configs(source_root / "Configs") if (source_root / "Configs").is_dir() else {
            "checked": 0, "valid": 0, "failed": 0, "errors": [], "duplicates": [],
        }
        configs_present = (source_root / "Configs").is_dir()
        baselines, options, release_inventory = resolve_baselines(
            session_id, source_root, folder_name, target_url, username, password, previous, overrides
        )
        binaries = compare_binaries(source_root, baselines)
        historical_comparisons = compare_release_history(source_root, options)
        visible_historical_comparisons = [
            item for item in historical_comparisons
            if item["status"] != "Missing from current"
        ]
        current_number = int(re.search(r"\d+", folder_name).group())
        expected_releases = [
            f"Codedrop{number}"
            for number in range(current_number - 1, max(current_number - 6, 0), -1)
        ]
        available_releases = {name.casefold() for name in release_inventory}
        release_coverage = []
        for component_path, choices in sorted(options.items()):
            component_area, component_name = component_path.split("/", 1)
            by_release = {item["code_drop"].casefold(): item for item in choices}
            for expected_release in expected_releases:
                match = by_release.get(expected_release.casefold())
                if match:
                    comparison = "Compared"
                    compared_files = sum(
                        row["code_drop"] == match["code_drop"]
                        and row["area"] == component_area
                        and row["component"] == component_name
                        for row in historical_comparisons
                    )
                    details = f"{compared_files} file(s) compared."
                elif expected_release.casefold() in available_releases:
                    comparison = "Component not present in release"
                    details = "The release exists, but this component path was not found."
                else:
                    comparison = "Release unavailable"
                    details = "No matching release folder or ZIP was found under the SVN path."
                release_coverage.append({
                    "code_drop": expected_release,
                    "area": component_area,
                    "component": component_name,
                    "component_path": component_path,
                    "comparison": comparison,
                    "details": details,
                })
        history_releases, version_history = build_version_history(
            session_id, source_root, folder_name, target_url,
            baselines, options, username, password,
        )
        findings: list[dict[str, Any]] = []
        config_results: list[dict[str, Any]] = []
        rules_hash = ""
        config_results = config_diffs(source_root, baselines)
        baseline_validation_errors = []
        for config in config_results:
            issue = config.get("baseline_validation_error")
            baseline = config.get("baseline")
            if not issue or not baseline:
                continue
            baseline_validation_errors.append({
                **issue,
                "release": baseline["code_drop"],
                "source_file": (
                    f"{baseline['code_drop']}/Configs/{config['file']}"
                ),
            })
        if validation["failed"] == 0 and configs_present:
            findings, rules_hash = scan_configs(
                source_root / "Configs", Path(app.config["RULES_FILE"])
            )
            _add_finding_comparison_context(folder_name, findings, config_results)
        scan_status = (
            "not run: Configs directory missing"
            if not configs_present else
            "blocked: invalid JSON"
            if validation["failed"] else
            "completed"
        )
        hash_value = folder_hash(source_root)
        report_dir = Path(row["workdir"]) / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        build_binaries_report(
            report_dir / "Binaries.xlsx", folder_name, binaries,
            history_releases, version_history,
            historical_comparisons, release_coverage,
        )
        build_configs_report(
            report_dir / "Configs.xlsx", folder_name, config_results, findings, rules_hash,
            validation, configs_present, scan_status, historical_comparisons,
            release_coverage,
        )
        areas_missing = [
            area for area in ("Binaries", "Configs")
            if not (source_root / area).is_dir()
        ]
        state = {
            "folder_name": folder_name,
            "target_url": target_url,
            "target_type": target_type,
            "source_url": row["source_url"],
            "source_root": str(source_root),
            "structure_checks": checks,
            "areas_missing": areas_missing,
            "validation": validation,
            "baseline_validation_errors": baseline_validation_errors,
            "configs_present": configs_present,
            "config_scan_status": scan_status,
            "baselines": baselines,
            "baseline_options": options,
            "binaries": binaries,
            "history_releases": history_releases,
            "version_history": version_history,
            "historical_comparison_rows": len(visible_historical_comparisons),
            "historical_code_drops": sorted({
                item["code_drop"] for item in historical_comparisons
            }, key=lambda name: int(re.search(r"\d+", name).group()), reverse=True),
            "release_inventory": release_inventory,
            "release_coverage": release_coverage,
            "configs": config_results,
            "findings": findings,
            "rules_hash": rules_hash,
            "folder_hash": hash_value,
            "scanned_at": _utc_now(),
            "binary_reviewed": (previous or {}).get("binary_reviewed", False),
            "skipped_areas": [
                area for area in (previous or {}).get("skipped_areas", [])
                if area in areas_missing
            ],
            "acknowledged": (previous or {}).get("acknowledged", []),
            "scan_history": (previous or {}).get("scan_history", []),
            "rescan_completed": (
                configs_present and (previous or {}).get("rescan_completed", False)
            ),
            "upload": (previous or {}).get("upload"),
        }
        state["historical_comparison_rows"] = len(visible_historical_comparisons)
        build_report_bundle(report_dir, folder_name, state)
        if previous is None:
            state["scan_history"] = [{
                "scanned_at": state["scanned_at"],
                "folder_hash": hash_value,
                "findings": findings,
            }]
        return state

    def source_job(
        session_id: str,
        archive_path: str,
        username: str,
        password: str,
    ) -> None:
        with app.app_context():
            try:
                row = get_session(session_id)
                workdir = Path(row["workdir"])
                current_dir = workdir / "current"
                if current_dir.exists():
                    shutil.rmtree(current_dir)
                set_progress(session_id, "Extracting ZIP and validating the folder structure…")
                try:
                    source_root = extract_zip(
                        archive_path, current_dir, fallback_folder_name=row["folder_name"]
                    )
                finally:
                    Path(archive_path).unlink(missing_ok=True)
                folder_match = re.fullmatch(
                    r"Codedrop\d+", source_root.name, re.IGNORECASE
                )
                if folder_match and source_root.name.casefold() != row["folder_name"].casefold():
                    raise WorkflowError(
                        f"The source folder is named {source_root.name}, but the selected release name is {row['folder_name']}."
                    )
                set_progress(session_id, "Validating JSON and resolving component baselines in SVN…")
                state = analyze(session_id, row, source_root, username, password)
                update_session(
                    session_id, state,
                    "ready" if not state["validation"]["failed"] else "validation_failed",
                )
                audit(session_id, "source_analyzed", {
                    "mode": "zip",
                    "folder_hash": state["folder_hash"],
                    "json_checked": state["validation"]["checked"],
                    "json_failed": state["validation"]["failed"],
                })
            except WorkflowError as error:
                row = get_session(session_id)
                state = read_state(row)
                state["error"] = str(error)
                update_session(session_id, state, "failed")
                audit(session_id, "source_analysis_failed", {"error": str(error)})
            except Exception:
                current_app.logger.exception("Unexpected release analysis failure for session %s", session_id)
                row = get_session(session_id)
                state = read_state(row)
                state["error"] = "Unexpected analysis error. Check the application log for details."
                update_session(session_id, state, "failed")
                audit(session_id, "source_analysis_failed", {"error": state["error"]})

    def set_progress(session_id: str, message: str) -> None:
        row = get_session(session_id)
        state = read_state(row)
        state["progress"] = message
        update_session(session_id, state, "analyzing")

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "database": "SQLite"})

    @app.post("/api/sessions")
    def create_session():
        data = request.get_json(silent=True) or {}
        folder_name = validate_folder_name(str(data.get("folder_name", "")))
        target_url, _target_type = _comparison_target(str(data.get("target_url", "")))
        session_id = str(uuid.uuid4())
        workdir = Path(app.config["WORKSPACE"]) / session_id
        workdir.mkdir(parents=True)
        now = _utc_now()
        db().execute(
            "INSERT INTO sessions (id, folder_name, target_url, workdir, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 'created', ?, ?)",
            (session_id, folder_name, target_url, str(workdir), now, now),
        )
        db().commit()
        audit(session_id, "session_created", {"folder_name": folder_name, "target_url": target_url})
        return jsonify({"id": session_id}), 201

    @app.post("/api/sessions/<session_id>/source")
    def upload_source(session_id: str):
        row = get_session(session_id)
        mode = request.form.get("source_mode", "zip")
        if mode != "zip":
            raise WorkflowError("Only ZIP uploads are supported as a release source.")
        username = request.form.get("svn_username", "")
        password = request.form.get("svn_password", "")
        workdir = Path(row["workdir"])
        archive = request.files.get("archive")
        if not archive or not archive.filename:
            raise WorkflowError("Choose a ZIP file to upload.")
        if not _local_folder(row["target_url"]) and (
            not username.strip() or not password
        ):
            raise WorkflowError(
                "Enter both the SVN username and password to read the remote repository."
            )
        archive_path = workdir / "source-upload.zip"
        archive.save(archive_path)
        db().execute(
            "UPDATE sessions SET source_url = '', status = 'analyzing', state_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps({"progress": "Starting ZIP review…"}), _utc_now(), session_id),
        )
        db().commit()
        executor.submit(
            source_job, session_id, str(archive_path), username, password,
        )
        return jsonify({"id": session_id, "status": "analyzing"}), 202

    @app.get("/api/sessions/<session_id>")
    def session_details(session_id: str):
        row = get_session(session_id)
        return jsonify({
            "id": session_id,
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "state": public_state(read_state(row)),
        })

    @app.post("/api/sessions/<session_id>/baseline")
    def change_baseline(session_id: str):
        row = get_session(session_id)
        old_state = read_state(row)
        if not old_state.get("folder_hash"):
            raise WorkflowError("Upload a source folder before changing baselines.")
        data = request.form if request.form else (request.get_json(silent=True) or {})
        rel_path = str(data.get("path", ""))
        code_drop = str(data.get("code_drop", ""))
        options = old_state.get("baseline_options", {}).get(rel_path, [])
        if not any(item["code_drop"] == code_drop for item in options):
            raise WorkflowError("Choose a baseline listed for this area and component.")
        overrides = {key: value["code_drop"] for key, value in old_state["baselines"].items()}
        overrides[rel_path] = code_drop
        state = analyze(
            session_id,
            row,
            Path(old_state["source_root"]),
            request.form.get("svn_username", ""),
            request.form.get("svn_password", ""),
            old_state,
            overrides,
        )
        update_session(session_id, state, "ready" if not state["validation"]["failed"] else "validation_failed")
        audit(session_id, "baseline_changed", {"path": rel_path, "code_drop": code_drop})
        return jsonify(public_state(state))

    @app.post("/api/sessions/<session_id>/rescan")
    def rescan_configs(session_id: str):
        row = get_session(session_id)
        old_state = read_state(row)
        if not old_state.get("source_root"):
            raise WorkflowError("Upload a source folder before rescanning configs.")
        archive = request.files.get("archive")
        if not archive or not archive.filename:
            raise WorkflowError("Select a corrected Configs ZIP; rescans always use the newly uploaded files.")
        workdir = Path(row["workdir"])
        upload_dir = workdir / "configs-reupload"
        replacement = workdir / "Configs.replacement"
        backup = workdir / "Configs.previous"
        current_root = Path(old_state["source_root"])
        previous_configs = current_root / "Configs"
        try:
            configs_source = extract_configs_zip(archive.stream, upload_dir)
            if replacement.exists():
                shutil.rmtree(replacement)
            shutil.copytree(configs_source, replacement)
            if backup.exists():
                shutil.rmtree(backup)
            if previous_configs.exists():
                previous_configs.rename(backup)
            try:
                replacement.rename(previous_configs)
            except OSError:
                if backup.exists() and not previous_configs.exists():
                    backup.rename(previous_configs)
                raise
            if backup.exists():
                shutil.rmtree(backup)
        finally:
            shutil.rmtree(upload_dir, ignore_errors=True)
            if replacement.exists():
                shutil.rmtree(replacement, ignore_errors=True)
        state = analyze(
            session_id, row, current_root,
            request.form.get("svn_username", ""),
            request.form.get("svn_password", ""),
            old_state,
            {key: value["code_drop"] for key, value in old_state.get("baselines", {}).items()},
        )
        old_findings = {item["id"]: item for item in old_state.get("findings", [])}
        new_findings = {item["id"]: item for item in state["findings"]}
        history = old_state.get("scan_history", [])
        history.append({
            "scanned_at": state["scanned_at"],
            "folder_hash": state["folder_hash"],
            "findings": list(new_findings.values()),
        })
        state["scan_history"] = history
        state["rescan_completed"] = (
            state["validation"]["failed"] == 0
            and (state["configs_present"] or state["config_scan_status"] == "not run: Configs directory missing")
        )
        state["finding_changes"] = {
            "fixed": [
                {"finding": value, "original_value": value["value"], "current_value": "–"}
                for key, value in old_findings.items() if key not in new_findings
            ],
            "still_present": [
                {
                    "finding": value,
                    "original_value": old_findings[key]["value"],
                    "current_value": value["value"],
                }
                for key, value in new_findings.items() if key in old_findings
            ],
            "new": [
                {"finding": value, "original_value": "–", "current_value": value["value"]}
                for key, value in new_findings.items() if key not in old_findings
            ],
        }
        state["acknowledged"] = [
            item for item in old_state.get("acknowledged", []) if item in new_findings
        ]
        update_session(session_id, state, "ready" if not state["validation"]["failed"] else "validation_failed")
        audit(session_id, "configs_rescanned", {
            "folder_hash": state["folder_hash"],
            "json_checked": state["validation"]["checked"],
            "json_failed": state["validation"]["failed"],
            "findings": len(state["findings"]),
        })
        return jsonify(public_state(state))

    @app.post("/api/sessions/<session_id>/review")
    def review_binaries(session_id: str):
        row = get_session(session_id)
        state = read_state(row)
        data = request.get_json(silent=True) or {}
        if "Binaries" in state.get("areas_missing", []):
            raise WorkflowError("This ZIP has no Binaries folder. Confirm skipping binary review instead.")
        if data.get("reviewed") is not True:
            raise WorkflowError("Explicitly confirm that you reviewed the binary comparison.")
        state["binary_reviewed"] = True
        update_session(session_id, state)
        audit(session_id, "binary_comparison_reviewed", {})
        return jsonify(public_state(state))

    @app.post("/api/sessions/<session_id>/skip-area")
    def skip_missing_area(session_id: str):
        row = get_session(session_id)
        state = read_state(row)
        data = request.get_json(silent=True) or {}
        area = str(data.get("area", ""))
        if area not in {"Binaries", "Configs"}:
            raise WorkflowError("Choose Binaries or Configs to confirm skipping.")
        if area not in state.get("areas_missing", []):
            raise WorkflowError(f"The {area} folder is present; its review cannot be skipped.")
        skipped = set(state.get("skipped_areas", []))
        skipped.add(area)
        state["skipped_areas"] = sorted(skipped)
        update_session(session_id, state)
        build_report_bundle(Path(row["workdir"]) / "reports", state["folder_name"], state)
        audit(session_id, "review_area_skipped", {"area": area})
        return jsonify(public_state(state))

    @app.post("/api/sessions/<session_id>/acknowledge")
    def acknowledge_warning(session_id: str):
        row = get_session(session_id)
        state = read_state(row)
        data = request.get_json(silent=True) or {}
        finding_id = str(data.get("finding_id", ""))
        if not any(
            finding["id"] == finding_id and finding["severity"] == "Warning"
            for finding in state.get("findings", [])
        ):
            raise WorkflowError("Only an active warning can be acknowledged.")
        acknowledged = set(state.get("acknowledged", []))
        if data.get("acknowledged"):
            acknowledged.add(finding_id)
        else:
            acknowledged.discard(finding_id)
        state["acknowledged"] = sorted(acknowledged)
        update_session(session_id, state)
        audit(session_id, "warning_acknowledged", {
            "finding_id": finding_id,
            "acknowledged": bool(data.get("acknowledged")),
        })
        return jsonify(public_state(state))

    @app.post("/api/sessions/<session_id>/upload")
    def confirm_upload(session_id: str):
        row = get_session(session_id)
        state = read_state(row)
        data = request.get_json(silent=True) or {}
        if state.get("target_type") == "local_folder":
            raise WorkflowError("SVN commits are disabled for local-folder comparisons. Use an SVN repository URL.")
        message = str(data.get("commit_message", "")).strip()
        approver = str(data.get("approver", "")).strip()
        username = str(data.get("svn_username", "")).strip()
        password = str(data.get("svn_password", ""))
        if not message:
            raise WorkflowError("Enter a commit message.")
        if not approver:
            raise WorkflowError("Enter the approver name for the audit record.")
        if state.get("validation", {}).get("failed"):
            raise WorkflowError("SVN upload is blocked until every JSON config file is valid.")
        missing_areas = set(state.get("areas_missing", []))
        unconfirmed_skips = missing_areas - set(state.get("skipped_areas", []))
        if unconfirmed_skips:
            areas = ", ".join(sorted(unconfirmed_skips))
            raise WorkflowError(f"Confirm skipping the missing {areas} review step(s) before approval.")
        if "Configs" not in missing_areas and not state.get("rescan_completed"):
            raise WorkflowError("Upload requires a clean dummy-value scan after a fresh Configs ZIP re-upload.")
        if "Binaries" not in missing_areas and not state.get("binary_reviewed"):
            raise WorkflowError("Review and confirm the binary comparison before upload.")
        blockers = [item for item in state.get("findings", []) if item["severity"] == "Blocker"]
        if blockers:
            raise WorkflowError(f"SVN upload is blocked by {len(blockers)} dummy-value blocker(s).")
        warnings = {
            item["id"] for item in state.get("findings", []) if item["severity"] == "Warning"
        }
        if not warnings.issubset(set(state.get("acknowledged", []))):
            raise WorkflowError("Acknowledge every active dummy-value warning before upload.")
        source_root = Path(state["source_root"])
        if folder_hash(source_root) != state.get("folder_hash"):
            raise WorkflowError("The source changed after its last scan. Re-upload configs and scan again.")
        target_url = safe_url_child(state["target_url"], state["folder_name"])
        try:
            existing = svn_directory_entries(state["target_url"], username, password)
        except WorkflowError:
            raise
        if any(item["name"].casefold() == state["folder_name"].casefold() for item in existing):
            raise WorkflowError(f"{state['folder_name']} already exists in the SVN destination.")
        revision, output = svn_import(source_root, target_url, message, username, password)
        result = {
            "revision": revision or "unknown",
            "url": target_url,
            "message": message,
            "approver": approver,
            "uploaded_at": _utc_now(),
            "svn_output": output,
        }
        for component_path in component_paths(source_root):
            if not component_path.startswith("Binaries/"):
                continue
            component = component_path.split("/", 1)[1]
            component_root = source_root / "Binaries" / component
            for binary in component_root.rglob("*"):
                if binary.is_file() and binary.suffix.casefold() in {".exe", ".dll"}:
                    metadata = binary_version_details(binary)
                    db().execute(
                        "INSERT OR REPLACE INTO binary_version_cache "
                        "(base_url, code_drop, component_path, relative_path, revision, version, sha256) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            state["target_url"], state["folder_name"], component_path,
                            binary.relative_to(component_root).as_posix(), revision or "",
                            metadata["version"], metadata["sha256"],
                        ),
                    )
            db().execute(
                "INSERT OR REPLACE INTO binary_version_index "
                "(base_url, code_drop, component_path, revision, fetched_at) VALUES (?, ?, ?, ?, ?)",
                (state["target_url"], state["folder_name"], component_path, revision or "", _utc_now()),
            )
        db().commit()
        try:
            current_dir = Path(row["workdir"]) / "current"
            if current_dir.exists():
                shutil.rmtree(current_dir)
            baselines_dir = Path(row["workdir"]) / "baselines"
            if baselines_dir.exists():
                shutil.rmtree(baselines_dir)
        except OSError as error:
            current_app.logger.warning(
                "Could not remove staged release files for session %s: %s", session_id, error
            )
            result["cleanup_warning"] = "The release was committed, but staged files could not be fully removed."
        state["upload"] = result
        update_session(session_id, state, "uploaded")
        db().execute(
            "DELETE FROM baseline_cache WHERE base_url = ? AND code_drop = ?",
            (state["target_url"], state["folder_name"]),
        )
        for rel_path in component_paths(source_root):
            db().execute(
                "INSERT OR REPLACE INTO baseline_cache "
                "(base_url, code_drop, rel_path, present, revision, fetched_at) VALUES (?, ?, ?, 1, ?, ?)",
                (state["target_url"], state["folder_name"], rel_path, revision, _utc_now()),
            )
        db().commit()
        audit(session_id, "svn_uploaded", result)
        return jsonify(public_state(state))

    @app.get("/api/sessions/<session_id>/reports/<report_name>")
    def download_report(session_id: str, report_name: str):
        row = get_session(session_id)
        if report_name not in {"Binaries.xlsx", "Configs.xlsx", "Release-Review.zip"}:
            abort(404)
        path = Path(row["workdir"]) / "reports" / report_name
        if not path.is_file():
            abort(404, description="This report is not available until its checks have passed.")
        return send_file(path, as_attachment=True, download_name=report_name)

    @app.get("/api/sessions/<session_id>/json-errors.csv")
    def download_json_errors(session_id: str):
        import csv
        from io import StringIO

        state = read_state(get_session(session_id))
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["File", "Line", "Column", "Error", "Context"])
        for error in state.get("validation", {}).get("errors", []):
            writer.writerow([
                error["file"], error["line"], error["column"], error["message"], error["context"],
            ])
        from flask import Response

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=json-validation-errors.csv"},
        )

    @app.get("/api/sessions/<session_id>/audit")
    def audit_history(session_id: str):
        get_session(session_id)
        rows = db().execute(
            "SELECT event, detail_json, created_at FROM audit_log WHERE session_id = ? ORDER BY id",
            (session_id,),
        ).fetchall()
        return jsonify([
            {"event": row["event"], "details": json.loads(row["detail_json"]), "created_at": row["created_at"]}
            for row in rows
        ])

    @app.errorhandler(WorkflowError)
    def workflow_error(error: WorkflowError):
        return jsonify({"error": str(error)}), 400

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify({"error": "Upload exceeds the 2 GB request limit."}), 413

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": getattr(error, "description", "Invalid request.")}), 400

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
