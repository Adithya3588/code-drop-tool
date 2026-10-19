from __future__ import annotations

import hashlib
import difflib
import json
import os
import re
import shutil
import subprocess
import zipfile
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, urlsplit


class WorkflowError(Exception):
    pass


class DuplicateObject:
    def __init__(self, pairs: list[tuple[str, Any]]) -> None:
        self.pairs = pairs


def validate_folder_name(value: str) -> str:
    name = value.strip()
    if not re.fullmatch(r"Codedrop\d+", name, re.IGNORECASE):
        raise WorkflowError("Folder name must match Codedrop followed by a number (for example, Codedrop8 or Codedrop10).")
    return name


def validate_svn_url(value: str) -> str:
    url = value.strip().rstrip("/")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https", "svn", "svn+ssh", "file"}:
        raise WorkflowError("Use a valid SVN URL (https://, http://, svn://, svn+ssh:// or file://).")
    if parsed.scheme != "file" and not parsed.netloc:
        raise WorkflowError("The SVN URL must include a host.")
    if parsed.username or parsed.password:
        raise WorkflowError("Do not include credentials in an SVN URL; enter them in the credential fields.")
    return url


def _safe_member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise WorkflowError(f"Unsafe path in ZIP archive: {name}")
    if path.parts and re.match(r"^[A-Za-z]:", path.parts[0]):
        raise WorkflowError(f"Unsafe path in ZIP archive: {name}")
    return path


def extract_zip_contents(
    upload, destination: Path, max_bytes: int = 2 * 1024**3
) -> Path:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    total = 0
    try:
        with zipfile.ZipFile(upload) as archive:
            for member in archive.infolist():
                relative = _safe_member_path(member.filename)
                mode = member.external_attr >> 16
                if mode & 0o170000 == 0o120000:
                    raise WorkflowError(f"Symbolic links are not allowed in ZIP archives: {member.filename}")
                total += member.file_size
                if total > max_bytes:
                    raise WorkflowError("The ZIP archive expands beyond the 2 GB upload limit.")
                target = destination.joinpath(*relative.parts)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member) as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
    except zipfile.BadZipFile as error:
        raise WorkflowError("The uploaded file is not a valid ZIP archive.") from error
    except RuntimeError as error:
        raise WorkflowError("Encrypted ZIP archives are not supported.") from error
    return destination


def extract_zip(
    upload,
    destination: Path,
    max_bytes: int = 2 * 1024**3,
    fallback_folder_name: str | None = None,
) -> Path:
    extract_zip_contents(upload, destination, max_bytes)
    root = find_drop_root(destination)
    if root is None:
        if fallback_folder_name:
            matching_folder = next(
                (
                    path for path in destination.iterdir()
                    if path.is_dir()
                    and path.name.casefold() == fallback_folder_name.casefold()
                ),
                None,
            )
            if matching_folder:
                return matching_folder
            return destination
        raise WorkflowError("The ZIP must contain a Codedrop folder with Binaries and/or Configs.")
    return root


def find_drop_root(base: Path) -> Path | None:
    if any((base / area).is_dir() for area in ("Binaries", "Configs")):
        return base
    candidates = [
        path for path in base.iterdir()
        if path.is_dir() and any((path / area).is_dir() for area in ("Binaries", "Configs"))
    ]
    if len(candidates) > 1:
        raise WorkflowError("The ZIP contains more than one possible code drop folder.")
    return candidates[0] if candidates else None


def archived_code_drop_roots(
    archive_path: Path, declared_name: str | None = None
) -> list[str]:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = [
                PurePosixPath(name.replace("\\", "/"))
                for name in archive.namelist()
                if name and not name.endswith("/")
            ]
    except (OSError, zipfile.BadZipFile) as error:
        raise WorkflowError(f"Could not inspect code-drop archive {archive_path.name}: {error}") from error
    roots = {
        parts[0]
        for member in members
        if len(parts := member.parts) >= 3
        and re.fullmatch(r"Codedrop\d+", parts[0], re.IGNORECASE)
        and parts[1].casefold() in {"binaries", "configs"}
    }
    if roots:
        return sorted(roots, key=lambda name: int(re.search(r"\d+", name).group()))
    if declared_name and any(
        len(member.parts) >= 2 and member.parts[0].casefold() in {"binaries", "configs"}
        for member in members
    ):
        return [declared_name]
    return []


def extract_configs_zip(upload, destination: Path) -> Path:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    total = 0
    try:
        with zipfile.ZipFile(upload) as archive:
            for member in archive.infolist():
                relative = _safe_member_path(member.filename)
                mode = member.external_attr >> 16
                if mode & 0o170000 == 0o120000:
                    raise WorkflowError(f"Symbolic links are not allowed in ZIP archives: {member.filename}")
                total += member.file_size
                if total > 2 * 1024**3:
                    raise WorkflowError("The ZIP archive expands beyond the 2 GB upload limit.")
                target = destination.joinpath(*relative.parts)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member) as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
    except zipfile.BadZipFile as error:
        raise WorkflowError("The uploaded file is not a valid ZIP archive.") from error
    except RuntimeError as error:
        raise WorkflowError("Encrypted ZIP archives are not supported.") from error
    candidates = [destination]
    candidates.extend(path for path in destination.rglob("Configs") if path.is_dir())
    config_dirs = [path for path in candidates if path.name.casefold() == "configs"]
    if len(config_dirs) > 1:
        raise WorkflowError("The re-uploaded ZIP contains more than one Configs folder.")
    configs = config_dirs[0] if config_dirs else None
    if configs is None:
        if any(path.is_file() for path in destination.rglob("*")) and not (destination / "Binaries").exists():
            configs = destination
        else:
            raise WorkflowError("The re-uploaded ZIP must contain a Configs folder or its contents.")
    return configs


def _normalize_pairs(value: Any, path: str, duplicates: list[dict[str, str]]) -> Any:
    if isinstance(value, DuplicateObject):
        result: dict[str, Any] = {}
        seen: set[str] = set()
        for key, item in value.pairs:
            child_path = f"{path}.{key}" if path else key
            if key in seen:
                duplicates.append({"key_path": child_path, "key": key})
            seen.add(key)
            result[key] = _normalize_pairs(item, child_path, duplicates)
        return result
    if isinstance(value, list):
        return [
            _normalize_pairs(item, f"{path}[{index}]", duplicates)
            for index, item in enumerate(value)
        ]
    return value


def load_json(path: Path) -> tuple[Any, list[dict[str, str]]]:
    text = path.read_text(encoding="utf-8-sig")
    duplicates: list[dict[str, str]] = []
    parsed = json.loads(text, object_pairs_hook=DuplicateObject)
    return _normalize_pairs(parsed, "", duplicates), duplicates


def validate_configs(config_root: Path) -> dict[str, Any]:
    files = sorted(path for path in config_root.rglob("*.json") if path.is_file())
    errors: list[dict[str, Any]] = []
    duplicates: list[dict[str, str]] = []
    for path in files:
        relative = path.relative_to(config_root).as_posix()
        try:
            _, repeated = load_json(path)
            duplicates.extend({"file": relative, **entry} for entry in repeated)
        except UnicodeDecodeError as error:
            errors.append({
                "file": relative,
                "line": 1,
                "column": error.start + 1,
                "message": "File is not valid UTF-8.",
                "context": path.read_bytes()[:160].decode("utf-8", errors="replace"),
            })
        except json.JSONDecodeError as error:
            lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
            errors.append({
                "file": relative,
                "line": error.lineno,
                "column": error.colno,
                "message": error.msg,
                "context": "\n".join(lines[max(0, error.lineno - 2):error.lineno + 1]),
            })
    return {
        "checked": len(files),
        "valid": len(files) - len(errors),
        "failed": len(errors),
        "errors": errors,
        "duplicates": duplicates,
    }


def read_rules(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        rules = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise WorkflowError(f"Could not read dummy-value rules: {error}") from error
    if not isinstance(rules, dict) or not isinstance(rules.get("rules"), list):
        raise WorkflowError("Dummy-value rules must be a JSON object with a rules array.")
    if not isinstance(rules.get("ignoreCase", True), bool) or not isinstance(rules.get("scanKeys", False), bool):
        raise WorkflowError("Dummy-value settings ignoreCase and scanKeys must be true or false.")
    for index, rule in enumerate(rules["rules"]):
        if not isinstance(rule, dict) or rule.get("match") not in {
            "contains", "wholeWord", "exact", "regex"
        }:
            raise WorkflowError(f"Dummy-value rule {index + 1} has an unknown match type.")
        if rule.get("severity") not in {"Blocker", "Warning"} or not isinstance(rule.get("pattern"), str):
            raise WorkflowError(f"Dummy-value rule {index + 1} needs a pattern and valid severity.")
        if "enabled" in rule and not isinstance(rule["enabled"], bool):
            raise WorkflowError(f"Dummy-value rule {index + 1} enabled must be true or false.")
        if rule.get("match") == "regex":
            try:
                re.compile(rule["pattern"])
            except re.error as error:
                raise WorkflowError(f"Dummy-value rule {index + 1} has an invalid regex: {error}") from error
    allowlist = rules.get("allowlist", [])
    if not isinstance(allowlist, list) or any(
        not isinstance(entry, dict)
        or not all(isinstance(entry.get(key), str) for key in ("file", "keyPath", "pattern"))
        for entry in allowlist
    ):
        raise WorkflowError("Dummy-value allowlist entries need file, keyPath, and pattern strings.")
    empty_keys = rules.get("emptyRequiredKeys", [])
    if not isinstance(empty_keys, list) or any(not isinstance(key, str) for key in empty_keys):
        raise WorkflowError("emptyRequiredKeys must be an array of key-name strings.")
    return rules, hashlib.sha256(raw).hexdigest()


def _sensitive(key_path: str) -> bool:
    return bool(re.search(r"password|passwd|secret|token|connection.?string|api.?key|credential", key_path, re.I))


def _display_value(value: Any, key_path: str) -> str:
    if _sensitive(key_path):
        return "••••••••"
    return json.dumps(value, ensure_ascii=False, sort_keys=True) if not isinstance(value, str) else value


def _mask_json(value: Any, prefix: str = "") -> Any:
    if prefix and _sensitive(prefix):
        return "••••••••"
    if isinstance(value, dict):
        return {
            key: _mask_json(child, f"{prefix}.{key}" if prefix else key)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_mask_json(child, f"{prefix}[{index}]") for index, child in enumerate(value)]
    return value


def scan_configs(config_root: Path, rules_path: Path) -> tuple[list[dict[str, Any]], str]:
    rules, rules_hash = read_rules(rules_path)
    findings: list[dict[str, Any]] = []
    all_rules = [rule for rule in rules["rules"] if rule.get("enabled", True)]
    allowlist = rules.get("allowlist", [])
    ignore_case = rules.get("ignoreCase", True)

    def matches(pattern: str, match_type: str, value: str) -> bool:
        flags = re.IGNORECASE if ignore_case else 0
        if match_type == "exact":
            return value.casefold() == pattern.casefold() if ignore_case else value == pattern
        if match_type == "contains":
            return pattern.casefold() in value.casefold() if ignore_case else pattern in value
        expression = (
            rf"\b{re.escape(pattern)}\b" if match_type == "wholeWord" else pattern
        )
        return re.search(expression, value, flags) is not None

    def inspect_value(file: str, key_path: str, value: Any) -> None:
        rendered = str(value) if isinstance(value, (str, int, float, bool)) else json.dumps(value, ensure_ascii=False)
        for rule in all_rules:
            if rule.get("component") and rule["component"] not in file.split("/"):
                continue
            if matches(rule["pattern"], rule["match"], rendered):
                if any(
                    entry.get("file") == file
                    and entry.get("keyPath") == key_path
                    and entry.get("pattern") == rule["pattern"]
                    for entry in allowlist
                ):
                    continue
                finding = {
                    "id": hashlib.sha256(
                        f"{file}\0{key_path}\0{rule['pattern']}\0{rule['severity']}".encode()
                    ).hexdigest()[:16],
                    "file": file,
                    "key_path": key_path,
                    "value": _display_value(value, key_path),
                    "pattern": rule["pattern"],
                    "severity": rule["severity"],
                }
                if finding not in findings:
                    findings.append(finding)
        if value == "" and any(
            str(key).casefold() in key_path.casefold()
            for key in rules.get("emptyRequiredKeys", [])
        ):
            findings.append({
                "id": hashlib.sha256(f"{file}\0{key_path}\0empty".encode()).hexdigest()[:16],
                "file": file,
                "key_path": key_path,
                "value": "",
                "pattern": "empty required value",
                "severity": "Blocker",
            })

    def walk(file: str, value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_path = f"{prefix}.{key}" if prefix else key
                if rules.get("scanKeys", False):
                    inspect_value(file, key_path, key)
                walk(file, child, key_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(file, child, f"{prefix}[{index}]")
        else:
            inspect_value(file, prefix, value)

    for path in sorted(item for item in config_root.rglob("*.json") if item.is_file()):
        if path.name.casefold() == "template.json":
            continue
        try:
            data, duplicates = load_json(path)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        relative = path.relative_to(config_root).as_posix()
        walk(relative, data)
        for duplicate in duplicates:
            findings.append({
                "id": hashlib.sha256(
                    f"{relative}\0{duplicate['key_path']}\0duplicate".encode()
                ).hexdigest()[:16],
                "file": relative,
                "key_path": duplicate["key_path"],
                "value": "",
                "pattern": "duplicate JSON key",
                "severity": "Warning",
            })
    return findings, rules_hash


def flatten_json(value: Any, prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            flattened.update(flatten_json(child, f"{prefix}.{key}" if prefix else key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            flattened.update(flatten_json(child, f"{prefix}[{index}]"))
    else:
        flattened[prefix or "$"] = value
    return flattened


def _json_error_context(path: Path, error: Exception, *, reveal_contents: bool = True) -> str:
    if not reveal_contents:
        return "Baseline file contents are hidden to protect earlier-release data."
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return ""
    if isinstance(error, json.JSONDecodeError):
        lines = text.splitlines()
        start = max(0, error.lineno - 2)
        end = min(len(lines), error.lineno + 1)
        return "\n".join(lines[start:end])
    if isinstance(error, UnicodeDecodeError):
        return path.read_bytes()[:160].decode("utf-8", errors="replace")
    return ""


def config_diffs(current_root: Path, baselines: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    current_configs = current_root / "Configs"
    results = []
    current_files = {
        item.relative_to(current_configs).as_posix(): item
        for item in current_configs.rglob("*") if item.is_file()
    } if current_configs.is_dir() else {}
    for relative, path in sorted(current_files.items()):
        component = relative.split("/")[0]
        baseline = baselines.get(f"Configs/{component}")
        previous_root = Path(baseline["local_path"]) if baseline else None
        relative_inside_component = "/".join(PurePosixPath(relative).parts[1:])
        previous_path = (
            previous_root.joinpath(*PurePosixPath(relative_inside_component).parts)
            if previous_root and relative_inside_component else None
        )
        if path.suffix.casefold() != ".json":
            previous_hash = (
                hashlib.sha256(previous_path.read_bytes()).hexdigest()
                if previous_path and previous_path.is_file() else None
            )
            current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            status = (
                "New" if previous_hash is None else
                "Unchanged" if previous_hash == current_hash else
                "Changed"
            )
            changes = [] if status == "Unchanged" else [{
                "key_path": "File content (SHA-256)",
                "previous": previous_hash or "–",
                "current": current_hash,
                "change": "Added" if previous_hash is None else "Changed",
            }]
            results.append({
                "file": relative,
                "status": status,
                "baseline": baseline,
                "changes": changes,
                "text_diff": [],
            })
            continue
        previous = None
        try:
            current, _ = load_json(path)
        except json.JSONDecodeError as error:
            baseline_hash = (
                _file_hash(previous_path)
                if previous_path and previous_path.is_file() else "–"
            )
            current_hash = _file_hash(path)
            results.append({
                "file": relative,
                "status": "Invalid JSON",
                "baseline": baseline,
                "changes": [{
                    "key_path": "File comparison (SHA-256)",
                    "previous": baseline_hash,
                    "current": current_hash,
                    "change": "Invalid JSON; semantic diff unavailable",
                }],
                "text_diff": [],
                "current_validation_error": {
                    "file": relative,
                    "line": error.lineno,
                    "column": error.colno,
                    "message": error.msg,
                    "context": _json_error_context(path, error, reveal_contents=True),
                },
            })
            continue
        except UnicodeDecodeError as error:
            baseline_hash = (
                _file_hash(previous_path)
                if previous_path and previous_path.is_file() else "–"
            )
            current_hash = _file_hash(path)
            results.append({
                "file": relative,
                "status": "Invalid JSON",
                "baseline": baseline,
                "changes": [{
                    "key_path": "File comparison (SHA-256)",
                    "previous": baseline_hash,
                    "current": current_hash,
                    "change": "Invalid UTF-8; semantic diff unavailable",
                }],
                "text_diff": [],
                "current_validation_error": {
                    "file": relative,
                    "line": 1,
                    "column": error.start + 1,
                    "message": "JSON file is not valid UTF-8.",
                    "context": _json_error_context(path, error, reveal_contents=True),
                },
            })
            continue
        baseline_error = None
        if previous_path and previous_path.is_file():
            try:
                previous, _ = load_json(previous_path)
            except json.JSONDecodeError as error:
                baseline_error = {
                    "file": relative,
                    "line": error.lineno,
                    "column": error.colno,
                    "message": f"Baseline JSON is invalid: {error.msg}",
                    "context": _json_error_context(previous_path, error, reveal_contents=False),
                }
            except UnicodeDecodeError as error:
                baseline_error = {
                    "file": relative,
                    "line": 1,
                    "column": error.start + 1,
                    "message": "Baseline JSON is not valid UTF-8.",
                    "context": _json_error_context(previous_path, error, reveal_contents=False),
                }
        if baseline_error:
            results.append({
                "file": relative,
                "status": "Baseline invalid JSON",
                "baseline": baseline,
                "changes": [{
                    "key_path": "File comparison (SHA-256)",
                    "previous": hashlib.sha256(previous_path.read_bytes()).hexdigest(),
                    "current": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "change": "Baseline invalid JSON",
                }],
                "text_diff": [],
                "baseline_validation_error": baseline_error,
            })
            continue
        old_values = flatten_json(previous) if previous is not None else {}
        new_values = flatten_json(current)
        changes = []
        for key in sorted(old_values.keys() | new_values.keys()):
            if key not in old_values:
                kind = "Added"
            elif key not in new_values:
                kind = "Removed"
            elif old_values[key] != new_values[key]:
                kind = "Changed"
            else:
                continue
            changes.append({
                "key_path": key,
                "previous": _display_value(old_values.get(key), key),
                "current": _display_value(new_values.get(key), key),
                "change": kind,
            })
        results.append({
            "file": relative,
            "status": "New" if previous is None else ("Changed" if changes else "Unchanged"),
            "baseline": baseline,
            "changes": changes,
            "text_diff": list(difflib.unified_diff(
                json.dumps(_mask_json(previous), indent=2, ensure_ascii=False, sort_keys=True).splitlines()
                if previous is not None else [],
                json.dumps(_mask_json(current), indent=2, ensure_ascii=False, sort_keys=True).splitlines(),
                fromfile=(f"{baseline['code_drop']}/{baseline['path']}/{relative_inside_component}"
                          if baseline else "no baseline"),
                tofile=f"current/Configs/{relative}",
                lineterm="",
                n=2,
            )),
        })
    for group, baseline in sorted(baselines.items()):
        if not group.startswith("Configs/"):
            continue
        component = group.split("/", 1)[1]
        baseline_root = Path(baseline["local_path"])
        if not baseline_root.is_dir():
            continue
        for path in sorted(item for item in baseline_root.rglob("*") if item.is_file()):
            relative = path.relative_to(baseline_root).as_posix()
            current_relative = f"{component}/{relative}"
            if current_relative in current_files:
                continue
            baseline_error = None
            if path.suffix.casefold() == ".json":
                try:
                    previous, _ = load_json(path)
                except json.JSONDecodeError as error:
                    baseline_error = {
                        "file": current_relative,
                        "line": error.lineno,
                        "column": error.colno,
                        "message": f"Removed baseline JSON is invalid: {error.msg}",
                    }
                    previous = None
                except UnicodeDecodeError as error:
                    baseline_error = {
                        "file": current_relative,
                        "line": 1,
                        "column": error.start + 1,
                        "message": "Removed baseline JSON is not valid UTF-8.",
                    }
                    previous = None
                if baseline_error:
                    changes = [{
                        "key_path": "File content (SHA-256)",
                        "previous": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "current": "–",
                        "change": "Removed",
                    }]
                    text_diff = []
                else:
                    changes = [
                        {
                            "key_path": key,
                            "previous": _display_value(value, key),
                            "current": "–",
                            "change": "Removed",
                        }
                        for key, value in sorted(flatten_json(previous).items())
                    ]
                    text_diff = list(difflib.unified_diff(
                        json.dumps(_mask_json(previous), indent=2, ensure_ascii=False, sort_keys=True).splitlines(),
                        [],
                        fromfile=f"{baseline['code_drop']}/{baseline['path']}/{relative}",
                        tofile="removed",
                        lineterm="",
                        n=2,
                    ))
            else:
                previous_hash = hashlib.sha256(path.read_bytes()).hexdigest()
                changes = [{
                    "key_path": "File content (SHA-256)",
                    "previous": previous_hash,
                    "current": "–",
                    "change": "Removed",
                }]
                text_diff = []
            results.append({
                "file": current_relative,
                "status": "Removed",
                "baseline": baseline,
                "changes": changes,
                "text_diff": text_diff,
                **({"baseline_validation_error": baseline_error} if baseline_error else {}),
            })
    results.sort(key=lambda item: item["file"])
    return results


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _binary_version(path: Path) -> str:
    import pefile

    try:
        executable = pefile.PE(str(path), fast_load=True)
        executable.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        for entry in getattr(executable, "FileInfo", []):
            for string_table in getattr(entry, "StringTable", []):
                values = string_table.entries
                version = values.get(b"FileVersion")
                if version:
                    return version.decode("utf-8", errors="replace").strip("\x00 ")
        for entry in getattr(executable, "VS_FIXEDFILEINFO", []):
            info = entry.FileVersionMS, entry.FileVersionLS
            return ".".join(str(part) for part in (
                info[0] >> 16, info[0] & 0xFFFF, info[1] >> 16, info[1] & 0xFFFF
            ))
    except pefile.PEFormatError:
        return "N/A"
    return "N/A"


def binary_version_details(path: Path) -> dict[str, str]:
    return {"version": _binary_version(path), "sha256": _file_hash(path)}


def compare_binaries(current_root: Path, baselines: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    binaries = current_root / "Binaries"
    rows = []
    current_components = (
        {item.name: item for item in binaries.iterdir() if item.is_dir()}
        if binaries.is_dir() else {}
    )
    component_names = set(current_components)
    component_names.update(
        path.split("/", 1)[1]
        for path in baselines
        if path.startswith("Binaries/")
    )
    for component_name in sorted(component_names):
        component_dir = current_components.get(component_name)
        group = f"Binaries/{component_name}"
        baseline = baselines.get(group)
        baseline_root = Path(baseline["local_path"]) if baseline else None
        current_files = {
            item.relative_to(component_dir).as_posix(): item
            for item in component_dir.rglob("*") if item.is_file()
        } if component_dir else {}
        old_files = {
            item.relative_to(baseline_root).as_posix(): item
            for item in baseline_root.rglob("*") if item.is_file()
        } if baseline_root and baseline_root.is_dir() else {}
        old_by_hash: dict[str, list[str]] = defaultdict(list)
        for relative, path in old_files.items():
            old_by_hash[_file_hash(path)].append(relative)
        paired_old: set[str] = set()
        for relative, path in sorted(current_files.items()):
            old = old_files.get(relative)
            if old:
                paired_old.add(relative)
                old_version, current_version = _binary_version(old), _binary_version(path)
                same_hash = _file_hash(old) == _file_hash(path)
                status = "Unchanged" if same_hash else (
                    "Hash changed, same version"
                    if old_version != "N/A" and old_version == current_version
                    else "Changed"
                )
                try:
                    if old_version != "N/A" and current_version != "N/A":
                        if tuple(map(int, current_version.split("."))) < tuple(map(int, old_version.split("."))):
                            status = "Version downgrade"
                except ValueError:
                    pass
            else:
                matching = next(
                    (candidate for candidate in old_by_hash.get(_file_hash(path), []) if candidate not in paired_old),
                    None,
                )
                if matching:
                    old = old_files[matching]
                    paired_old.add(matching)
                    old_version, current_version, status = _binary_version(old), _binary_version(path), "Moved"
                else:
                    old_version, current_version, status = "–", _binary_version(path), "New"
            rows.append({
                "component": component_name,
                "file": relative,
                "baseline_path": (
                    f"{baseline['code_drop']}/{group}/{relative}" if baseline else "No baseline found"
                ),
                "baseline_version": old_version,
                "current_version": current_version,
                "status": status,
                "baseline_drop": baseline["code_drop"] if baseline else "",
                "baseline_local_path": str(baseline_root) if baseline_root else "",
            })
        for relative, path in sorted(old_files.items()):
            if relative not in paired_old:
                rows.append({
                    "component": component_name,
                    "file": relative,
                    "baseline_path": f"{baseline['code_drop']}/{group}/{relative}" if baseline else "",
                    "baseline_version": _binary_version(path),
                    "current_version": "–",
                    "status": "Removed",
                    "baseline_drop": baseline["code_drop"] if baseline else "",
                    "baseline_local_path": str(baseline_root) if baseline_root else "",
                })
    return rows


def compare_release_history(
    current_root: Path,
    baseline_options: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    results = []
    for component_path, choices in sorted(baseline_options.items()):
        area, component = component_path.split("/", 1)
        current_component = current_root / area / component
        current_files = {
            path.relative_to(current_component).as_posix(): path
            for path in current_component.rglob("*") if path.is_file()
        } if current_component.is_dir() else {}
        for choice in choices:
            baseline_root = Path(choice["local_path"]) if choice.get("local_path") else None
            baseline_files = {
                path.relative_to(baseline_root).as_posix(): path
                for path in baseline_root.rglob("*") if path.is_file()
            } if baseline_root and baseline_root.is_dir() else {}
            for relative in sorted(set(current_files) | set(baseline_files)):
                current_file = current_files.get(relative)
                baseline_file = baseline_files.get(relative)
                current_hash = _file_hash(current_file) if current_file else ""
                baseline_hash = _file_hash(baseline_file) if baseline_file else ""
                if current_file is None:
                    status = "Missing from current"
                elif baseline_file is None:
                    status = "Added since baseline"
                elif current_hash == baseline_hash:
                    status = "Unchanged"
                else:
                    status = "Changed"
                key_changes: int | str = 0
                if (
                    current_file and baseline_file
                    and current_file.suffix.casefold() == ".json"
                ):
                    try:
                        old_json, _ = load_json(baseline_file)
                        new_json, _ = load_json(current_file)
                        old_values = flatten_json(old_json)
                        new_values = flatten_json(new_json)
                        key_changes = sum(
                            old_values.get(key) != new_values.get(key)
                            for key in set(old_values) | set(new_values)
                        )
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        key_changes = "N/A"
                results.append({
                    "area": area,
                    "component": component,
                    "file": relative,
                    "code_drop": choice["code_drop"],
                    "status": status,
                    "baseline_sha256": baseline_hash or "–",
                    "current_sha256": current_hash or "–",
                    "json_key_changes": key_changes if current_file and current_file.suffix.casefold() == ".json" else "",
                })
    return results


def folder_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(bytes.fromhex(_file_hash(path)))
    return digest.hexdigest()


def svn_executable() -> str:
    configured = os.environ.get("SVN_EXECUTABLE", "svn")
    found = shutil.which(configured)
    if not found:
        raise WorkflowError(
            "The Subversion command-line client was not found. Install Apache Subversion and "
            "ensure svn.exe is on PATH, or set SVN_EXECUTABLE to its full path."
        )
    return found


def run_svn(
    arguments: list[str],
    username: str = "",
    password: str = "",
    input_data: str | None = None,
) -> subprocess.CompletedProcess[str]:
    executable = svn_executable()
    args = [executable, "--non-interactive", "--no-auth-cache"]
    if username.strip():
        args.extend(["--username", username.strip()])
    stdin_data = input_data
    if password:
        args.append("--password-from-stdin")
        stdin_data = password + "\n"
    result = subprocess.run(
        args + arguments,
        input=stdin_data,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
        check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise WorkflowError(f"SVN command failed: {detail[-1600:]}")
    return result


def svn_export(
    url: str, destination: Path, revision: str = "HEAD", username: str = "", password: str = ""
) -> None:
    run_svn(["export", "--force", "-r", revision, url, str(destination)], username, password)


def svn_directory_entries(
    url: str, username: str = "", password: str = "", recursive: bool = False
) -> list[dict[str, str]]:
    arguments = ["list", "--xml", "-r", "HEAD"]
    if recursive:
        arguments.append("--recursive")
    result = run_svn(arguments + [url], username, password)
    import xml.etree.ElementTree as ET

    tree = ET.fromstring(result.stdout)
    entries = []
    for entry in tree.findall(".//entry"):
        name = entry.findtext("name", "")
        if not name or (not recursive and "/" in name.strip("/")):
            continue
        entries.append({
            "name": name.rstrip("/"),
            "kind": entry.get("kind", ""),
            "revision": entry.find("commit").get("revision", "") if entry.find("commit") is not None else "",
        })
    return entries


def svn_component_revision(
    url: str, component: str, username: str = "", password: str = ""
) -> str | None:
    result = run_svn(["list", "--xml", "-r", "HEAD", url], username, password)
    import xml.etree.ElementTree as ET

    tree = ET.fromstring(result.stdout)
    for entry in tree.findall(".//entry"):
        if entry.findtext("name", "").rstrip("/") == component:
            commit = entry.find("commit")
            return commit.get("revision", "") if commit is not None else ""
    return None


def svn_import(
    source: Path,
    destination_url: str,
    message: str,
    username: str = "",
    password: str = "",
) -> tuple[str, str]:
    result = run_svn(
        ["import", "--depth", "infinity", str(source), destination_url, "--message", message],
        username,
        password,
    )
    match = re.search(r"Committed revision (\d+)\.", result.stdout + result.stderr)
    revision = match.group(1) if match else ""
    return revision, (result.stdout + result.stderr).strip()


def safe_url_child(base: str, *parts: str) -> str:
    quoted = [quote(part, safe="") for part in parts]
    return base.rstrip("/") + "/" + "/".join(quoted)
