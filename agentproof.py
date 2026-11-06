#!/usr/bin/env python3
"""AgentProof: local evidence and rollback guard for AI-assisted delivery."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import html
import json
import os
import re
import shutil
import stat as stat_module
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable


VERSION = "0.1.0"
DEFAULT_EXCLUDES = {
    ".git",
    ".agentproof",
    ".next",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
}
DEFAULT_SENSITIVE_PATTERNS = [
    ".env*",
    "*.key",
    "*.pem",
    "id_rsa*",
    "auth.json",
    "credentials",
    "credentials.*",
    "secrets",
    "secrets.*",
    ".ssh/**",
    ".aws/credentials",
    ".npmrc",
]
NAMED_CREDENTIAL_RE = re.compile(r"(credentials|secrets)[-_]")
DOC_SUFFIXES = (".md", ".mdx", ".rst", ".adoc")
SECRET_RE = re.compile(
    r"(?i)(sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{12,}|"
    r"(?:access[_ -]?token|api[_ -]?key|app[_ -]?secret)\s*[:=]\s*\S+)"
)


class AgentProofError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact(text: str | bytes, limit: int = 4000) -> str:
    # TimeoutExpired preserves captured output as bytes even with text=True.
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    cleaned = SECRET_RE.sub("[REDACTED]", text or "")
    return cleaned[-limit:]


def path_is_sensitive(rel: str, patterns: Iterable[str]) -> bool:
    # Match case-insensitively on every platform so case aliases on macOS do
    # not bypass credential protection.
    normalized = rel.replace(os.sep, "/").casefold()
    parts = normalized.split("/")
    # Check nested credential directories and sensitive directory ancestors too.
    candidates = parts + ["/".join(parts[i:]) for i in range(len(parts))]
    # secrets_prod.json / credentials-backup.yaml are credentials too; only documents about them are not.
    if any(NAMED_CREDENTIAL_RE.match(part) and not part.endswith(DOC_SUFFIXES) for part in parts):
        return True
    for pattern in patterns:
        pat = pattern.replace(os.sep, "/").casefold()
        if any(fnmatch.fnmatch(value, pat) for value in candidates):
            return True
        if pat.endswith("/**") and pat[:-3] in candidates:
            return True
    return False


def merge_sensitive_patterns(*groups: Any) -> list[str]:
    patterns = list(DEFAULT_SENSITIVE_PATTERNS)
    for group in groups:
        if not isinstance(group, list) or not all(isinstance(x, str) and x for x in group):
            raise AgentProofError("sensitive_patterns must be an array of non-empty strings")
        patterns.extend(group)
    return list(dict.fromkeys(patterns))


def iter_project_entries(project: Path, excludes: set[str]) -> Iterable[Path]:
    for root, dirs, files in os.walk(project, topdown=True, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in excludes)
        root_path = Path(root)
        for name in sorted(files):
            yield root_path / name
        for name in sorted(dirs):
            candidate = root_path / name
            if candidate.is_symlink():
                yield candidate


def scan_project(
    project: Path,
    *,
    sensitive_patterns: list[str],
    excludes: set[str],
    max_hash_bytes: int,
    backup_dir: Path | None = None,
    max_copy_bytes: int = 0,
) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    for path in iter_project_entries(project, excludes):
        try:
            rel = path.relative_to(project).as_posix()
            stat = path.lstat()
        except OSError:
            continue
        sensitive = path_is_sensitive(rel, sensitive_patterns)
        item: dict[str, Any] = {
            "type": "symlink" if path.is_symlink() else "file",
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "mode": stat.st_mode & 0o777,
            "sensitive": sensitive,
            "sha256": None,
            "backup": None,
        }
        if path.is_symlink():
            item["link_target"] = os.readlink(path)
        elif not stat_module.S_ISREG(stat.st_mode):
            item["type"] = "special"
            item["note"] = "metadata only; not a regular file"
        elif sensitive:
            item["note"] = "metadata only; sensitive content was not read"
        elif stat.st_size <= max_hash_bytes:
            try:
                item["sha256"] = sha256_file(path)
                if backup_dir is not None and stat.st_size <= max_copy_bytes:
                    destination = backup_dir / rel
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, destination)
                    item["backup"] = f"files/{rel}"
            except OSError as exc:
                item["error"] = str(exc)
        else:
            item["note"] = f"metadata only; file exceeds {max_hash_bytes} bytes"
        entries[rel] = item
    return entries


def git_context(project: Path) -> dict[str, Any]:
    probe = subprocess.run(
        ["git", "-C", str(project), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        return {"is_git": False}
    head = subprocess.run(
        ["git", "-C", str(project), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    )
    status = subprocess.run(
        ["git", "-C", str(project), "status", "--porcelain=v1", "-z"],
        capture_output=True,
    )
    return {
        "is_git": True,
        "head": head.stdout.strip() if head.returncode == 0 else None,
        "dirty_entries": len([x for x in status.stdout.split(b"\0") if x]),
    }


def snapshot_project(
    project: Path,
    output: Path,
    *,
    max_hash_bytes: int = 20 * 1024 * 1024,
    max_copy_bytes: int = 5 * 1024 * 1024,
    sensitive_patterns: list[str] | None = None,
) -> Path:
    project = project.resolve()
    output = output.resolve()
    if not project.is_dir():
        raise AgentProofError(f"project directory does not exist: {project}")
    if output.exists():
        raise AgentProofError(f"snapshot output already exists: {output}")
    output.mkdir(parents=True)
    # Custom rules may extend, but must never disable the built-in protection.
    patterns = merge_sensitive_patterns(sensitive_patterns or [])
    entries = scan_project(
        project,
        sensitive_patterns=patterns,
        excludes=set(DEFAULT_EXCLUDES),
        max_hash_bytes=max_hash_bytes,
        backup_dir=output / "files",
        max_copy_bytes=max_copy_bytes,
    )
    manifest = {
        "schema_version": 1,
        "agentproof_version": VERSION,
        "created_at": utc_now(),
        "project": str(project),
        "limits": {
            "max_hash_bytes": max_hash_bytes,
            "max_copy_bytes": max_copy_bytes,
        },
        "sensitive_patterns": patterns,
        "git": git_context(project),
        "entries": entries,
        "summary": {
            "entry_count": len(entries),
            "content_backups": sum(bool(x.get("backup")) for x in entries.values()),
            "sensitive_metadata_only": sum(bool(x.get("sensitive")) for x in entries.values()),
        },
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest_path


def load_manifest(path: Path) -> tuple[Path, dict[str, Any]]:
    path = path.resolve()
    manifest_path = path / "manifest.json" if path.is_dir() else path
    if not manifest_path.is_file():
        raise AgentProofError(f"snapshot manifest not found: {manifest_path}")
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AgentProofError(f"invalid snapshot manifest: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("entries"), dict):
        raise AgentProofError("unsupported snapshot schema")
    for rel, entry in data["entries"].items():
        if (not rel or Path(rel).is_absolute() or any(part in {"", ".", ".."} for part in rel.split("/"))
                or "\x00" in rel or not isinstance(entry, dict)):
            raise AgentProofError("invalid snapshot entry or relative path")
    merge_sensitive_patterns(data.get("sensitive_patterns", []))
    return manifest_path, data


def compare_entries(
    baseline: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]
) -> dict[str, list[str]]:
    before = set(baseline)
    after = set(current)
    added = sorted(after - before)
    deleted = sorted(before - after)
    modified: list[str] = []
    for rel in sorted(before & after):
        left, right = baseline[rel], current[rel]
        if left.get("type") != right.get("type") or left.get("mode") != right.get("mode"):
            modified.append(rel)
        elif left.get("type") == "symlink":
            if left.get("link_target") != right.get("link_target"):
                modified.append(rel)
        elif left.get("sha256") is not None and right.get("sha256") is not None:
            if left["sha256"] != right["sha256"]:
                modified.append(rel)
        elif (left.get("size"), left.get("mtime_ns")) != (
            right.get("size"),
            right.get("mtime_ns"),
        ):
            modified.append(rel)
    return {"added": added, "modified": modified, "deleted": deleted}


def safe_project_path(project: Path, relative: str) -> Path:
    if Path(relative).is_absolute():
        raise AgentProofError(f"path must be relative to the project: {relative}")
    try:
        target = (project / relative).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise AgentProofError(f"path cannot be resolved: {relative}") from exc
    try:
        target.relative_to(project.resolve())
    except ValueError as exc:
        raise AgentProofError(f"path escapes project: {relative}") from exc
    return target


def image_dimensions(path: Path) -> tuple[int, int] | None:
    try:
        with path.open("rb") as handle:
            head = handle.read(32)
            if head[:8] == b"\x89PNG\r\n\x1a\n" and head[12:16] == b"IHDR":
                return struct.unpack(">II", head[16:24])
            if head[:6] in {b"GIF87a", b"GIF89a"}:
                return struct.unpack("<HH", head[6:10])
            if head[:2] != b"\xff\xd8":
                return None
            handle.seek(2)
            while True:
                marker_start = handle.read(1)
                if not marker_start:
                    return None
                if marker_start != b"\xff":
                    continue
                marker = handle.read(1)
                while marker == b"\xff":
                    marker = handle.read(1)
                if marker in {bytes([x]) for x in range(0xC0, 0xC4)} | {
                    bytes([x]) for x in range(0xC5, 0xC8)
                } | {bytes([x]) for x in range(0xC9, 0xCC)} | {
                    bytes([x]) for x in range(0xCD, 0xD0)
                }:
                    _length = struct.unpack(">H", handle.read(2))[0]
                    _precision = handle.read(1)
                    height, width = struct.unpack(">HH", handle.read(4))
                    return width, height
                length_raw = handle.read(2)
                if len(length_raw) != 2:
                    return None
                length = struct.unpack(">H", length_raw)[0]
                handle.seek(max(0, length - 2), os.SEEK_CUR)
    except (OSError, struct.error):
        return None


def run_command_check(project: Path, check: dict[str, Any]) -> dict[str, Any]:
    project = project.resolve()
    name = str(check.get("name") or "unnamed command")
    argv = check.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        return {"name": name, "passed": False, "error": "argv must be a non-empty string list"}
    cwd = safe_project_path(project, str(check.get("cwd") or "."))
    timeout = max(1, min(int(check.get("timeout", 120)), 1800))
    started = time.monotonic()
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env={**os.environ, "NO_COLOR": "1"},
        )
        return {
            "name": name,
            "argv": argv,
            "cwd": str(cwd.relative_to(project)),
            "passed": result.returncode == 0,
            "exit_code": result.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout_tail": redact(result.stdout),
            "stderr_tail": redact(result.stderr),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "name": name,
            "argv": argv,
            "passed": False,
            "error": f"timed out after {timeout}s",
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout_tail": redact(exc.stdout or ""),
            "stderr_tail": redact(exc.stderr or ""),
        }
    except OSError as exc:
        return {"name": name, "argv": argv, "passed": False, "error": str(exc)}


def check_artifact(
    project: Path, check: dict[str, Any], *, patterns: list[str] | None = None
) -> dict[str, Any]:
    name = str(check.get("name") or check.get("path") or "unnamed artifact")
    relative = str(check.get("path") or "")
    result: dict[str, Any] = {"name": name, "path": relative, "passed": False, "problems": []}
    if not relative:
        result["problems"].append("path is required")
        return result
    protected = merge_sensitive_patterns(patterns or [])
    if path_is_sensitive(relative, protected):
        result["problems"].append("sensitive artifact content must not be read")
        return result
    try:
        path = safe_project_path(project, relative)
    except AgentProofError as exc:
        result["problems"].append(str(exc))
        return result
    if path_is_sensitive(path.relative_to(project.resolve()).as_posix(), protected):
        result["problems"].append("sensitive artifact content must not be read")
        return result
    if not path.is_file():
        result["problems"].append("file does not exist")
        return result
    stat = path.stat()
    result["bytes"] = stat.st_size
    min_bytes = int(check.get("min_bytes", 1))
    if stat.st_size < min_bytes:
        result["problems"].append(f"file is smaller than {min_bytes} bytes")
    expected_sha = check.get("sha256")
    if expected_sha:
        actual_sha = sha256_file(path)
        result["sha256"] = actual_sha
        if actual_sha != expected_sha:
            result["problems"].append("SHA-256 mismatch")
    image_rules = check.get("image")
    if isinstance(image_rules, dict):
        dims = image_dimensions(path)
        result["image_dimensions"] = list(dims) if dims else None
        if not dims:
            result["problems"].append("unsupported or invalid image header")
        else:
            width, height = dims
            if width < int(image_rules.get("min_width", 1)):
                result["problems"].append("image width below minimum")
            if height < int(image_rules.get("min_height", 1)):
                result["problems"].append("image height below minimum")
    result["passed"] = not result["problems"]
    return result


def load_config(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AgentProofError(f"invalid config: {exc}") from exc
    if not isinstance(data, dict):
        raise AgentProofError("config must be a JSON object")
    if not isinstance(data.get("commands", []), list) or not isinstance(data.get("artifacts", []), list):
        raise AgentProofError("commands and artifacts must be arrays")
    for field in ("commands", "artifacts"):
        if not all(isinstance(check, dict) for check in data.get(field, [])):
            raise AgentProofError(f"{field} entries must be JSON objects")
    merge_sensitive_patterns(data.get("sensitive_patterns", []))
    return data


def render_html_report(report: dict[str, Any]) -> str:
    def badge(passed: bool) -> str:
        label = "PASS" if passed else "FAIL"
        return f'<span class="badge {label.lower()}">{label}</span>'

    diff = report["changes"]
    command_rows = "".join(
        f"<tr><td>{html.escape(x['name'])}</td><td>{badge(x['passed'])}</td>"
        f"<td>{html.escape(' '.join(x.get('argv', [])))}</td><td>{x.get('duration_seconds', '')}</td></tr>"
        for x in report["commands"]
    ) or '<tr><td colspan="4">No command checks configured.</td></tr>'
    artifact_rows = "".join(
        f"<tr><td>{html.escape(x['name'])}</td><td>{badge(x['passed'])}</td>"
        f"<td>{html.escape(x['path'])}</td><td>{html.escape('; '.join(x.get('problems', [])))}</td></tr>"
        for x in report["artifacts"]
    ) or '<tr><td colspan="4">No artifact checks configured.</td></tr>'
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,">
<title>AgentProof · {html.escape(report['verdict'])}</title><style>
:root{{--bg:#07111f;--panel:#101f33;--line:#29415e;--text:#edf7ff;--muted:#9db1c8;--ok:#73f0b5;--bad:#ff7a90;--accent:#4ddaf7}}
*{{box-sizing:border-box}}body{{margin:0;background:linear-gradient(145deg,#07111f,#0b1730);color:var(--text);font:15px/1.55 ui-sans-serif,system-ui,sans-serif}}
main{{max-width:1080px;margin:auto;padding:48px 22px}}h1{{font-size:42px;margin:0 0 8px}}h2{{margin-top:34px}}.muted{{color:var(--muted)}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.card{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}}
.metric{{font-size:28px;font-weight:800}}.badge{{font-weight:800;border-radius:999px;padding:4px 10px}}.pass{{background:#164b3d;color:var(--ok)}}.fail{{background:#5d2633;color:var(--bad)}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border-radius:12px;overflow:hidden}}th,td{{text-align:left;padding:12px;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--muted)}}code{{color:var(--accent)}}
@media(max-width:720px){{.grid{{grid-template-columns:1fr 1fr}}h1{{font-size:32px}}table{{font-size:12px;display:block;overflow-x:auto}}}}
</style></head><body><main>
<p class="muted">AGENTPROOF / LOCAL DELIVERY EVIDENCE</p><h1>{badge(report['passed'])} AI 交付验真报告</h1>
<p class="muted">{html.escape(report['generated_at'])} · {html.escape(report.get('project_label') or Path(report['project']).name)}</p>
<div class="grid"><div class="card"><div class="metric">{len(diff['added'])}</div><div class="muted">新增文件</div></div>
<div class="card"><div class="metric">{len(diff['modified'])}</div><div class="muted">修改文件</div></div>
<div class="card"><div class="metric">{len(diff['deleted'])}</div><div class="muted">删除文件</div></div>
<div class="card"><div class="metric">{report['rollback']['restorable_files']}</div><div class="muted">可恢复基线文件</div></div></div>
<h2>命令验收</h2><table><thead><tr><th>检查</th><th>结果</th><th>命令</th><th>秒</th></tr></thead><tbody>{command_rows}</tbody></table>
<h2>产物验收</h2><table><thead><tr><th>产物</th><th>结果</th><th>路径</th><th>问题</th></tr></thead><tbody>{artifact_rows}</tbody></table>
<h2>变更与安全</h2><div class="card"><p>敏感路径变更：<strong>{len(report['sensitive_changes'])}</strong></p>
<p>新增：{html.escape(', '.join(diff['added']) or '无')}</p><p>修改：{html.escape(', '.join(diff['modified']) or '无')}</p><p>删除：{html.escape(', '.join(diff['deleted']) or '无')}</p></div>
<p class="muted">AgentProof does not upload project contents. Sensitive paths are metadata-only by default.</p>
</main></body></html>"""


def verify_project(project: Path, baseline_path: Path, config_path: Path, output_dir: Path) -> dict[str, Any]:
    project = project.resolve()
    manifest_path, manifest = load_manifest(baseline_path)
    config = load_config(config_path)
    patterns = merge_sensitive_patterns(manifest.get("sensitive_patterns", []), config.get("sensitive_patterns", []))
    limits = manifest.get("limits") or {}
    current = scan_project(
        project,
        sensitive_patterns=patterns,
        excludes=set(DEFAULT_EXCLUDES),
        max_hash_bytes=int(limits.get("max_hash_bytes", 20 * 1024 * 1024)),
    )
    changes = compare_entries(manifest["entries"], current)
    sensitive_changes = sorted(
        rel
        for rel in changes["added"] + changes["modified"] + changes["deleted"]
        if path_is_sensitive(rel, patterns)
    )
    command_results = [run_command_check(project, x) for x in config.get("commands", [])]
    artifact_results = [check_artifact(project, x, patterns=patterns) for x in config.get("artifacts", [])]
    commands_pass = all(x["passed"] for x in command_results)
    artifacts_pass = all(x["passed"] for x in artifact_results)
    passed = commands_pass and artifacts_pass and not sensitive_changes
    report = {
        "schema_version": 1,
        "agentproof_version": VERSION,
        "generated_at": utc_now(),
        "project": str(project),
        "project_label": project.name,
        "baseline": str(manifest_path),
        "passed": passed,
        "verdict": "PASS" if passed else "FAIL",
        "changes": changes,
        "sensitive_changes": sensitive_changes,
        "commands": command_results,
        "artifacts": artifact_results,
        "rollback": {
            "restorable_files": sum(bool(x.get("backup")) for x in manifest["entries"].values()),
            "added_files_are_never_auto_deleted": True,
            "sensitive_files_are_not_copied": True,
        },
    }
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "report.html").write_text(render_html_report(report), encoding="utf-8")
    return report


def restore_file_path(root: Path, relative: str) -> Path:
    """Reject symlinks rather than silently restoring their resolved targets."""
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise AgentProofError(f"restore path contains a symlink: {relative}")
    target = safe_project_path(root, relative)
    if target.exists() and not target.is_file():
        raise AgentProofError(f"restore path is not a regular file: {relative}")
    return target


def restore_snapshot(
    project: Path, baseline_path: Path, *, selected: list[str] | None = None, yes: bool = False
) -> dict[str, Any]:
    project = project.resolve()
    manifest_path, manifest = load_manifest(baseline_path)
    snapshot_dir = manifest_path.parent
    patterns = merge_sensitive_patterns(manifest.get("sensitive_patterns", []))
    wanted = set(manifest["entries"] if selected is None else selected)
    if wanted - manifest["entries"].keys():
        raise AgentProofError("selected path is not present in the snapshot")
    plan: list[dict[str, Any]] = []
    validated: list[tuple[Path, Path, str]] = []
    for rel, entry in sorted(manifest["entries"].items()):
        if rel not in wanted:
            continue
        if entry.get("sensitive") or path_is_sensitive(rel, patterns):
            plan.append({"path": rel, "action": "skip", "reason": "sensitive content was not copied"})
            continue
        backup = entry.get("backup")
        if not backup:
            plan.append({"path": rel, "action": "skip", "reason": "no content backup"})
            continue
        if entry.get("type") != "file" or backup != f"files/{rel}":
            raise AgentProofError(f"invalid backup path or type: {rel}")
        expected_sha = entry.get("sha256")
        if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            raise AgentProofError(f"missing or invalid backup SHA-256: {rel}")
        source = restore_file_path(snapshot_dir, backup)
        target = restore_file_path(project, rel)
        try:
            if not source.is_file() or source.stat().st_size != entry.get("size"):
                raise AgentProofError(f"backup missing or size mismatch: {rel}")
            if sha256_file(source) != expected_sha:
                raise AgentProofError(f"backup SHA-256 mismatch: {rel}")
        except OSError as exc:
            raise AgentProofError(f"cannot validate backup: {rel}") from exc
        action = "restore" if target.exists() else "recreate"
        plan.append({"path": rel, "action": action})
        validated.append((source, target, expected_sha))
    # Validate the whole selection before the first write, including preview.
    if yes:
        for source, target, expected_sha in validated:
            temporary: Path | None = None
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(prefix=".agentproof-", dir=target.parent, delete=False) as handle:
                    temporary = Path(handle.name)
                shutil.copy2(source, temporary)
                if sha256_file(temporary) != expected_sha:
                    raise AgentProofError("backup changed during restore")
                # Replace the directory entry, never write through a hardlink.
                os.replace(temporary, target)
            except OSError as exc:
                raise AgentProofError(f"cannot restore file: {target.relative_to(project)}") from exc
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
    return {
        "mode": "applied" if yes else "preview",
        "project": str(project),
        "baseline": str(manifest_path),
        "plan": plan,
        "note": "Files added after the snapshot are never deleted automatically.",
    }


def default_snapshot_dir(project: Path) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return project / ".agentproof" / "snapshots" / stamp


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local evidence and rollback guard for AI-assisted delivery")
    parser.add_argument("--version", action="version", version=f"AgentProof {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    snapshot = sub.add_parser("snapshot", help="capture a metadata baseline and bounded rollback copy")
    snapshot.add_argument("--project", type=Path, default=Path.cwd())
    snapshot.add_argument("--output", type=Path)
    snapshot.add_argument("--max-hash-mb", type=int, default=20)
    snapshot.add_argument("--max-copy-mb", type=int, default=5)

    verify = sub.add_parser("verify", help="compare a baseline, run checks, and render evidence")
    verify.add_argument("--project", type=Path, default=Path.cwd())
    verify.add_argument("--baseline", type=Path, required=True)
    verify.add_argument("--config", type=Path, required=True)
    verify.add_argument("--output-dir", type=Path, required=True)

    restore = sub.add_parser("restore", help="preview or apply bounded restoration from a snapshot")
    restore.add_argument("--project", type=Path, default=Path.cwd())
    restore.add_argument("--baseline", type=Path, required=True)
    restore.add_argument("--path", action="append", dest="paths")
    restore.add_argument("--yes", action="store_true", help="apply the restore plan; omission is preview-only")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "snapshot":
            output = args.output or default_snapshot_dir(args.project.resolve())
            manifest = snapshot_project(
                args.project,
                output,
                max_hash_bytes=args.max_hash_mb * 1024 * 1024,
                max_copy_bytes=args.max_copy_mb * 1024 * 1024,
            )
            data = json.loads(manifest.read_text(encoding="utf-8"))
            print(json.dumps({"ok": True, "manifest": str(manifest), "summary": data["summary"]}, ensure_ascii=False))
            return 0
        if args.command == "verify":
            report = verify_project(args.project, args.baseline, args.config, args.output_dir)
            print(json.dumps({"ok": report["passed"], "verdict": report["verdict"], "report_dir": str(args.output_dir.resolve())}, ensure_ascii=False))
            return 0 if report["passed"] else 2
        result = restore_snapshot(args.project, args.baseline, selected=args.paths, yes=args.yes)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except AgentProofError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
