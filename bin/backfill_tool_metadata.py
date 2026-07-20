#!/usr/bin/env python3
"""Backfill Uuid, Created, Updated, VerificationLevel on yaml/** tools."""

from __future__ import annotations

import re
import subprocess
import uuid
from datetime import date
from pathlib import Path

try:
    import yaml
except ImportError:
    raise SystemExit("PyYAML required: pip install pyyaml")

ROOT = Path(__file__).resolve().parents[1]
YAML_ROOT = ROOT / "yaml"
TODAY = date.today().isoformat()
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL namespace


def stable_uuid(tool_id: str) -> str:
    return str(uuid.uuid5(NAMESPACE, f"lolgai.tool/{tool_id}"))


def git_first_commit_date(path: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "log", "--follow", "--diff-filter=A", "--format=%aI", "--", str(path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        lines = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
        if not lines:
            return None
        return lines[-1][:10]
    except OSError:
        return None


def git_last_commit_date(path: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%aI", "--", str(path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        line = out.stdout.strip()
        return line[:10] if line else None
    except OSError:
        return None


def normalize_date(value: object) -> str | None:
    if not value:
        return None
    s = str(value).strip().strip("'\"")
    if DATE_RE.match(s):
        return s
    if len(s) >= 10 and DATE_RE.match(s[:10]):
        return s[:10]
    return None


def infer_verification_level(doc: dict) -> str:
    explicit = str(doc.get("VerificationLevel") or "").strip().lower()
    if explicit in {"unverified", "documented", "observed"}:
        return explicit

    coverage = doc.get("Coverage") or {}
    empirical = str(coverage.get("EmpiricalNotes") or doc.get("EmpiricalNotes") or "").lower()
    verified = bool(coverage.get("Verified"))

    lab_markers = (
        "lab-",
        "lab ",
        "lab hosts",
        "lab-verified",
        "empirically verified",
        "observed:",
        "observed binaries",
        "codesign",
        "authenticode",
        "winget",
        "install-genai-tools.sh",
    )
    has_observed_binary = "observed:" in empirical or "observed binaries" in empirical
    if verified and (has_observed_binary or any(m in empirical for m in lab_markers)):
        return "observed"
    if verified:
        return "documented"
    return "unverified"


def dump_yaml(doc: dict) -> str:
    return yaml.dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False)


def backfill_file(path: Path, *, touch_updated: bool = False) -> dict[str, str]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        return {"skip": str(path)}

    tool_id = str(doc.get("Id") or path.stem)
    changes: list[str] = []

    if not doc.get("Uuid"):
        doc["Uuid"] = stable_uuid(tool_id)
        changes.append("Uuid")

    created = normalize_date(doc.get("Created"))
    if not created:
        created = git_first_commit_date(path) or TODAY
        doc["Created"] = created
        changes.append("Created")

    updated = normalize_date(doc.get("Updated")) or normalize_date(doc.get("LastModified"))
    if touch_updated or not updated:
        doc["Updated"] = TODAY if touch_updated else (git_last_commit_date(path) or updated or created)
        changes.append("Updated")
    elif doc.get("LastModified") and not doc.get("Updated"):
        doc["Updated"] = normalize_date(doc.get("LastModified")) or TODAY
        changes.append("Updated")

    # Keep LastModified in sync for legacy readers until fully migrated
    doc["LastModified"] = doc["Updated"]

    level = infer_verification_level(doc)
    if doc.get("VerificationLevel") != level:
        doc["VerificationLevel"] = level
        changes.append(f"VerificationLevel={level}")

    if changes:
        path.write_text(dump_yaml(doc), encoding="utf-8")

    return {"path": str(path.relative_to(ROOT)), "changes": ",".join(changes) or "none"}


def main() -> int:
    files = sorted(YAML_ROOT.rglob("*.yaml")) + sorted(YAML_ROOT.rglob("*.yml"))
    touched = 0
    for path in files:
        result = backfill_file(path)
        if result.get("changes") and result["changes"] != "none":
            touched += 1
            print(f"{result['path']}: {result['changes']}")
    print(f"Backfilled {touched}/{len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
