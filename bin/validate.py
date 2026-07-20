#!/usr/bin/env python3
"""Validate all yaml/**/*.yaml against schema/lolgai.tool.schema.json."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "lolgai.tool.schema.json"
YAML_ROOT = ROOT / "yaml"

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
VERIFICATION_LEVELS = {"unverified", "documented", "observed"}
LOCALHOST_SERVE_RE = re.compile(r"(?i)(127\.0\.0\.1|localhost|\bserve\s*$)")
PUBLIC_BIND_RE = re.compile(r"(?i)0\.0\.0\.0|--host\s+0\.0\.0\.0|OLLAMA_HOST=0\.0\.0\.0")
CAPABILITY_ABUSE_PATTERNS: dict[str, re.Pattern[str]] = {
    "Tunnel": re.compile(r"(?i)tunnel|T1572"),
    "MCP": re.compile(r"(?i)\bmcp\b|mcps|mcp_|context.?server|T1106"),
    "Headless": re.compile(r"(?i)-p\b|--print|--headless|--json|headless"),
    "Bypass": re.compile(
        r"(?i)dangerously|skip-permission|allow-all|yolo|--force|--auto|--trust|"
        r"auto-approve|always-approve|trust-all|--yes-always"
    ),
}
GENERIC_ABUSE_RE = re.compile(
    r"(?i)find world-readable secrets|read ~/.aws/credentials and ~/.ssh|"
    r"VS Code extension — abuse via extension host|"
    r"completion extension — no standalone CLI"
)
BENIGN_ABUSE_CMD_RE = re.compile(
    r"(?i)"
    r"summarize logs|summarize dmesg|summarize ticket|summarize file|summarize document|"
    r"summarize auth\.log|summarize stdin|summarize git diff|summarize threat report|"
    r"hello\"|explain this|review repo for credentials|audit repo\"|analyze code|"
    r"quick inference|fast inference|run prompt|inference prompt|translate log|"
    r"implement feature|fix lint|fix failing|add tests|scaffold API|generate unit|"
    r"refactor payment|apply patch set|map repo architecture|explain this codebase|"
    r"explain this vulnerability|research question|question about logs|prompt text|"
    r"deepseek chat \"summarize|ollama run llama.*hello|--help\s*$|mcp list\s*$"
)
THEATER_DESC_RE = re.compile(
    r"(?i)^(non-interactive query|deepseek cli chat|one-shot prompt|terminal chat|"
    r"direct messages api from shell|fabric pattern prompt|shell-gpt one-shot|"
    r"community chatgpt cli|cohere cli chat|mistral cli chat|groq cli chat|"
    r"fetch arbitrary urls|query local sqlite via mcp|mcp stdio bridge|"
    r"headless browser automation via mcp|in-memory mcp knowledge graph|"
    r"mcp bridge to local postgres|run mcp server process|debug/proxy mcp traffic)$"
)
PRODUCT_PURPOSE_ABUSE_RE = re.compile(
    r"(?i)\bfetch arbitrary urls\b|\bquery local sqlite\b|\bmcp stdio bridge\b|"
    r"\bheadless browser automation via mcp\b|\bin-memory mcp knowledge\b|"
    r"\brun mcp server process\b|\bdebug/proxy mcp traffic\b"
)
WEAK_SIGNING_DEPTH = {"none", "partial", "shared_host", "adhoc"}
STRONG_SIGNING_DEPTH = {"full", "authenticode"}
PROCESS_NAME_COLLISIONS = {"agent", "cline", "code helper (plugin)", "python", "node", "code helper"}


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def normalize_date_field(value: object) -> str | None:
    if not value:
        return None
    s = str(value).strip().strip("'\"")
    if DATE_RE.match(s):
        return s
    if len(s) >= 10 and DATE_RE.match(s[:10]):
        return s[:10]
    return None


def validate_basic(doc: dict, path: Path, errors: list[str], warnings: list[str]) -> None:
    required = ["Name", "Id", "Category", "Details"]
    for key in required:
        if key not in doc:
            errors.append(f"{path}: missing required field '{key}'")
    details = doc.get("Details") or {}
    if isinstance(details, dict) and not details.get("Binaries"):
        errors.append(f"{path}: Details.Binaries required")
    tool_id = doc.get("Id")
    if tool_id and path.stem != tool_id:
        errors.append(f"{path}: filename stem '{path.stem}' != Id '{tool_id}'")

    uuid_val = str(doc.get("Uuid") or "").strip()
    if not uuid_val:
        errors.append(f"{path}: missing required field 'Uuid'")
    elif not UUID_RE.match(uuid_val):
        errors.append(f"{path}: Uuid must be a valid UUID ({uuid_val!r})")

    for field in ("Created", "Updated"):
        val = normalize_date_field(doc.get(field))
        if not val:
            errors.append(f"{path}: missing or invalid {field} (YYYY-MM-DD required)")
        elif not DATE_RE.match(val):
            errors.append(f"{path}: invalid {field} date {val!r}")

    level = str(doc.get("VerificationLevel") or "").strip().lower()
    if not level:
        errors.append(f"{path}: missing VerificationLevel (unverified|documented|observed)")
    elif level not in VERIFICATION_LEVELS:
        errors.append(f"{path}: invalid VerificationLevel {level!r}")

    if level == "observed":
        coverage = doc.get("Coverage") or {}
        empirical = str(coverage.get("EmpiricalNotes") or doc.get("EmpiricalNotes") or "")
        signing = doc.get("Signing") or {}
        has_signing = any(isinstance(v, dict) and v for v in signing.values())
        if not empirical.strip() and not has_signing:
            warnings.append(
                f"{path}: VerificationLevel=observed but no Coverage.EmpiricalNotes or Signing evidence"
            )

    commands = doc.get("Commands") or []
    if len(commands) < 1:
        errors.append(f"{path}: Commands must include at least one entry")
    if not commands:
        warnings.append(f"{path}: no Commands entries")
        return

    details = doc.get("Details") or {}
    bins = details.get("Binaries") or []
    bin_name = str(bins[0]).split(".exe")[0] if bins else ""
    cli_exe = str(details.get("CliExecutable") or bin_name or doc.get("Id") or "").split(".exe")[0]
    usages: set[str] = set()
    generic_only = True
    normal_cmds: set[str] = set()
    abuse_cmds: list[tuple[int, str]] = []
    for idx, cmd in enumerate(commands):
        if not isinstance(cmd, dict):
            errors.append(f"{path}: Commands[{idx}] must be a mapping")
            continue
        usage = str(cmd.get("Usage") or "").strip().lower()
        if not usage:
            errors.append(f"{path}: Commands[{idx}] missing Usage (normal|abuse)")
        elif usage not in {"normal", "abuse", "legitimate", "legit"}:
            errors.append(f"{path}: Commands[{idx}] invalid Usage '{usage}'")
        else:
            usages.add("normal" if usage in {"normal", "legitimate", "legit"} else "abuse")

        mitre = str(cmd.get("MitreID") or "").strip()
        if mitre and not MITRE_RE.match(mitre):
            errors.append(f"{path}: Commands[{idx}] invalid MitreID '{mitre}'")

        cmdtxt = str(cmd.get("Command") or "").strip()
        desc = str(cmd.get("Description") or "")
        is_normal = usage in {"normal", "legitimate", "legit"}
        if is_normal:
            normal_cmds.add(cmdtxt)
        elif usage == "abuse":
            abuse_cmds.append((idx, cmdtxt))
            bare_names = {bin_name, cli_exe, str(doc.get("Id") or ""), f"{bin_name} --help", f"{cli_exe} --help"}
            if cmdtxt in bare_names or cmdtxt.strip() in bare_names:
                errors.append(
                    f"{path}: Commands[{idx}] abuse Command is bare binary/help "
                    f"({cmdtxt!r}) — that is normal operation, not dual-use"
                )
            elif cmdtxt in normal_cmds:
                errors.append(
                    f"{path}: Commands[{idx}] abuse Command equals a normal Command "
                    f"(must be dual-use, not identical benign usage)"
                )
            elif PRODUCT_PURPOSE_ABUSE_RE.search(desc):
                errors.append(
                    f"{path}: Commands[{idx}] abuse Description restates product purpose "
                    f"({desc!r}) — use a distinct dual-use pattern or omit abuse"
                )
            if BENIGN_ABUSE_CMD_RE.search(cmdtxt) and not re.search(
                r"(?i)\.aws|\.ssh|0\.0\.0\.0|dangerously|skip-permission|allow-all|"
                r"attacker|stolen|\$STOLEN|credential|secret|id_ed25519|/tmp/leak",
                cmdtxt + " " + desc,
            ):
                warnings.append(
                    f"{path}: Commands[{idx}] abuse Command looks like normal dev activity "
                    f"({cmdtxt[:72]}…)"
                )
            if THEATER_DESC_RE.search(desc.strip()):
                warnings.append(
                    f"{path}: Commands[{idx}] abuse Description is generic theater "
                    f"({desc!r}) — name the dual-use (credential ingest, public bind, bypass flag)"
                )
        if is_normal and mitre == "T1048":
            if not PUBLIC_BIND_RE.search(cmdtxt) and (
                LOCALHOST_SERVE_RE.search(cmdtxt) or cmdtxt.strip().endswith(" serve")
            ):
                errors.append(
                    f"{path}: Commands[{idx}] normal localhost serve must not use MitreID T1048 "
                    f"(use abuse + public bind, or omit MITRE on normal serve)"
                )

        if not GENERIC_ABUSE_RE.search(cmdtxt + " " + desc):
            generic_only = False

    if "normal" not in usages:
        errors.append(f"{path}: Commands missing at least one Usage: normal entry")

    tid = str(doc.get("Id") or "")
    if generic_only and tid not in {
        "claude",
        "cursor",
        "google-antigravity",
        "github-copilot",
        "codex-openai",
        "ollama",
        "gemini-cli",
        "aider",
        "cline",
        "windsurf",
        "kiro",
    }:
        warnings.append(
            f"{path}: only generic/template command recipes — add concrete Commands for this tool"
        )

    details_caps = doc.get("Details") or {}
    caps = {str(x) for x in (details_caps.get("Capabilities") or [])}
    abuse_blob = " ".join(
        f"{cmd.get('Command', '')} {cmd.get('Description', '')}"
        for cmd in commands
        if str(cmd.get("Usage") or "").strip().lower() in {"abuse", "lol", "dual-use", "dual_use"}
        or (
            str(cmd.get("Usage") or "").strip().lower() not in {"normal", "legitimate", "legit"}
            and re.search(
                r"(?i)bypass|exfil|credential|0\.0\.0\.0|dangerously|tunnel|attacker|stolen",
                f"{cmd.get('Command', '')} {cmd.get('Description', '')}",
            )
        )
    )
    for cap in sorted(caps & CAPABILITY_ABUSE_PATTERNS.keys()):
        if "abuse" not in usages:
            continue
        if not CAPABILITY_ABUSE_PATTERNS[cap].search(abuse_blob):
            warnings.append(
                f"{path}: Capability {cap!r} documented but no abuse recipe covers that option class "
                f"(tunnel/MCP/bypass/headless) — extend Commands in this YAML"
            )
    if ("local_llm" in str(doc.get("Category") or "") or tid in {"ollama", "vllm", "tabby-server", "localai"}) and "abuse" in usages:
        if not PUBLIC_BIND_RE.search(abuse_blob):
            warnings.append(
                f"{path}: local LLM server but no public-bind abuse (0.0.0.0 / OLLAMA_HOST) — add env/host recipe"
            )

    signing = doc.get("Signing") or {}
    if not signing:
        warnings.append(f"{path}: missing Signing section")

    details = doc.get("Details") or {}
    website = str(details.get("Website") or doc.get("OfficialUrl") or "").strip()
    if not website:
        warnings.append(f"{path}: missing official link (Details.Website or OfficialUrl)")
    for os_name, block in signing.items():
        if not isinstance(block, dict):
            continue
        depth = str(block.get("Depth") or "").strip().lower()
        usable = block.get("UsableForAttribution")
        if usable is True and depth in WEAK_SIGNING_DEPTH:
            errors.append(
                f"{path}: Signing.{os_name} UsableForAttribution=true incompatible with Depth={depth!r}"
            )


def _tool_binaries(doc: dict) -> set[str]:
    details = doc.get("Details") or {}
    out: set[str] = set()
    for b in details.get("Binaries") or []:
        out.add(str(b).lower())
        if str(b).lower().endswith(".exe"):
            out.add(str(b).lower()[:-4])
    return out


def has_strong_attribution(doc: dict) -> bool:
    """Grade A requires usable signing or a high-reliability product-specific signal."""
    signing = doc.get("Signing") or {}
    for block in signing.values():
        if not isinstance(block, dict):
            continue
        if block.get("UsableForAttribution") is True:
            depth = str(block.get("Depth") or "").strip().lower()
            if depth in STRONG_SIGNING_DEPTH:
                return True

    bins = _tool_binaries(doc)
    for op in doc.get("DetectionOpportunities") or []:
        for sig in op.get("AttributionSignals") or []:
            if str(sig.get("Reliability") or "").strip().lower() != "high":
                continue
            field = str(sig.get("Field") or "").strip().lower()
            val = str(sig.get("Value") or "").strip().lower()
            if field in {"process.executable", "process.command_line"}:
                return True
            if field == "process.name" and val and val not in PROCESS_NAME_COLLISIONS:
                return True
            if field == "process.parent.name":
                continue  # corroboration-only — not sufficient alone for Grade A
            if field == "process.parent.code_signature.signing_id":
                return True
    return False


def validate_grade(doc: dict, path: Path, errors: list[str]) -> None:
    coverage = doc.get("Coverage") or {}
    grade = str(coverage.get("ReadinessGrade") or "").strip().upper()
    if grade == "A" and not has_strong_attribution(doc):
        errors.append(
            f"{path}: ReadinessGrade A requires strong attribution "
            f"(Signing.UsableForAttribution on full/authenticode depth, or high-reliability "
            f"product-specific signal — not shared Code Helper / generic process.name alone)"
        )


def main() -> int:
    if not YAML_ROOT.exists():
        print(f"Missing {YAML_ROOT}", file=sys.stderr)
        return 1

    files = sorted(YAML_ROOT.rglob("*.yaml")) + sorted(YAML_ROOT.rglob("*.yml"))
    if not files:
        print("No YAML files found under yaml/", file=sys.stderr)
        return 1

    validator = None
    try:
        import jsonschema

        schema = load_schema()
        validator = jsonschema.Draft202012Validator(schema)
    except ImportError:
        print("FAIL: jsonschema required for schema validation (pip install -r requirements.txt)", file=sys.stderr)
        return 1

    errors: list[str] = []
    warnings: list[str] = []
    ids: set[str] = set()
    for path in files:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{path}: YAML parse error: {exc}")
            continue
        if not isinstance(doc, dict):
            errors.append(f"{path}: root must be a mapping")
            continue
        validate_basic(doc, path, errors, warnings)
        validate_grade(doc, path, errors)
        tool_id = doc.get("Id")
        if isinstance(tool_id, str):
            if tool_id in ids:
                errors.append(f"{path}: duplicate Id '{tool_id}'")
            ids.add(tool_id)
        if validator is not None:
            for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.path)):
                loc = ".".join(str(p) for p in err.path) or "(root)"
                errors.append(f"{path}: {loc}: {err.message}")

    if warnings:
        print(f"WARN ({len(warnings)} note(s)):")
        for w in warnings[:25]:
            print(f"  - {w}")
        if len(warnings) > 25:
            print(f"  ... +{len(warnings) - 25} more")

    if errors:
        print(f"FAIL ({len(errors)} issue(s)):")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"OK — {len(files)} tool file(s) validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
