#!/usr/bin/env python3
"""Build website/public/api/* from yaml/** and emit site summary stats."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required: uv sync  (or: uv pip install pyyaml)", file=sys.stderr)
    sys.exit(1)

from reference_score import compute_reference_score

ROOT = Path(__file__).resolve().parents[1]
YAML_ROOT = ROOT / "yaml"
API_DIR = ROOT / "website" / "public" / "api"

FN_ALLOW = {"Shell", "Headless", "MCP", "Tunnel", "Bypass", "Local", "Creds"}

# When YAML omits Capabilities, derive filter chips from catalog category.
CATEGORY_DEFAULT_FNS: dict[str, set[str]] = {
    "cli_agent": {"Shell", "Headless"},
    "ide_agent": {"Shell", "Headless"},
    "ide_extension": {"Headless"},
    "tunnel": {"Tunnel"},
    "local_llm": {"Local"},
    "chat_cli": {"Headless"},
    "speech": {"Headless"},
    "image_gen": {"Headless"},
    "cloud_mlops": {"Headless"},
    "cloud_agent": {"Shell", "Headless"},
    "mcp": {"MCP"},
    "desktop": {"Headless"},
    "framework": {"Headless"},
    "api_only": {"Headless"},
    "other": {"Headless"},
}

# Command.Category values that are not site filter chips map to filters here.
CMD_CATEGORY_TO_FN: dict[str, str] = {
    "Execute": "Headless",
    "Shell": "Shell",
    "Headless": "Headless",
    "MCP": "MCP",
    "Tunnel": "Tunnel",
    "Bypass": "Bypass",
    "Local": "Local",
    "Creds": "Creds",
}

# Shared VS Code / Electron helper process names — not useful as catalog Binary column labels.
GENERIC_BINARIES = {
    "python",
    "python3",
    "python.exe",
    "python3.exe",
    "node",
    "node.exe",
    "electron",
    "electron.exe",
    "bash",
    "zsh",
    "sh",
    "cmd.exe",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "code",
    "code.exe",
    "code helper",
    "code helper (plugin)",
    "code helper (gpu)",
    "code helper (renderer)",
    "cursor helper",
    "cursor helper (plugin)",
    "cursor helper (gpu)",
    "cursor helper (renderer)",
    "windsurf helper",
    "windsurf helper (plugin)",
    "claude helper",
    "claude helper (plugin)",
    "claude helper (gpu)",
    "claude helper (renderer)",
}


def is_generic_binary(name: str | None) -> bool:
    n = str(name or "").strip().lower()
    if not n:
        return True
    if n in GENERIC_BINARIES:
        return True
    if "helper" in n and ("(" in n or n.endswith("helper")):
        return True
    return False


def catalog_binary(tool: dict) -> str:
    """Primary catalog label: CliExecutable, then first non-generic binary, then tool Id."""
    details = tool.get("Details") or {}
    cli = details.get("CliExecutable")
    if cli and not is_generic_binary(str(cli)):
        return str(cli)
    for binary in details.get("Binaries") or []:
        if binary and not is_generic_binary(str(binary)):
            return str(binary)
    for surface in tool.get("Surfaces") or []:
        if not isinstance(surface, dict):
            continue
        for binary in surface.get("Binaries") or []:
            if binary and not is_generic_binary(str(binary)):
                return str(binary)
    tool_id = str(tool.get("Id") or "")
    if tool_id and not is_generic_binary(tool_id):
        return tool_id
    return str(tool.get("Name") or tool_id or "unknown")


def catalog_sort_key(tool: dict) -> tuple[str, str, str]:
    """Case-insensitive catalog order: binary (table column), name, id."""
    primary = catalog_binary(tool)
    bin_key = primary.casefold()
    name = str(tool.get("Name") or tool.get("Id") or "").casefold()
    tool_id = str(tool.get("Id") or "")
    return (bin_key, name, tool_id)


def site_tool_sort_key(tool: dict) -> tuple[str, str, str]:
    """Match catalog_sort_key for flattened API rows."""
    bin_key = str(tool.get("bin") or tool.get("id") or "").casefold()
    name = str(tool.get("name") or tool.get("id") or "").casefold()
    tool_id = str(tool.get("id") or "")
    return (bin_key, name, tool_id)


def load_tools() -> list[dict]:
    tools: list[dict] = []
    files = sorted(YAML_ROOT.rglob("*.yaml")) + sorted(YAML_ROOT.rglob("*.yml"))
    for path in files:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            continue
        doc["_source"] = str(path.relative_to(ROOT))
        tools.append(doc)
    tools.sort(key=catalog_sort_key)
    return tools


def category_label(cat: str) -> str:
    labels = {
        "cli_agent": "CLI Agent",
        "ide_agent": "IDE Agent",
        "ide_extension": "IDE Extension",
        "tunnel": "Tunnel",
        "local_llm": "Local",
        "chat_cli": "Chat CLI",
        "speech": "Speech",
        "image_gen": "Image Gen",
        "cloud_mlops": "Cloud / MLOps",
        "cloud_agent": "Cloud Agent",
        "mcp": "MCP",
        "desktop": "Desktop",
        "framework": "Framework",
        "api_only": "API",
        "other": "Other",
    }
    if cat in labels:
        return labels[cat]
    return (cat or "").replace("_", " ").title()


def derive_fns(tool: dict, details: dict, commands: list) -> list[str]:
    """Build GTFOBins-style function chips; never leave the catalog cell empty."""
    fns: set[str] = {f for f in (details.get("Capabilities") or []) if f in FN_ALLOW}
    for cmd in commands:
        if not isinstance(cmd, dict):
            continue
        cat = cmd.get("Category")
        if cat in FN_ALLOW:
            fns.add(cat)
        elif cat in CMD_CATEGORY_TO_FN:
            mapped = CMD_CATEGORY_TO_FN[cat]
            if mapped in FN_ALLOW:
                # Shell-spawning tools get Shell instead of generic Headless for Execute.
                if cat == "Execute" and details.get("SpawnsShells"):
                    fns.add("Shell")
                else:
                    fns.add(mapped)
    if details.get("SpawnsShells"):
        fns.add("Shell")
    # Always include category defaults (e.g. local_llm → Local) so Type and
    # Function filters stay aligned for local runtimes like Ollama.
    fns |= set(CATEGORY_DEFAULT_FNS.get(tool.get("Category") or "", set()))
    if not fns:
        fns.add("Headless")
    return sorted(fns)


def infer_artifact_platforms(entry: dict | str) -> list[str]:
    """Return normalized OS list for an artifact path; empty means all platforms."""
    if isinstance(entry, str):
        path = entry
        explicit: list[str] = []
    else:
        path = str(entry.get("Path") or "")
        raw = entry.get("Platforms") or entry.get("Platform") or entry.get("OperatingSystem")
        if isinstance(raw, str):
            explicit = [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
        elif isinstance(raw, list):
            explicit = [str(p).strip() for p in raw if str(p).strip()]
        else:
            explicit = []

    norm_map = {
        "macos": "macOS",
        "mac": "macOS",
        "darwin": "macOS",
        "linux": "Linux",
        "windows": "Windows",
        "win": "Windows",
        "win32": "Windows",
    }
    out: list[str] = []
    seen: set[str] = set()
    for p in explicit:
        key = p.casefold()
        if key in {"all", "any", "cross-platform", "cross platform"}:
            return []
        n = norm_map.get(key, p if p in {"macOS", "Linux", "Windows"} else "")
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    if out:
        return out

    pl = path.lower()
    if any(x in pl for x in ("%localappdata%", "%appdata%", "%userprofile%", "%programfiles%", "\\users\\", ".exe")):
        return ["Windows"]
    if "library/application support" in pl or "library/logs" in pl or "/applications/" in pl:
        return ["macOS"]
    if pl.startswith("/usr/") or pl.startswith("/opt/") or "journalctl" in pl or "/var/log" in pl:
        return ["Linux"]
    # Home-relative unix paths (~/.…) are usually shared by macOS + Linux
    if path.startswith("~/") or path.startswith("$HOME/") or path.startswith("${HOME}/"):
        if "\\windows\\" in pl or "%localappdata%" in pl:
            return ["Windows"]
        return ["macOS", "Linux"]
    return []


def normalize_artifact_path(path: str, platforms: list[str]) -> str:
    """Normalize path literals for display (Windows %VAR% vs mixed ~/~\\)."""
    p = str(path or "").strip()
    if not p:
        return p
    # Collapse accidental YAML double-escaping on Windows paths.
    while "\\\\" in p:
        p = p.replace("\\\\", "\\")
    plat = set(platforms or [])
    is_windows = "Windows" in plat or (
        not plat
        and any(
            x in p.lower()
            for x in ("%localappdata%", "%appdata%", "%userprofile%", "%programfiles%")
        )
    )
    if is_windows:
        if p.startswith("~/"):
            p = "%USERPROFILE%\\" + p[2:].replace("/", "\\")
        elif p.startswith("~\\"):
            p = "%USERPROFILE%\\" + p[2:]
    return p


def _artifact_dedupe_key(path: str, platforms: list[str]) -> tuple[str, tuple[str, ...]]:
    norm_path = normalize_artifact_path(path, platforms).casefold()
    plat_key = tuple(sorted(platforms)) if platforms else ("",)
    return (norm_path, plat_key)


def dedupe_artifact_rows(rows: list[dict]) -> list[dict]:
    """Drop duplicate path+platform rows; prefer entries with notes and explicit platforms."""
    ranked: list[tuple[int, dict]] = []
    for row in rows:
        path = str(row.get("path") or "").strip()
        if not path:
            continue
        platforms = list(row.get("platforms") or [])
        score = 0
        if row.get("notes"):
            score += 2
        if platforms:
            score += 1
        ranked.append((score, row))

    ranked.sort(key=lambda item: item[0], reverse=True)
    seen: set[tuple[str, tuple[str, ...]]] = set()
    out: list[dict] = []
    for _, row in ranked:
        path = str(row.get("path") or "").strip()
        platforms = list(row.get("platforms") or [])
        key = _artifact_dedupe_key(path, platforms)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "path": normalize_artifact_path(path, platforms),
                "notes": str(row.get("notes") or "").strip(),
                "platforms": platforms,
            }
        )
    return out


def art_entries(arts: dict, key: str) -> list[dict]:
    """Structured artifact rows with optional per-OS platform tags."""
    out: list[dict] = []
    for entry in arts.get(key) or []:
        if isinstance(entry, str):
            path = entry.strip()
            if not path:
                continue
            platforms = infer_artifact_platforms(path)
            out.append({"path": path, "notes": "", "platforms": platforms})
        elif isinstance(entry, dict) and entry.get("Path"):
            path = str(entry["Path"]).strip()
            note = str(entry.get("Notes") or entry.get("Description") or "").strip()
            platforms = infer_artifact_platforms(entry)
            out.append({"path": path, "notes": note, "platforms": platforms})
    return dedupe_artifact_rows(out)


def flatten_surfaces(tool: dict) -> list[dict]:
    out: list[dict] = []
    for surface in tool.get("Surfaces") or []:
        if not isinstance(surface, dict):
            continue
        row: dict = {
            "id": surface.get("Id") or "",
            "label": surface.get("Label") or "",
            "binaries": [b for b in (surface.get("Binaries") or []) if b],
        }
        for src, dst in (
            ("Description", "description"),
            ("Framework", "framework"),
            ("CliExecutable", "cliExecutable"),
            ("SpawnsShells", "spawnsShells"),
            ("Agentic", "agentic"),
        ):
            if surface.get(src) is not None:
                row[dst] = surface[src]
        if surface.get("HelperProcesses"):
            row["helperProcesses"] = list(surface["HelperProcesses"])
        if surface.get("ConfigDirs"):
            row["configDirs"] = surface["ConfigDirs"]
        if surface.get("Signing"):
            row["signing"] = surface["Signing"]
        if surface.get("Integrations"):
            row["integrations"] = surface["Integrations"]
        out.append(row)
    return out


PACKAGE_MIRROR_HOSTS = frozenset(
    {
        "pypi.org",
        "www.npmjs.com",
        "npmjs.com",
        "npmjs.org",
        "crates.io",
        "rubygems.org",
    }
)


def _url_host(url: str) -> str:
    from urllib.parse import urlparse

    try:
        return (urlparse(url).netloc or "").lower().removeprefix("www.")
    except Exception:  # noqa: BLE001
        return ""


def _is_package_mirror(url: str) -> bool:
    host = _url_host(url)
    return host in PACKAGE_MIRROR_HOSTS or host.endswith(".pypi.org")


def _official_url_score(url: str, title: str = "") -> int:
    """Higher = better official source."""
    u = url.lower()
    t = title.lower()
    score = 0
    if "github.com" in u:
        score += 30
        if "/anthropics/" in u or "/openai/" in u or "/google-" in u:
            score += 10
    if any(x in u for x in (".dev/docs", "/docs", "docs.", "documentation")):
        score += 25
    if any(x in t for x in ("official", "documentation", "product page", "homepage")):
        score += 15
    if _is_package_mirror(u):
        score -= 20
    if "support." in u or "learn.microsoft.com" in u:
        score += 10
    return score


def official_url_label(url: str) -> str:
    u = url.lower()
    if any(x in u for x in ("/docs", "docs.", ".dev/docs", "documentation", "learn.microsoft.com")):
        return "Official documentation ↗"
    if "github.com" in u:
        return "Official GitHub repository ↗"
    if _is_package_mirror(u):
        return "Official package page ↗"
    return "Official project ↗"


def pick_official_url(tool: dict, details: dict, resources: list[dict]) -> tuple[str, str]:
    """Return (url, label) for the primary official project link."""
    for candidate in (
        tool.get("OfficialUrl"),
        details.get("OfficialUrl"),
        details.get("Website"),
    ):
        url = str(candidate or "").strip()
        if url.startswith("http"):
            return url, official_url_label(url)

    best_url = ""
    best_score = -999
    best_title = ""
    for resource in resources:
        link = str(resource.get("link") or "").strip()
        title = str(resource.get("title") or "").strip()
        if not link.startswith("http"):
            continue
        score = _official_url_score(link, title)
        if score > best_score:
            best_score = score
            best_url = link
            best_title = title
    if best_url:
        if best_title and any(x in best_title.lower() for x in ("official", "documentation", "repository", "homepage")):
            return best_url, f"{best_title} ↗"
        return best_url, official_url_label(best_url)
    return "", ""


def _normalize_cli_name(name: str) -> str:
    n = str(name or "").strip()
    if n.lower().endswith(".exe"):
        return n[:-4]
    return n


def derive_cli_aliases(tool: dict, details: dict) -> tuple[str, list[str]]:
    """Return (primary_cli, alias_list) for display."""
    primary = _normalize_cli_name(str(details.get("CliExecutable") or catalog_binary(tool) or ""))

    if "CliAliases" in details:
        explicit = [
            _normalize_cli_name(a)
            for a in (details.get("CliAliases") or [])
            if a and not is_generic_binary(str(a))
        ]
        aliases: list[str] = []
        seen: set[str] = set()
        for alias in explicit:
            if alias == primary or alias in seen:
                continue
            seen.add(alias)
            aliases.append(alias)
        return primary, aliases

    candidates: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        n = _normalize_cli_name(name)
        if not n or n == primary or is_generic_binary(n):
            return
        if n in seen:
            return
        seen.add(n)
        candidates.append(n)

    for binary in details.get("Binaries") or []:
        add(str(binary))

    candidates.sort(key=lambda n: n.casefold())
    return primary, candidates


def build_search_terms(tool: dict, details: dict, binaries: list[str]) -> list[str]:
    terms: list[str] = [
        str(tool.get("Id") or ""),
        str(tool.get("Name") or ""),
        str(tool.get("Vendor") or ""),
        str(details.get("CliExecutable") or ""),
    ]
    terms.extend(str(a) for a in (tool.get("SearchAliases") or []) if a)
    for surface in tool.get("Surfaces") or []:
        if not isinstance(surface, dict):
            continue
        if surface.get("Id"):
            terms.append(str(surface["Id"]))
        if surface.get("Label"):
            terms.append(str(surface["Label"]))
        terms.extend(str(b) for b in (surface.get("Binaries") or []) if b)
    terms.extend(str(b) for b in binaries if b)
    seen: set[str] = set()
    out: list[str] = []
    for term in terms:
        t = term.strip()
        if not t:
            continue
        key = t.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out


def flatten_for_site(tool: dict) -> dict:
    details = tool.get("Details") or {}
    coverage = tool.get("Coverage") or {}
    binaries = details.get("Binaries") or []
    primary = catalog_binary(tool)
    commands = tool.get("Commands") or []
    mitre = sorted(
        {
            c.get("MitreID")
            for c in commands
            if isinstance(c, dict) and c.get("MitreID")
        }
    )
    ops = []
    for op in tool.get("DetectionOpportunities") or []:
        if not isinstance(op, dict):
            continue
        clean = {k: v for k, v in op.items() if k not in ("ExampleQueries", "ESQL", "Sigma", "KQL", "EQL")}
        ops.append(clean)

    resources = []
    for r in tool.get("Resources") or []:
        if not isinstance(r, dict):
            continue
        link = r.get("Link") or r.get("Url") or ""
        title = r.get("Title") or link
        if link:
            resources.append({"title": title, "link": link})

    official_url, official_url_label_text = pick_official_url(tool, details, resources)
    cli_primary, cli_aliases = derive_cli_aliases(tool, details)

    arts = tool.get("Artifacts") or {}

    def art_paths(key: str) -> list[str]:
        """Flat legacy strings for CSV/compat; prefer structured *_entries fields."""
        out: list[str] = []
        for row in art_entries(arts, key):
            note = row.get("notes") or ""
            out.append(f"{row['path']}" + (f" ({note})" if note else ""))
        return out

    disk_entries = art_entries(arts, "Disk")
    if not disk_entries:
        disk_entries = [
            {"path": p, "notes": "", "platforms": infer_artifact_platforms(p)}
            for p in (details.get("InstallationPaths") or [])
            if isinstance(p, str) and p.strip()
        ]
    config_entries = art_entries(arts, "ConfigFiles")
    if not config_entries:
        config_entries = [
            {"path": p, "notes": "", "platforms": infer_artifact_platforms(p)}
            for p in (details.get("ContextFiles") or [])
            if isinstance(p, str) and p.strip()
        ]
    log_entries = art_entries(arts, "Logs")
    session_entries = art_entries(arts, "Sessions")
    auth_entries = art_entries(arts, "AuthTokens")
    hook_entries = art_entries(arts, "Hooks")
    skills_entries = art_entries(arts, "Skills")
    mcp_entries = art_entries(arts, "MCP")
    env_entries = art_entries(arts, "Environment")

    signing = tool.get("Signing") or {}
    sign_bits: list[str] = []
    signing_details: list[dict] = []
    for os_name, label in (("macOS", "macOS"), ("Windows", "Windows"), ("Linux", "Linux")):
        block = signing.get(os_name) or {}
        if not isinstance(block, dict) or not block:
            continue
        row_fields: list[dict[str, str]] = []
        for key, display in (
            ("Depth", "Depth"),
            ("SigningId", "Signing ID"),
            ("TeamId", "Team ID"),
            ("BundleId", "Bundle ID"),
            ("Authority", "Authority"),
            ("Publisher", "Publisher"),
            ("CertificateCN", "Certificate CN"),
            ("Subject", "Subject"),
            ("Thumbprint", "Thumbprint (SHA-1)"),
            ("Issuer", "Issuer"),
        ):
            val = block.get(key)
            if val:
                row_fields.append({"label": display, "value": str(val)})
        notes = block.get("Notes")
        if notes:
            row_fields.append({"label": "Notes", "value": str(notes)})
        if row_fields:
            signing_details.append({"os": os_name, "label": label, "fields": row_fields})
        parts = []
        if block.get("SigningId"):
            parts.append(f"id={block['SigningId']}")
        if block.get("TeamId"):
            parts.append(f"team={block['TeamId']}")
        if block.get("Authority"):
            parts.append(str(block["Authority"]))
        elif block.get("Publisher"):
            parts.append(f"publisher={block['Publisher']}")
        if block.get("Thumbprint"):
            parts.append(f"thumbprint={block['Thumbprint']}")
        if block.get("Depth"):
            parts.append(f"depth={block['Depth']}")
        if parts:
            sign_bits.append(f"{label}: " + "; ".join(parts))

    verification_level = str(tool.get("VerificationLevel") or "").strip().lower()
    if verification_level not in {"unverified", "documented", "observed"}:
        coverage = tool.get("Coverage") or {}
        verified = bool(coverage.get("Verified"))
        empirical = str(coverage.get("EmpiricalNotes") or tool.get("EmpiricalNotes") or "").lower()
        if verified and any(
            m in empirical
            for m in ("lab", "observed", "empirically verified", "authenticode", "codesign")
        ):
            verification_level = "observed"
        elif verified:
            verification_level = "documented"
        else:
            verification_level = "unverified"

    updated = str(tool.get("Updated") or tool.get("LastModified") or "").strip()
    created = str(tool.get("Created") or "").strip()
    filter_capabilities = derive_filter_capabilities(tool, details, verification_level)
    public_ecosystems = flatten_public_ecosystems(tool)
    filter_ecosystem = derive_filter_ecosystem(tool, details, resources, public_ecosystems)

    flat: dict = {
        "id": tool.get("Id"),
        "uuid": str(tool.get("Uuid") or ""),
        "name": tool.get("Name"),
        "bin": primary,
        "binaries": binaries,
        "vendor": tool.get("Vendor"),
        "author": tool.get("Author") or "",
        "contributors": [
            c for c in (tool.get("Contributors") or [])
            if isinstance(c, str) and c.strip()
        ],
        "type": category_label(tool.get("Category") or ""),
        "category": tool.get("Category"),
        "description": (tool.get("Description") or "").strip(),
        "website": details.get("Website") or "",
        "officialUrl": official_url,
        "officialUrlLabel": official_url_label_text,
        "cliPrimary": cli_primary,
        "cliAliases": cli_aliases,
        "resources": resources,
        "fns": derive_fns(tool, details, commands),
        "surfaces": flatten_surfaces(tool),
        "search": build_search_terms(tool, details, binaries),
        "helpers": details.get("HelperProcesses") or [],
        "mitre": mitre,
        "os": details.get("SupportedOS") or [],
        "verified": bool(coverage.get("Verified")),
        "verificationLevel": verification_level,
        "created": created,
        "updated": updated,
        "grade": str(coverage.get("ReadinessGrade") or "?").lower(),
        "ops": len(ops),
        "commands": commands,
        "detection_opportunities": ops,
        "artifacts": arts,
        "disk": art_paths("Disk") or list(details.get("InstallationPaths") or []),
        "config_files": art_paths("ConfigFiles") or list(details.get("ContextFiles") or []),
        "logs": art_paths("Logs"),
        "sessions": art_paths("Sessions"),
        "auth_tokens": art_paths("AuthTokens"),
        "hooks": art_paths("Hooks"),
        "skills": art_paths("Skills"),
        "mcp": art_paths("MCP"),
        "environment": art_paths("Environment"),
        "disk_entries": disk_entries,
        "config_entries": config_entries,
        "log_entries": log_entries,
        "session_entries": session_entries,
        "auth_entries": auth_entries,
        "hook_entries": hook_entries,
        "skills_entries": skills_entries,
        "mcp_entries": mcp_entries,
        "env_entries": env_entries,
        "network_domains": [
            d
            for n in (arts.get("Network") or [])
            for d in (n.get("Domains") or [])
        ],
        "signing": signing,
        "signing_summary": sign_bits,
        "signing_details": signing_details,
        "coverage": coverage,
        "source": tool.get("_source"),
        "agentic": details.get("Agentic") is True,
        "spawnsShells": bool(details.get("SpawnsShells")),
        "configDirs": details.get("ConfigDirs") or {},
        "packages": details.get("Packages") or {},
        "extensionIds": tool.get("ExtensionIds") or {},
        "customAgents": tool.get("CustomAgents") or {},
        "integrations": tool.get("Integrations") or {},
        "publicEcosystems": public_ecosystems,
        "dataProvenance": tool.get("DataProvenance") or {},
        "undocumentedEmpirical": tool.get("UndocumentedEmpirical") or [],
        "verifiedPlatforms": tool.get("VerifiedPlatforms") or {},
        "coverageConfidence": str(coverage.get("Confidence") or "").lower(),
        "filterCapabilities": filter_capabilities,
        "filterEcosystem": filter_ecosystem,
    }
    flat["score"] = compute_reference_score(tool, flat)
    return flat


WEAK_STUB_FIELDS = frozenset({"process.name", "process.parent.name"})

STRONG_FIELD_PREFIXES = (
    "process.code_signature.",
    "process.parent.code_signature.",
    "process.env.",
)
STRONG_EXACT_FIELDS = frozenset(
    {
        "process.executable",
        "process.parent.executable",
        "process.working_directory",
        "process.parent.working_directory",
        "file.path",
        "process.pe.original_file_name",
        "process.hash.sha256",
        "process.parent.command_line",
    }
)


def collect_attribution_signals(tool: dict) -> list[dict]:
    signals: list[dict] = []
    for op in tool.get("detection_opportunities") or []:
        if not isinstance(op, dict):
            continue
        for sig in op.get("AttributionSignals") or []:
            if not isinstance(sig, dict):
                continue
            if sig.get("Field") and sig.get("Value") is not None:
                signals.append(sig)
    return signals


def is_strong_attribution_signal(sig: dict) -> bool:
    """True for signing, path, env, or other distinctive ranked signals."""
    field = str(sig.get("Field") or "")
    value = str(sig.get("Value") or "")
    if field in STRONG_EXACT_FIELDS:
        return True
    if any(field.startswith(prefix) for prefix in STRONG_FIELD_PREFIXES):
        return True
    if field in {"process.args", "process.command_line"} and any(
        ch in value for ch in ("*", "/", "\\")
    ):
        return True
    return False


def has_any_attribution_signal(tool: dict) -> bool:
    return bool(collect_attribution_signals(tool))


def has_weak_attribution_only(tool: dict) -> bool:
    """Any ranked signal, excluding a lone auto-generated process.name stub."""
    signals = collect_attribution_signals(tool)
    if not signals:
        return False
    if len(signals) == 1 and signals[0].get("Field") == "process.name":
        return False
    return True


def has_strong_attribution(tool: dict) -> bool:
    """Usable attribution: signing/path/env/distinctive args, or 2+ non-stub fields."""
    signals = collect_attribution_signals(tool)
    if not signals:
        return False
    if any(is_strong_attribution_signal(sig) for sig in signals):
        return True
    fields = {str(sig.get("Field") or "") for sig in signals}
    return len(fields - WEAK_STUB_FIELDS) >= 2


def has_attribution_signals_raw(tool: dict) -> bool:
    """True when any DetectionOpportunities row has a ranked AttributionSignal."""
    for op in tool.get("DetectionOpportunities") or []:
        if not isinstance(op, dict):
            continue
        for sig in op.get("AttributionSignals") or []:
            if isinstance(sig, dict) and sig.get("Field") and sig.get("Value") is not None:
                return True
    return False


def derive_filter_capabilities(tool: dict, details: dict, verification_level: str) -> list[str]:
    """Catalog capability filter keys (OR within group on the site)."""
    arts = tool.get("Artifacts") or {}
    caps: list[str] = []
    agentic = details.get("Agentic")
    if agentic is True:
        caps.append("agentic")
    elif agentic is False:
        caps.append("non_agentic")

    detail_caps = set(details.get("Capabilities") or [])
    has_mcp_cmd = any(
        isinstance(cmd, dict) and cmd.get("Category") == "MCP" for cmd in (tool.get("Commands") or [])
    )
    if "MCP" in detail_caps or arts.get("MCP") or has_mcp_cmd:
        caps.append("mcp_support")

    if details.get("SpawnsShells"):
        caps.append("spawns_shells")

    if arts.get("Hooks"):
        caps.append("hooks_support")

    if arts.get("Skills"):
        caps.append("on_disk_skills")

    if has_attribution_signals_raw(tool):
        caps.append("attribution_signals")

    if verification_level == "observed":
        caps.append("empirically_verified")

    return caps


def flatten_public_ecosystems(tool: dict) -> list[dict]:
    """Emit PublicEcosystems for tools.json (camelCase keys)."""
    rows: list[dict] = []
    for item in tool.get("PublicEcosystems") or []:
        if not isinstance(item, dict):
            continue
        title = str(item.get("Title") or "").strip()
        url = str(item.get("Url") or "").strip()
        category = str(item.get("Category") or "").strip()
        if not title or not url or not category:
            continue
        row: dict[str, Any] = {"title": title, "url": url, "category": category}
        if item.get("Operator"):
            row["operator"] = str(item["Operator"])
        if item.get("Description"):
            row["description"] = str(item["Description"])
        for src, dst in (
            ("Official", "official"),
            ("Public", "public"),
            ("OpenSubmission", "openSubmission"),
            ("Installable", "installable"),
            ("CanExecuteCode", "canExecuteCode"),
            ("CanInstallRemoteCode", "canInstallRemoteCode"),
        ):
            if src in item:
                row[dst] = bool(item[src])
        for src, dst in (
            ("SurfaceScope", "surfaceScope"),
            ("InstallSurfaces", "installSurfaces"),
            ("PackagesCanInclude", "packagesCanInclude"),
        ):
            vals = item.get(src)
            if isinstance(vals, list) and vals:
                row[dst] = [str(v) for v in vals if v]
        if item.get("SourceRepo"):
            row["sourceRepo"] = str(item["SourceRepo"])
        rows.append(row)
    return rows


def _ecosystem_kind_to_filter(kind: str) -> set[str]:
    """Map artifact category/kind to catalog filter keys."""
    eco: set[str] = set()
    if kind in {"skill_catalog", "skill_registry"}:
        eco.add("skill_catalog")
    elif kind == "plugin_marketplace":
        eco.add("plugin_marketplace")
    elif kind in {"mcp_registry", "mcp_directory"}:
        eco.add("mcp_registry")
    elif kind == "extension_gallery":
        eco.add("extension_gallery")
    elif kind == "prompt_library":
        eco.add("prompt_library")
    elif kind == "agent_hub":
        eco.add("agent_hub")
    elif kind == "rules_hub":
        eco.add("rules_hub")
    return eco


def derive_filter_ecosystem(
    tool: dict,
    details: dict,
    resources: list[dict],
    public_ecosystems: list[dict] | None = None,
) -> list[str]:
    """Ecosystem filters from PublicEcosystems data; URL heuristics as fallback."""
    eco: set[str] = set()
    ecosystems = public_ecosystems if public_ecosystems is not None else flatten_public_ecosystems(tool)

    if ecosystems:
        eco.add("has_public")
        all_official = True
        for art in ecosystems:
            kind = str(art.get("category") or "")
            eco.update(_ecosystem_kind_to_filter(kind))
            if art.get("installable"):
                eco.add("installable")
            if art.get("official") is False:
                all_official = False
        if all_official:
            eco.add("official_only")

    # Fallback heuristics when PublicEcosystems absent (legacy Resources links)
    if not ecosystems:
        for resource in resources:
            text = f"{resource.get('title', '')} {resource.get('link', '')}".lower()
            if "marketplace" in text:
                eco.add("plugin_marketplace")
            if "extension" in text and any(
                token in text for token in ("gallery", "marketplace", "vscode", "jetbrains", "open-vsx")
            ):
                eco.add("extension_gallery")
            if "mcp" in text and any(
                token in text for token in ("registry", "directory", "servers", "hub", "catalog")
            ):
                eco.add("mcp_registry")
            if "skill" in text and any(token in text for token in ("catalog", "registry", "marketplace")):
                eco.add("skill_catalog")

    framework = str(details.get("Framework") or "")
    category = str(tool.get("Category") or "")
    if framework in {"vscode_extension", "electron"} or category in {
        "ide_extension",
        "desktop",
        "ide_agent",
    }:
        eco.add("installable_surface")

    return sorted(eco)


def build_lookup(site_tools: list[dict]) -> dict[str, str]:
    """Map id, name, binary, and CLI aliases (case-insensitive) → canonical tool id."""
    ranked: dict[str, tuple[str, int]] = {}

    def priority(key: str, tool_id: str, kind: str) -> int:
        fold = key.casefold()
        tid = tool_id.casefold()
        if fold == tid:
            return 100
        if kind in {"bin", "cliPrimary"}:
            return 80
        if kind == "name":
            return 60
        if kind == "alias":
            return 40
        if kind == "binary":
            return 20
        return 10

    def add(key: str, tool_id: str, kind: str) -> None:
        k = str(key or "").strip()
        if not k:
            return
        score = priority(k, tool_id, kind)
        for variant in {k, k.casefold()} if k.casefold() != k else {k}:
            current = ranked.get(variant)
            if current is None or score >= current[1]:
                ranked[variant] = (tool_id, score)

    for tool in site_tools:
        tool_id = str(tool.get("id") or "")
        if not tool_id:
            continue
        add(tool_id, tool_id, "id")
        add(str(tool.get("name") or ""), tool_id, "name")
        add(str(tool.get("bin") or ""), tool_id, "bin")
        add(str(tool.get("cliPrimary") or ""), tool_id, "cliPrimary")
        for alias in tool.get("cliAliases") or []:
            add(str(alias), tool_id, "alias")
        for binary in tool.get("binaries") or []:
            add(str(binary), tool_id, "binary")

    lookup = {key: tool_id for key, (tool_id, _score) in ranked.items()}
    return dict(sorted(lookup.items(), key=lambda item: item[0].casefold()))


def write_per_tool_json(site_tools: list[dict]) -> None:
    """Emit public/api/tools/<id>.json — one flattened tool object per file."""
    tools_dir = API_DIR / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    current_ids = {str(t.get("id") or "") for t in site_tools if t.get("id")}
    for stale in tools_dir.glob("*.json"):
        if stale.stem not in current_ids:
            stale.unlink()
    for tool in site_tools:
        tool_id = str(tool.get("id") or "")
        if not tool_id:
            continue
        (tools_dir / f"{tool_id}.json").write_text(
            json.dumps(tool, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


EMBED_START = "<!-- LOLGAI_EMBED_START -->"
EMBED_END = "<!-- LOLGAI_EMBED_END -->"


def embed_catalog_in_index(tools_json: str, stats_json: str) -> None:
    """Inject build-time JSON embed for offline / file:// preview."""
    index_path = ROOT / "website" / "index.html"
    html = index_path.read_text(encoding="utf-8")
    # Escape </ so JSON cannot prematurely close the HTML script element.
    tools_safe = tools_json.replace("</", "<\\/")
    stats_safe = stats_json.replace("</", "<\\/")
    block = (
        f"{EMBED_START}\n"
        f'<script type="application/json" id="lolgai-tools-embed">{tools_safe}</script>\n'
        f'<script type="application/json" id="lolgai-stats-embed">{stats_safe}</script>\n'
        f"{EMBED_END}"
    )
    if EMBED_START in html and EMBED_END in html:
        start = html.index(EMBED_START)
        end = html.index(EMBED_END) + len(EMBED_END)
        html = html[:start] + block + html[end:]
    elif EMBED_START in html and EMBED_END not in html:
        # Avoid truncating the document if END marker was lost.
        raise RuntimeError(
            f"{index_path}: found {EMBED_START!r} without {EMBED_END!r}; "
            "refusing to rewrite (would truncate </head>/<body>)"
        )
    else:
        if "</head>" not in html:
            raise RuntimeError(f"{index_path}: missing </head>; refusing embed rewrite")
        html = html.replace("</head>", block + "\n</head>", 1)
    if "<body" not in html or "</html>" not in html:
        raise RuntimeError(f"{index_path}: embed rewrite would leave invalid HTML; aborting write")
    index_path.write_text(html, encoding="utf-8")


def main() -> int:
    tools = load_tools()
    if not tools:
        print("No tools found under yaml/", file=sys.stderr)
        return 1

    API_DIR.mkdir(parents=True, exist_ok=True)
    site_tools = [flatten_for_site(t) for t in tools]
    site_tools.sort(key=site_tool_sort_key)

    (API_DIR / "tools.json").write_text(
        json.dumps(site_tools, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (API_DIR / "tools.raw.json").write_text(
        json.dumps(tools, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    write_per_tool_json(site_tools)
    lookup = build_lookup(site_tools)
    (API_DIR / "lookup.json").write_text(
        json.dumps(lookup, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # CSV exports
    write_csv(
        API_DIR / "tools.csv",
        [
            {
                "id": t["id"],
                "name": t["name"],
                "bin": t["bin"],
                "vendor": t["vendor"],
                "author": t.get("author") or "",
                "contributors": "|".join(t.get("contributors") or []),
                "category": t["category"],
                "verified": t["verified"],
                "verification_level": t.get("verificationLevel") or "unverified",
                "created": t.get("created") or "",
                "updated": t.get("updated") or "",
                "grade": t["grade"],
                "capabilities": "|".join(t["fns"]),
                "mitre": "|".join(t["mitre"]),
            }
            for t in site_tools
        ],
        [
            "id",
            "name",
            "bin",
            "vendor",
            "author",
            "contributors",
            "category",
            "verified",
            "verification_level",
            "created",
            "updated",
            "grade",
            "capabilities",
            "mitre",
        ],
    )

    binary_rows = []
    for t in site_tools:
        for b in t["binaries"] or [t["bin"]]:
            binary_rows.append({"binary": b, "tool_id": t["id"], "vendor": t["vendor"]})
    write_csv(API_DIR / "binaries.csv", binary_rows, ["binary", "tool_id", "vendor"])

    domain_rows = []
    for t in tools:
        net = ((t.get("Artifacts") or {}).get("Network")) or []
        for entry in net:
            if not isinstance(entry, dict):
                continue
            for d in entry.get("Domains") or []:
                domain_rows.append({"domain": d, "tool_id": t.get("Id"), "vendor": t.get("Vendor")})
    write_csv(API_DIR / "domains.csv", domain_rows, ["domain", "tool_id", "vendor"])

    total = len(site_tools)
    with_strong = sum(1 for t in site_tools if has_strong_attribution(t))
    with_weak = sum(1 for t in site_tools if has_weak_attribution_only(t))
    with_any = sum(1 for t in site_tools if has_any_attribution_signal(t))
    stats = {
        "tools": total,
        "categories": len({t["category"] for t in site_tools if t["category"]}),
        "with_strong_attribution": with_strong,
        "with_strong_attribution_pct": round(100 * with_strong / total) if total else 0,
        # Secondary counters: any ranked signal vs. weak parent/name stubs only.
        "with_attribution": with_weak,
        "with_attribution_pct": round(100 * with_weak / total) if total else 0,
        "with_any_signal": with_any,
        "with_any_signal_pct": round(100 * with_any / total) if total else 0,
        "verified": sum(1 for t in site_tools if t["verified"]),
        "verification_levels": {
            level: sum(1 for t in site_tools if t.get("verificationLevel") == level)
            for level in ("unverified", "documented", "observed")
        },
        "with_signing_thumbprint": sum(
            1
            for t in site_tools
            for block in (t.get("signing") or {}).values()
            if isinstance(block, dict) and block.get("Thumbprint")
        ),
    }
    (API_DIR / "stats.json").write_text(
        json.dumps(stats, indent=2) + "\n",
        encoding="utf-8",
    )

    score_issues: list[str] = []
    for t in site_tools:
        s = t.get("score") or {}
        dims = s.get("dimensions") or []
        if s.get("max") == 0:
            score_issues.append(f"{t.get('id')}: score.max==0")
        if len(dims) != 8:
            score_issues.append(f"{t.get('id')}: {len(dims)} dimensions (expected 8)")
    if score_issues:
        print("Score validation failed:", file=sys.stderr)
        for issue in score_issues[:20]:
            print(f"  - {issue}", file=sys.stderr)
        if len(score_issues) > 20:
            print(f"  … and {len(score_issues) - 20} more", file=sys.stderr)
        return 1

    tools_payload = json.dumps(site_tools, ensure_ascii=False, separators=(",", ":"))
    stats_payload = json.dumps(stats, separators=(",", ":"))
    embed_catalog_in_index(tools_payload, stats_payload)

    print(
        f"Built {len(site_tools)} tools → {API_DIR} "
        f"(+ {len(site_tools)} per-tool JSON, lookup.json with {len(lookup)} keys)"
    )
    print(json.dumps(stats))
    # Catalog health summary (stdout for CI / local build).
    print(
        "Catalog health: "
        f"{stats['tools']} tools · {stats['categories']} categories · "
        f"{stats['verified']} verified · "
        f"strong attribution {stats['with_strong_attribution_pct']}% "
        f"({stats['with_strong_attribution']} of {stats['tools']} · signing / path / env)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
