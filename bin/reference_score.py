"""Reference-depth scoring for LOL-GAI catalog entries.

Eight weighted dimensions (max 15) for catalog completeness.
Scores reflect catalog completeness for telemetry, config, and docs — not editorial Readiness A/B/C.
"""

from __future__ import annotations

from typing import Any

# Frameworks with no product-specific signing identity on the host.
NO_SIGNING = frozenset(
    {
        "cloud_only",
        "browser_only",
        "api_only",
        "vscode_extension",
    }
)

DIMENSION_LABELS: dict[str, str] = {
    "process_telemetry": "Process Telemetry",
    "code_signature": "Code Signature",
    "config_paths": "Config Paths",
    "attribution": "Attribution",
    "network_artifacts": "Network Artifacts",
    "context_files": "Context Files",
    "data_quality": "Data Quality",
    "reference_docs": "Reference Docs",
}

SIGNATURE_RANK = {"full": 3, "shared_host": 2, "partial": 2, "none": 0}


def _dim(
    dim_id: str,
    weight: int,
    score: int,
    applicable: bool,
    finding: str,
    *,
    ok: bool | None = None,
) -> dict[str, Any]:
    if ok is None:
        ok = applicable and score == weight
    return {
        "id": dim_id,
        "label": DIMENSION_LABELS[dim_id],
        "score": score,
        "max": weight,
        "finding": finding,
        "ok": ok,
        "applicable": applicable,
    }


def _norm_platform(key: str) -> str | None:
    k = str(key or "").strip().casefold()
    if k in {"macos", "mac", "darwin"}:
        return "macOS"
    if k in {"linux"}:
        return "Linux"
    if k in {"windows", "win", "win32"}:
        return "Windows"
    return None


def infer_framework(raw_tool: dict, details: dict) -> str:
    fw = str(details.get("Framework") or "").strip().lower()
    if fw:
        return fw
    category = str(raw_tool.get("Category") or "").strip().lower()
    if category == "api_only":
        return "api_only"
    if category == "mcp":
        return "node_cli"
    if category in {"cloud_agent", "cloud_mlops"}:
        return "cloud_only"
    return "native_binary"


def has_local_footprint(raw_tool: dict, details: dict) -> bool:
    """True when the catalog documents observable host processes (honest LOL-GAI mapping)."""
    if details.get("Binaries") or details.get("CliExecutable") or details.get("HelperProcesses"):
        return True
    for surface in raw_tool.get("Surfaces") or []:
        if not isinstance(surface, dict):
            continue
        if surface.get("Binaries") or surface.get("CliExecutable") or surface.get("HelperProcesses"):
            return True
    return False


def collect_process_names(raw_tool: dict, details: dict) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        n = str(name or "").strip()
        if not n:
            return
        key = n.casefold()
        if key in seen:
            return
        seen.add(key)
        names.append(n)

    for binary in details.get("Binaries") or []:
        add(str(binary))
    for helper in details.get("HelperProcesses") or []:
        add(str(helper))
    for surface in raw_tool.get("Surfaces") or []:
        if not isinstance(surface, dict):
            continue
        for binary in surface.get("Binaries") or []:
            add(str(binary))
        for helper in surface.get("HelperProcesses") or []:
            add(str(helper))
    return names


def collect_config_dir_platforms(raw_tool: dict, details: dict) -> set[str]:
    platforms: set[str] = set()

    def merge(block: dict | None) -> None:
        if not isinstance(block, dict):
            return
        for key, val in block.items():
            if not val:
                continue
            plat = _norm_platform(str(key))
            if plat:
                platforms.add(plat)

    merge(details.get("ConfigDirs"))
    for surface in raw_tool.get("Surfaces") or []:
        if isinstance(surface, dict):
            merge(surface.get("ConfigDirs"))

    arts = raw_tool.get("Artifacts") or {}
    for entry in arts.get("ConfigFiles") or []:
        if isinstance(entry, str):
            continue
        if not isinstance(entry, dict):
            continue
        raw_plat = entry.get("Platforms") or entry.get("Platform")
        if isinstance(raw_plat, list):
            for p in raw_plat:
                plat = _norm_platform(str(p))
                if plat:
                    platforms.add(plat)
        elif raw_plat:
            plat = _norm_platform(str(raw_plat))
            if plat:
                platforms.add(plat)
        elif entry.get("Path"):
            # Cross-platform config artifact without explicit OS — counts as one platform hint.
            platforms.add("__artifact__")

    if "__artifact__" in platforms:
        platforms.discard("__artifact__")
        if not platforms:
            platforms.add("__artifact__")
    return platforms


def platform_code_signature(block: dict | None) -> str:
    if not isinstance(block, dict) or not block:
        return "none"
    depth = str(block.get("Depth") or "none").strip().lower()
    if depth == "shared_host":
        return "shared_host"
    if depth == "partial":
        return "partial"
    if depth in {"full", "authenticode"}:
        usable = block.get("UsableForAttribution")
        has_identity = any(
            block.get(k)
            for k in (
                "SigningId",
                "TeamId",
                "Thumbprint",
                "Subject",
                "Publisher",
                "BundleId",
            )
        )
        if depth == "full" or (has_identity and usable is not False):
            return "full"
        if has_identity:
            return "partial"
        return "partial" if depth == "authenticode" else "none"
    return "none"


def best_code_signature(raw_tool: dict) -> tuple[str, str, str, str, str]:
    signing = raw_tool.get("Signing") or {}
    mac = platform_code_signature(signing.get("macOS"))
    win = platform_code_signature(signing.get("Windows"))
    lin = platform_code_signature(signing.get("Linux"))
    best = "none"
    best_rank = 0
    for cs in (mac, win, lin):
        rank = SIGNATURE_RANK.get(cs, 0)
        if rank > best_rank:
            best = cs
            best_rank = rank
    return best, mac, win, lin


def collect_attribution_signals(raw_tool: dict) -> list[dict]:
    signals: list[dict] = []
    for op in raw_tool.get("DetectionOpportunities") or []:
        if not isinstance(op, dict):
            continue
        for sig in op.get("AttributionSignals") or []:
            if isinstance(sig, dict) and sig.get("Field") and sig.get("Value") is not None:
                signals.append(sig)
    return signals


def has_shell_wrapper_indicators(raw_tool: dict, details: dict) -> bool:
    for op in raw_tool.get("DetectionOpportunities") or []:
        if not isinstance(op, dict):
            continue
        notes = " ".join(
            str(op.get(k) or "")
            for k in ("FalsePositiveGuidance", "Notes", "Description", "Name")
        ).lower()
        if any(
            token in notes
            for token in ("wrapper", "shim", "node_modules/.bin", "npm shim", "npx")
        ):
            return True
    return bool(details.get("Packages"))


def has_concrete_skill_paths(raw_tool: dict) -> bool:
    arts = raw_tool.get("Artifacts") or {}
    if arts.get("Skills"):
        return True
    integ = raw_tool.get("Integrations") or {}
    skills = integ.get("Skills") or {}
    if not isinstance(skills, dict):
        return False
    if skills.get("SkillFile"):
        return True
    if skills.get("WorkspaceDir") or skills.get("GlobalDir") or skills.get("AltWorkspaceDir"):
        return True
    if skills.get("WorkspaceDirs") or skills.get("GlobalDirs"):
        return True
    custom = raw_tool.get("CustomAgents") or {}
    if custom.get("AgentFile") or custom.get("WorkspaceDirs") or custom.get("GlobalDirs"):
        return True
    ctx = (raw_tool.get("Details") or {}).get("ContextFiles") or []
    return bool(ctx)


def collect_context_file_paths(raw_tool: dict, details: dict) -> list[str]:
    paths: list[str] = []
    for entry in details.get("ContextFiles") or []:
        if entry:
            paths.append(str(entry))
    arts = raw_tool.get("Artifacts") or {}
    context_markers = ("AGENTS.MD", "CLAUDE.MD", "SKILL.MD", "RULES.MD", "CURSORRULES", "AGENT.MD")
    for entry in arts.get("ConfigFiles") or []:
        if isinstance(entry, dict) and entry.get("Path"):
            path = str(entry["Path"])
            upper = path.upper()
            if any(marker in upper for marker in context_markers):
                paths.append(path)
    return paths


def reference_docs_count(raw_tool: dict, resources: list[dict], official_url: str) -> int:
    links: set[str] = set()
    for resource in resources:
        link = str(resource.get("link") or resource.get("Link") or "").strip()
        if link.startswith("http"):
            links.add(link)
    if official_url.startswith("http") and official_url not in links:
        links.add(official_url)
    return len(links)


def score_grade(pct: int) -> str:
    if pct >= 95:
        return "A+"
    if pct >= 90:
        return "A"
    if pct >= 75:
        return "B"
    if pct >= 60:
        return "C"
    return "D"


def _empirical_dim_id(label: str, notes: str) -> str:
    """Route lab-only observations into the most relevant score dimension."""
    text = f"{label} {notes}".lower()
    if any(token in text for token in (" env", "subprocess", "=1", "process.", "binary", "helper")):
        return "process_telemetry"
    if any(token in text for token in ("domain", "network", "api.", "http", "endpoint")):
        return "network_artifacts"
    if any(token in text for token in ("sign", "team id", "publisher", "authenticode", "thumbprint")):
        return "code_signature"
    if any(token in text for token in ("config", "~/.", "%userprofile%", "registry")):
        return "config_paths"
    if any(token in text for token in ("/", "\\", ".md", "file", "path", "context", "skill")):
        return "context_files"
    return "data_quality"


def _fold_empirical_into_score(
    score: dict[str, Any],
    empirical: list[Any] | None,
) -> dict[str, Any]:
    if not empirical:
        return score
    dims_by_id = {d["id"]: d for d in score.get("dimensions") or [] if d.get("id")}
    for row in empirical:
        if not isinstance(row, dict):
            continue
        label = str(row.get("Label") or "").strip()
        if not label:
            continue
        notes = str(row.get("Notes") or "").strip()
        dim = dims_by_id.get(_empirical_dim_id(label, notes))
        if not dim:
            continue
        suffix = f" Lab-observed (undocumented): {label}"
        if notes:
            suffix += f" — {notes}"
        finding = str(dim.get("finding") or "")
        if suffix not in finding:
            dim["finding"] = finding + suffix
    return score


def compute_reference_score(raw_tool: dict, site_tool: dict | None = None) -> dict[str, Any]:
    """Score a catalog entry. Pass raw YAML dict; optional flattened site row for precomputed fields."""
    details = raw_tool.get("Details") or {}
    coverage = raw_tool.get("Coverage") or {}
    framework = infer_framework(raw_tool, details)
    no_local = not has_local_footprint(raw_tool, details)
    agentic = details.get("Agentic") is True
    spawns_shells = bool(details.get("SpawnsShells"))
    process_names = collect_process_names(raw_tool, details)
    cli_executable = str(
        details.get("CliExecutable")
        or (site_tool.get("cliPrimary") if site_tool else "")
        or ""
    )
    helpers = list(details.get("HelperProcesses") or [])
    if site_tool:
        helpers.extend(site_tool.get("helpers") or [])
    has_helpers = bool(helpers)
    has_cli = bool(cli_executable) or has_helpers
    attribution_signals = collect_attribution_signals(raw_tool)
    network_domains = site_tool.get("network_domains") if site_tool else None
    if network_domains is None:
        network_domains = [
            d
            for n in ((raw_tool.get("Artifacts") or {}).get("Network") or [])
            for d in (n.get("Domains") or [])
            if isinstance(n, dict)
        ]
    resources = site_tool.get("resources") if site_tool else []
    if not resources:
        resources = [
            {"link": r.get("Link") or r.get("Url"), "title": r.get("Title")}
            for r in (raw_tool.get("Resources") or [])
            if isinstance(r, dict)
        ]
    official_url = str(
        (site_tool or {}).get("officialUrl")
        or raw_tool.get("OfficialUrl")
        or details.get("OfficialUrl")
        or details.get("Website")
        or ""
    ).strip()
    verified = bool(coverage.get("Verified"))
    confidence = str(
        coverage.get("Confidence")
        or (site_tool.get("coverageConfidence") if site_tool else "")
        or "low"
    ).lower()
    if confidence not in {"high", "medium", "low"}:
        confidence = "low"

    dims: list[dict[str, Any]] = []

    # 1. Process telemetry (weight 3)
    w = 3
    if no_local:
        dims.append(_dim("process_telemetry", w, w, False, "No local process footprint documented"))
    elif process_names and has_cli:
        if has_helpers and cli_executable:
            detail = "Process names, CLI executable, and helper processes documented"
        elif has_helpers:
            detail = "Process names and helper processes documented"
        else:
            detail = "Process names and CLI executable documented"
        dims.append(_dim("process_telemetry", w, 3, True, detail))
    elif process_names:
        dims.append(
            _dim(
                "process_telemetry",
                w,
                2,
                True,
                "Process names documented, no CLI executable or helpers",
            )
        )
    elif has_cli:
        dims.append(
            _dim(
                "process_telemetry",
                w,
                1,
                True,
                "CLI executable only, no process names",
            )
        )
    else:
        dims.append(_dim("process_telemetry", w, 0, True, "No process data documented"))

    # 2. Code signature (weight 2)
    w = 2
    if framework in NO_SIGNING and no_local:
        dims.append(_dim("code_signature", w, w, False, "No local process"))
    elif framework == "vscode_extension":
        dims.append(_dim("code_signature", w, w, False, "Runs inside VS Code host process"))
    else:
        cs, mac_cs, win_cs, lin_cs = best_code_signature(raw_tool)
        plat_summary = f"macOS:{mac_cs} / Windows:{win_cs} / Linux:{lin_cs}"
        if cs == "full":
            dims.append(_dim("code_signature", w, 2, True, f"Full attribution surface ({plat_summary})"))
        elif cs == "shared_host":
            dims.append(
                _dim(
                    "code_signature",
                    w,
                    1,
                    True,
                    f"Host app signing only ({plat_summary})",
                )
            )
        elif cs == "partial":
            dims.append(_dim("code_signature", w, 1, True, f"Partial signing data ({plat_summary})"))
        else:
            dims.append(
                _dim(
                    "code_signature",
                    w,
                    0,
                    True,
                    f"No code signature data on any platform ({plat_summary})",
                )
            )

    # 3. Config paths (weight 2)
    w = 2
    if no_local:
        dims.append(_dim("config_paths", w, w, False, "No local config"))
    else:
        platforms = collect_config_dir_platforms(raw_tool, details)
        explicit = {p for p in platforms if p != "__artifact__"}
        if len(explicit) >= 2:
            dims.append(
                _dim(
                    "config_paths",
                    w,
                    2,
                    True,
                    f"Config paths documented for {len(explicit)} platforms",
                )
            )
        elif len(explicit) == 1:
            dims.append(_dim("config_paths", w, 1, True, "Config path for 1 platform only"))
        elif "__artifact__" in platforms or (raw_tool.get("Artifacts") or {}).get("ConfigFiles"):
            dims.append(_dim("config_paths", w, 1, True, "Config artifact paths documented (no per-OS ConfigDirs)"))
        else:
            dims.append(_dim("config_paths", w, 0, True, "No config paths documented"))

    # 4. Attribution (weight 3) — score ranked signals even for non-agentic MCP servers
    w = 3
    if no_local:
        dims.append(_dim("attribution", w, w, False, "No local process"))
    elif attribution_signals:
        dims.append(
            _dim(
                "attribution",
                w,
                3,
                True,
                f"{len(attribution_signals)} ranked attribution signal(s) documented",
            )
        )
    elif not agentic:
        dims.append(
            _dim(
                "attribution",
                w,
                0,
                True,
                "Non-agentic tool — no ranked attribution signals yet",
            )
        )
    elif has_shell_wrapper_indicators(raw_tool, details):
        dims.append(
            _dim(
                "attribution",
                w,
                2,
                True,
                "Shell wrapper indicators known, no ranked signals yet",
            )
        )
    elif spawns_shells:
        dims.append(
            _dim(
                "attribution",
                w,
                1,
                True,
                "Shell-spawning agent; no ranked signals or wrapper detail yet",
            )
        )
    else:
        dims.append(_dim("attribution", w, 0, True, "No agent runtime data documented"))

    # 5. Network artifacts (weight 1)
    w = 1
    has_net = bool(network_domains)
    dims.append(
        _dim(
            "network_artifacts",
            w,
            1 if has_net else 0,
            True,
            "API domains or network endpoints documented"
            if has_net
            else "No concrete API domains documented",
        )
    )

    # 6. Context files (weight 1)
    w = 1
    if no_local:
        dims.append(_dim("context_files", w, w, False, "No local process"))
    elif not agentic:
        ctx_paths = collect_context_file_paths(raw_tool, details)
        if ctx_paths or has_concrete_skill_paths(raw_tool):
            dims.append(
                _dim(
                    "context_files",
                    w,
                    1,
                    True,
                    "Context file paths or skill/agent directories documented",
                )
            )
        else:
            dims.append(
                _dim(
                    "context_files",
                    w,
                    0,
                    True,
                    "Non-agentic — no context file or skill paths documented",
                )
            )
    else:
        ctx_paths = collect_context_file_paths(raw_tool, details)
        found = bool(ctx_paths) or has_concrete_skill_paths(raw_tool)
        dims.append(
            _dim(
                "context_files",
                w,
                1 if found else 0,
                True,
                "Context file paths or concrete skill directories documented"
                if found
                else "No context files or concrete skill paths",
            )
        )

    # 7. Data quality (weight 2)
    w = 2
    if confidence == "high":
        s = 2 if verified else 1
    elif confidence == "medium":
        s = 2 if verified else 0
    else:
        s = 1 if verified else 0
    if s == 2:
        detail = f"Empirically verified, {confidence} confidence"
    elif s == 1:
        detail = (
            "Empirically verified, low confidence"
            if verified
            else "High confidence, not yet verified"
        )
    else:
        detail = "Research-only — not empirically verified"
    dims.append(_dim("data_quality", w, s, True, detail))

    # 8. Reference docs (weight 1)
    w = 1
    doc_count = reference_docs_count(raw_tool, resources, official_url)
    dims.append(
        _dim(
            "reference_docs",
            w,
            1 if doc_count else 0,
            True,
            f"{doc_count} reference doc{'s' if doc_count != 1 else ''} linked"
            if doc_count
            else "No reference documentation",
        )
    )

    applicable = [d for d in dims if d["applicable"]]
    total = sum(d["score"] for d in applicable)
    max_score = sum(d["max"] for d in applicable)
    pct = int((total / max_score) * 100) if max_score else 0

    score: dict[str, Any] = {
        "total": total,
        "max": max_score,
        "pct": pct,
        "grade": score_grade(pct) if max_score else "—",
        "dimensions": [
            {
                "id": d["id"],
                "label": d["label"],
                "score": d["score"],
                "max": d["max"],
                "finding": d["finding"],
                "ok": d["ok"],
                "applicable": d["applicable"],
            }
            for d in dims
        ],
    }

    empirical = list(raw_tool.get("UndocumentedEmpirical") or [])
    if site_tool:
        for row in site_tool.get("undocumentedEmpirical") or []:
            if row not in empirical:
                empirical.append(row)
    return _fold_empirical_into_score(score, empirical)
