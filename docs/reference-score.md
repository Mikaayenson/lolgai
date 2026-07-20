# Reference score (computed catalog completeness)

The **Score** tab on each tool page is generated at build time by `bin/reference_score.py`.
The reference breakdown appears first; editorial **Readiness** (A/B/C) and data-provenance
detail are on the same tab below it.

| Concept | Meaning |
| --- | --- |
| **Reference score** | Weighted sum of eight YAML field groups (max 15). Letter grade A+ to D from percentage of applicable max. |
| **Readiness (A/B/C)** | Editorial policy for detection-engineering handoff. May diverge from the reference score. |

Regenerate after YAML edits:

```bash
python3 bin/validate.py && python3 bin/site.py
```

## Dimensions (weights)

| Dimension | Max | LOL-GAI sources |
| --- | ---: | --- |
| Process Telemetry | 3 | `Details.Binaries`, `CliExecutable`, `HelperProcesses`, surface binaries |
| Code Signature | 2 | `Signing.<OS>.Depth` (+ identity fields); best platform wins |
| Config Paths | 2 | `Details.ConfigDirs`, surface `ConfigDirs`, `Artifacts.ConfigFiles` |
| Attribution | 3 | `DetectionOpportunities[].AttributionSignals` (ranked signals score even when `Agentic: false`, e.g. MCP servers) |
| Network Artifacts | 1 | `Artifacts.Network[].Domains` |
| Context Files | 1 | `Details.ContextFiles`, `Integrations.Skills`, `CustomAgents`, skill artifact paths |
| Data Quality | 2 | `Coverage.Verified` + `Coverage.Confidence` |
| Reference Docs | 1 | `Resources` links (+ `OfficialUrl` when not duplicated) |

Non-applicable dimensions (no local process footprint, VS Code extension host signing, etc.)
are marked **n/a** and excluded from the maximum.

## Grade thresholds

| Grade | Percent of applicable max |
| --- | --- |
| A+ | ≥ 95% |
| A | ≥ 90% |
| B | ≥ 75% |
| C | ≥ 60% |
| D | < 60% |

## LOL-GAI scoring notes

- **Local footprint**: Process/config dimensions apply when binaries or CLI are documented,
  even if `Framework: api_only` (community CLIs).
- **Attribution**: Ranked `AttributionSignals` score full points regardless of `Agentic`;
  non-agentic tools without signals score 0 with an explicit finding.
- **Signing**: Maps `Depth: full | authenticode | partial | shared_host` per OS;
  `UsableForAttribution: false` downgrades when only host/shared identity is known.
