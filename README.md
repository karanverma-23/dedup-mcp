# dedup-mcp

MCP server exposing **deterministic same-type vulnerability deduplication** for Harness STO findings.

Part of the **Exemption Workflow Automation** umbrella alongside component-level exemption automation and an exemption revocation engine. This component is responsible for grouping STO findings that refer to the same underlying vulnerability so downstream agents can act on one canonical issue per group instead of N duplicate tickets.

## Tools exposed

| Tool | What it does |
|---|---|
| `normalize_sto_issues` | Convert raw STO Core API issue payloads (camelCase) into the snake_case `RefinedIssue` shape. Tolerant of multiple wrapper shapes. Falls back to title-parsing when structured fields are absent (extracts CVE / GHSA / CWE / `package@version` / file path). |
| `find_duplicate_groups` | Cluster a flat list of `RefinedIssue` records into duplicate groups, with confidence tier, matched signals, deterministically-picked primary per group, and a separate list of MEDIUM/LOW review candidates. |
| `compare_pair` | Single-pair tier check — returns the highest tier two issues match at, or `null`. Useful for ad-hoc investigation. |

## Quick start

```bash
npm install
npm test          # 47 checks across 8 fixtures, all green
npm run inspect   # MCP Inspector UI to call tools interactively
```

## Transports

- **stdio** (default) — for Cursor / Claude Desktop / Windsurf
- **HTTP** — `node dist/cli.js http` (defaults to port 8080, override via `PORT`). Used when reachable from a remote orchestrator (Worker Agent + tunnel).

## How matching works

For every pair of same-type issues we run a tier check (DefectDojo-style hash-field sets, adapted for cross-scanner availability gaps).

| Issue type | T1 (HIGH) | T2 (MEDIUM) | T3 (LOW) |
|---|---|---|---|
| **SCA** | ref_id ∩ + library + version | ref_id ∩ + library | ref_id ∩ only |
| **SAST** | cwe + file + line ±3 | cwe + file *or* same library+version (T2b — for SCA-shaped data labeled SAST) | cwe only *or* identical title (T3b — re-scan duplicates) |
| **CONTAINER** | ref_id ∩ + library + version + layer | ref_id ∩ + (library+ver) OR (ref_id+layer) | ref_id ∩ only |

Plus a narrow **cross-type RESCUE** for byte-for-byte identical titles across `issue_type` boundaries (catches STO API tagging quirks where the same finding lands as both SECRET and SAST). Only ever surfaces in `review_candidates`, never auto-grouped.

- **HIGH** matches → auto-grouped as duplicates
- **MEDIUM** matches → surfaced as `review_candidates` at default `group_threshold="HIGH"`
- **LOW** matches → reported as weak signals, NOT auto-grouped at HIGH threshold (false-positive risk per [Grype #2993](https://github.com/anchore/grype/issues/2993), [Grype #495](https://github.com/anchore/grype/issues/495))

Pairwise matches are clustered into groups via Union-Find. Within each group the "primary" is picked deterministically: highest severity → most reference_identifiers → lowest issue id.

CVE ↔ GHSA cross-referencing is handled via a hardcoded map of ~25 well-known pairs (`src/frameworks/cve-ghsa-map.ts`). NVD live API isn't used because of [1–10 s per-call latency and 6 s rate limit](https://gist.github.com/adulau/3940e1d3711ae03d6aef055b97ca458c).

### Title enrichment

When the STO API payload omits `referenceIdentifiers`, `libraryName`, `currentVersion`, or `fileName` (the compact-list endpoint omits all of these), the normalizer parses the `title` field for:

- CVE / GHSA / CWE / SNYK identifiers
- ~30 CWE-keyword inferences (`SQL Injection` → CWE-89, `Path Traversal` → CWE-22, `Prototype Pollution` → CWE-1321, etc.)
- Semgrep namespace patterns (`express-cookie-session-no-secure` → CWE-614, `detected-private-key` → CWE-798, etc.)
- `package@version` pairs (npm-style)
- Backtick-wrapped file paths (`` `config.js` `` or `` `profile.js:Class.method` ``)

This is what makes dedup work on the compact list endpoint without a per-issue `harness_get` hydration round-trip.

## Output shape

```jsonc
{
  "scope":   { "issue_count": 4, "types_seen": ["SCA"] },
  "duplicate_groups": [
    {
      "primary_issue_id": "iss-001",
      "duplicate_issue_ids": ["iss-002", "iss-003"],
      "confidence_tier": "HIGH",
      "scanners": ["snyk", "grype", "aqua_trivy"],
      "matched_signals": {
        "reference_identifiers": ["cve:CVE-2021-23337"],
        "library_name": "lodash",
        "current_version": "4.17.20"
      },
      "rationale": "SCA T1 match: shared identifier cve:CVE-2021-23337 on lodash@4.17.20."
    }
  ],
  "review_candidates": [ /* MEDIUM/LOW pairs that didn't auto-group */ ],
  "stats": {
    "input_issue_count": 4,
    "output_unique_issue_count": 2,
    "dedup_ratio": 0.5,
    "groups_by_tier": { "HIGH": 1, "MEDIUM": 0, "LOW": 0 }
  },
  "framework": "DefectDojo-style hash-field tiering ...",
  "warnings": []
}
```

This is the contract a downstream Exemption Workflow consumer expects:
- Auto-exempt the `duplicate_issue_ids` of each `HIGH`-tier group
- Open a Slack thread per group at MEDIUM tier for human review
- Ignore LOW-tier review candidates by default; opt in via `group_threshold="LOW"` for sibling-package noise reduction

## Citations / source links

- DefectDojo dedup philosophy: https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/
- DefectDojo per-scanner hash fields: https://docs.defectdojo.com/triage_findings/finding_deduplication/os__deduplication_tuning/
- Trivy internal dedup: https://github.com/aquasecurity/trivy/issues/3274
- CVE-only false-positive evidence (httpd-tools): https://github.com/anchore/grype/issues/2993
- NVD API performance: https://gist.github.com/adulau/3940e1d3711ae03d6aef055b97ca458c
- STO `RefinedIssue` schema: `sto_plugins/packages/python/sto_plugin/src/sto_plugin/refinement/refined_issue.py`

## What's deferred to v2

- Cross-type dedup (SCA → Container → DAST causal chain) — explicitly out of scope for v1
- Live NVD / GitHub Advisory lookup for richer CVE ↔ GHSA mapping
- Optional SHA256 hashing of matched fields for privacy when evidence shouldn't be in the clear
- Per-issue `harness_get` hydration for line numbers (needed to unlock SAST T1 / HIGH tier matches when scanners don't include line numbers in the compact list payload)
