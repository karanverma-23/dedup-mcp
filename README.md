# dedup-mcp

MCP server exposing **deterministic same-type vulnerability deduplication** for Harness STO findings (Agent Dev Days 2026, Work 3).

Part of the **Exemption Workflow Automation** umbrella:
- (Tarun) Component-level exemptions
- **(Karan) Vulnerability dedup ← this**
- (Mohit) Exemption revocation engine

## Tools exposed

| Tool | What it does |
|---|---|
| `find_duplicate_groups` | Cluster a flat list of `RefinedIssue` records into duplicate groups, with confidence tier, matched signals, and a deterministically-picked primary per group |
| `compare_pair` | Single-pair tier check — returns the highest tier two issues match at, or `null`. Useful for ad-hoc investigation |

## Quick start

```bash
npm install
npm test          # 16 checks across 5 fixtures, all green
npm run inspect   # MCP Inspector UI to call tools interactively
```

## How matching works

For every pair of same-type issues we run a tier check (DefectDojo-style hash-field
sets, adapted for cross-scanner availability gaps).

| Issue type | T1 (HIGH) | T2 (MEDIUM) | T3 (LOW) |
|---|---|---|---|
| **SCA** | ref_id ∩ + library + version | ref_id ∩ + library | ref_id ∩ only |
| **SAST** | cwe + file + line ±3 | cwe + file | cwe only |
| **CONTAINER** | ref_id ∩ + library + version + layer | ref_id ∩ + (library+ver) OR (ref_id+layer) | ref_id ∩ only |

- **HIGH** matches → auto-grouped as duplicates
- **MEDIUM** matches → surfaced as `review_candidates` (human approval gate)
- **LOW** matches → reported as weak signal, NOT grouped (false-positive risk per
  [Grype #2993](https://github.com/anchore/grype/issues/2993),
  [Grype #495](https://github.com/anchore/grype/issues/495))

Pairwise matches are clustered into groups via Union-Find. Within each group the
"primary" is picked deterministically: highest severity → most reference_identifiers → lowest issue id.

CVE ↔ GHSA cross-referencing is handled via a hardcoded map of ~25 well-known
pairs (`src/frameworks/cve-ghsa-map.ts`). NVD live API isn't used because of
[1–10 s per-call latency and 6 s rate limit](https://gist.github.com/adulau/3940e1d3711ae03d6aef055b97ca458c).

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

This is the contract Tarun's Exemption Workflow agent consumes:
- Auto-exempt the `duplicate_issue_ids` of each `HIGH`-tier group
- Open Slack thread per group at MEDIUM tier for human review
- Ignore LOW-tier review candidates by default

## Citations / source links

- DefectDojo dedup philosophy: https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/
- DefectDojo per-scanner hash fields: https://docs.defectdojo.com/triage_findings/finding_deduplication/os__deduplication_tuning/
- Trivy internal dedup: https://github.com/aquasecurity/trivy/issues/3274
- CVE-only false-positive evidence (httpd-tools): https://github.com/anchore/grype/issues/2993
- NVD API performance: https://gist.github.com/adulau/3940e1d3711ae03d6aef055b97ca458c
- STO `RefinedIssue` schema: `sto_plugins/packages/python/sto_plugin/src/sto_plugin/refinement/refined_issue.py`

## What's deferred to v2

- Cross-type dedup (SCA→Container→DAST chain) — explicitly out of scope per Lavakush
- Live NVD/GitHub Advisory lookup for richer CVE↔GHSA mapping
- Hashing for privacy (currently emits matched fields in the clear; v2 should optionally SHA256 them)
- `harness_get` for individual issue details (MCP server doesn't expose it today; orchestrator must work from `harness_list` payload)
