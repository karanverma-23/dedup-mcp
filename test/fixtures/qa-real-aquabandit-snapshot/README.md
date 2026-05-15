# QA Real-Data Snapshot — pipeline AQUABANDITGITLEAKS

Captured 2026-05-15 from QA STO project `STO` org `default`.

## Result baseline (the demo numbers)

| Metric | Value |
|---|---|
| Input issues from list endpoint | 50 |
| `title_enriched_count` | 50 (every issue had CVE+pkg in title) |
| Duplicate groups @ LOW threshold | 10 |
| Output unique issues | 21 |
| **Dedup ratio** | **58%** |

## Cluster breakdown

| CVE | Members | Family |
|---|---|---|
| CVE-2017-13716 | 8 | binutils* |
| CVE-2022-3219 | 7 | gpg* / dirmngr |
| CVE-2016-20013 | 5 | libc6* / libc-* |
| CVE-2024-26462 | 5 | krb5* |
| CVE-2024-10041 | 4 | libpam* |
| CVE-2024-56433 | 2 | login + passwd |
| CVE-2024-52005 | 2 | git + git-man |
| CVE-2025-27144 | 2 | go-jose v3 + v4 |
| CVE-2025-69421 | 2 | openssl + libssl3t64 |
| CVE-2025-0167  | 2 | curl + libcurl4t64 |

10 groups × avg 3.9 members = 39 dedup'd. 50 - 39 + 10 (the kept primaries) = 21 unique.

## To regenerate on a fresh QA pipeline

```
Use harness-mcp to list security issues for pipeline_ids="AQUABANDITGITLEAKS"
in org "default" project "STO", size=200.
Then dedup-mcp.normalize_sto_issues on the response.
Then dedup-mcp.find_duplicate_groups with refined_issues + group_threshold="LOW".
```

## Known limitations on this snapshot

- `scanners: []` on every group because the list endpoint doesn't return
  `productName`. Fix: either add `harness_get(security_issue, id=...)` enrichment
  in the orchestrator, or pass `default_product_name: "aqua_trivy"` when
  calling normalize (acceptable for single-scanner pipelines).
- All groups land at LOW tier (sibling-package clusters by definition share
  CVE but not library_name). MEDIUM/HIGH would only appear with multiple
  scanners flagging the same library@version.
