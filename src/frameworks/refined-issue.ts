/**
 * TypeScript shape of the STO `RefinedIssue` we accept as input.
 *
 * Source of truth for the field names:
 *   sto_plugins/packages/python/sto_plugin/src/sto_plugin/refinement/refined_issue.py
 *
 * We accept a SUPERSET of fields (some scanners populate more, some fewer).
 * Unknown fields are tolerated and ignored.
 */

export type IssueType =
  | "SAST"
  | "SCA"
  | "DAST"
  | "IAC"
  | "SECRET"
  | "MISCONFIG"
  | "CONTAINER";

export interface ReferenceIdentifier {
  /** Lowercase canonical type: "cve" | "cwe" | "ghsa" | "snyk" | "temp" */
  type: string;
  /** Identifier value, e.g. "CVE-2021-23337" */
  id: string;
}

export interface RefinedIssue {
  // ── identity ────────────────────────────────────────────────
  /** Stable issue id from STO core (preferred for output) */
  internal_id?: string;
  /** Alias accepted by some clients */
  id?: string;

  account_id?: string;
  scan_id?: string;

  /** Scanner identifier (uuid); non-portable across scanners */
  product_id?: string;
  /** Scanner display name: "snyk", "grype", "aqua_trivy", "bandit", "semgrep", "zap" */
  product_name?: string;

  // ── classification ──────────────────────────────────────────
  issue_type?: IssueType;

  /** Universal cross-scanner identifier list (CVE, CWE, GHSA, ...) */
  reference_identifiers?: ReferenceIdentifier[];

  // ── severity ────────────────────────────────────────────────
  /** Numeric 0-10 (CVSS-like), used for primary selection */
  severity?: number;
  /** Textual: "critical" | "high" | "medium" | "low" | "info" */
  severity_code?: string;

  // ── content ─────────────────────────────────────────────────
  title?: string;
  issue_description?: string;

  // ── SCA-specific ────────────────────────────────────────────
  library_name?: string;
  current_version?: string;

  // ── SAST-specific ───────────────────────────────────────────
  file_name?: string;
  line_number?: number;
  start_line?: number;
  end_line?: number;

  // ── Container-specific ──────────────────────────────────────
  image_layer_id?: string;
  image_registry?: string;
  image_tag?: string;
}

/**
 * Resolve the canonical id we'll emit in output, preferring the
 * STO-core internal_id, then id, then a deterministic fallback.
 */
export function issueId(issue: RefinedIssue): string {
  return (
    issue.internal_id ??
    issue.id ??
    `unknown:${issue.product_name ?? "?"}:${issue.scan_id ?? "?"}:${issue.title ?? "?"}`
  );
}
