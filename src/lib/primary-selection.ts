/**
 * Pick the canonical "primary" issue from a duplicate group.
 *
 * Deterministic tiebreak chain (NOT first-encountered like DefectDojo, which
 * is fragile in batch processing):
 *   1. Highest severity wins (cautious view; if scanners disagree, take the worst)
 *   2. Most reference_identifiers wins (richest metadata as canonical)
 *   3. Lowest issue id (stable string sort) — last-resort tiebreak
 */

import { RefinedIssue, issueId } from "../frameworks/refined-issue.js";

const SEVERITY_TEXT_RANK: Record<string, number> = {
  critical: 9.5,
  high: 7.5,
  medium: 5.0,
  low: 2.5,
  info: 0.0,
};

function severityScore(issue: RefinedIssue): number {
  if (typeof issue.severity === "number") return issue.severity;
  if (issue.severity_code) {
    const r = SEVERITY_TEXT_RANK[issue.severity_code.toLowerCase()];
    if (r !== undefined) return r;
  }
  return 0;
}

function refIdCount(issue: RefinedIssue): number {
  return (issue.reference_identifiers ?? []).length;
}

export function pickPrimary(group: RefinedIssue[]): RefinedIssue {
  const sorted = [...group].sort((a, b) => {
    const sevDiff = severityScore(b) - severityScore(a);
    if (sevDiff !== 0) return sevDiff;
    const refDiff = refIdCount(b) - refIdCount(a);
    if (refDiff !== 0) return refDiff;
    return issueId(a).localeCompare(issueId(b));
  });
  return sorted[0];
}
