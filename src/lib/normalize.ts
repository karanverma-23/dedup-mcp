/**
 * Field normalization for cross-scanner comparison.
 *
 * Rules are intentionally narrow — only changes that don't lose information
 * (case, leading whitespace, version-prefix glyphs).
 */

import { ReferenceIdentifier } from "../frameworks/refined-issue.js";

export function lower(s: string | undefined | null): string {
  return (s ?? "").trim().toLowerCase();
}

/**
 * Strip common version-prefix glyphs and trailing punctuation that titles
 * sometimes leak in (e.g. trailing `:` or `,` from `pkg@1.2.3: vuln description`).
 *   "v4.17.20"      → "4.17.20"
 *   "^4.17.20"      → "4.17.20"
 *   "~4.17.20"      → "4.17.20"
 *   "= 4.17.20"     → "4.17.20"
 *   "  4.17.20  "   → "4.17.20"
 *   "0.6.9:"        → "0.6.9"
 *   "1.5.3-5ubuntu5.1," → "1.5.3-5ubuntu5.1"
 */
export function normalizeVersion(v: string | undefined | null): string {
  if (!v) return "";
  return v
    .trim()
    .replace(/^[v^~=\s]+/i, "")
    .replace(/[:,;.\s]+$/, "")
    .trim()
    .toLowerCase();
}

/**
 * Path-normalize a file name: lowercase only on Windows-like paths is a
 * footgun, so we leave case alone but strip "./" and trailing whitespace.
 */
export function normalizePath(p: string | undefined | null): string {
  if (!p) return "";
  return p.trim().replace(/^\.\//, "");
}

/**
 * Build a canonical Set<string> of "type:id" tokens from a reference
 * identifiers list. Type is lowercased; id is uppercased (CVE/GHSA convention).
 */
export function refIdSet(
  refs: ReferenceIdentifier[] | undefined,
): Set<string> {
  const out = new Set<string>();
  for (const r of refs ?? []) {
    if (!r?.type || !r?.id) continue;
    out.add(`${r.type.toLowerCase()}:${r.id.toUpperCase()}`);
  }
  return out;
}

/** Set intersection convenience. */
export function intersect<T>(a: Set<T>, b: Set<T>): Set<T> {
  const out = new Set<T>();
  for (const x of a) if (b.has(x)) out.add(x);
  return out;
}
