/**
 * find_duplicate_groups
 *
 * Given a flat list of STO `RefinedIssue` objects, cluster them into duplicate
 * groups using same-type tiered matching, and return groups with confidence
 * tier, primary issue, and matched-signal evidence.
 *
 * Architecture:
 *   1. For each pair (a, b) where a.issue_type === b.issue_type, run matchPair
 *   2. If tier ≥ threshold (default HIGH, configurable), union them in DSU
 *   3. Read the resulting groups; for each multi-issue group:
 *      - pick primary deterministically
 *      - record the highest tier seen across pairs in the group
 *      - emit a structured group record
 *
 * Complexity: O(N²) on issues per type. Acceptable for typical scan sizes
 * (hundreds of issues per type). Bucket-by-refid optimisation deferred.
 */

import { RefinedIssue, issueId, IssueType } from "../frameworks/refined-issue.js";
import { matchPair, Tier, TierMatch } from "../lib/tier-match.js";
import { UnionFind } from "../lib/union-find.js";
import { pickPrimary } from "../lib/primary-selection.js";

export interface FindGroupsInput {
  issues: RefinedIssue[];
  /** Lowest tier to use for grouping. Default: HIGH (auto-group only). */
  group_threshold?: Tier;
}

export interface DuplicateGroup {
  primary_issue_id: string;
  duplicate_issue_ids: string[];
  confidence_tier: Tier;
  scanners: string[];
  matched_signals: Record<string, string | string[]>;
  rationale: string;
}

export interface ReviewCandidatePair {
  issue_a_id: string;
  issue_b_id: string;
  confidence_tier: Tier;
  matched_signals: Record<string, string | string[]>;
  rationale: string;
}

export interface FindGroupsOutput {
  scope: { issue_count: number; types_seen: IssueType[] };
  duplicate_groups: DuplicateGroup[];
  review_candidates: ReviewCandidatePair[];
  stats: {
    input_issue_count: number;
    output_unique_issue_count: number;
    dedup_ratio: number;
    groups_by_tier: Record<Tier, number>;
  };
  framework: string;
  warnings: string[];
}

const TIER_RANK: Record<Tier, number> = { LOW: 1, MEDIUM: 2, HIGH: 3 };

export function findDuplicateGroups(input: FindGroupsInput): FindGroupsOutput {
  const issues = input.issues;
  const threshold: Tier = input.group_threshold ?? "HIGH";
  const warnings: string[] = [];

  // Index issues by id for primary selection later
  const byId = new Map<string, RefinedIssue>();
  for (const issue of issues) {
    const id = issueId(issue);
    if (byId.has(id)) {
      warnings.push(`Duplicate input issue id "${id}" — keeping first occurrence.`);
    } else {
      byId.set(id, issue);
    }
  }

  // Track every pairwise match (for review candidates and group tier reporting)
  const allPairs: Array<{
    a: RefinedIssue;
    b: RefinedIssue;
    match: TierMatch;
  }> = [];

  // Compare ALL pairs (O(N²)). matchPair short-circuits on type-mismatch
  // EXCEPT for the cross-type title-equality rescue rule (which catches
  // STO API tagging quirks). For typical scan sizes (≤500 issues) this
  // is ~125K comparisons — milliseconds. Bucket-by-refid optimisation
  // can be added later if N grows past that.
  const typed = issues.filter((i) => i.issue_type);
  for (let i = 0; i < typed.length; i++) {
    for (let j = i + 1; j < typed.length; j++) {
      const m = matchPair(typed[i], typed[j]);
      if (m) allPairs.push({ a: typed[i], b: typed[j], match: m });
    }
  }

  // Build the union-find using only pairs at or above threshold
  const dsu = new UnionFind<string>();
  for (const id of byId.keys()) dsu.add(id);
  for (const { a, b, match } of allPairs) {
    if (TIER_RANK[match.tier] >= TIER_RANK[threshold]) {
      dsu.union(issueId(a), issueId(b));
    }
  }

  // Materialize duplicate groups (size >= 2)
  const dupGroups: DuplicateGroup[] = [];
  for (const [, members] of dsu.groups()) {
    if (members.length < 2) continue;
    const memberIssues = members
      .map((id) => byId.get(id))
      .filter((x): x is RefinedIssue => !!x);
    if (memberIssues.length < 2) continue;

    const primary = pickPrimary(memberIssues);
    const primaryId = issueId(primary);

    // Find the BEST (highest-tier) match within this group to label confidence.
    // Use `>=` so the first match initializes bestMatch even when the only
    // tier seen is LOW (otherwise matched_signals would be empty).
    let bestTier: Tier | null = null;
    let bestMatch: TierMatch | null = null;
    for (const { a, b, match } of allPairs) {
      const ai = issueId(a);
      const bi = issueId(b);
      const aIn = members.includes(ai);
      const bIn = members.includes(bi);
      if (aIn && bIn) {
        if (bestTier === null || TIER_RANK[match.tier] > TIER_RANK[bestTier]) {
          bestTier = match.tier;
          bestMatch = match;
        }
      }
    }
    const finalTier: Tier = bestTier ?? "LOW";

    const scanners = [
      ...new Set(memberIssues.map((m) => m.product_name).filter(Boolean)),
    ] as string[];

    dupGroups.push({
      primary_issue_id: primaryId,
      duplicate_issue_ids: members.filter((id) => id !== primaryId),
      confidence_tier: finalTier,
      scanners,
      matched_signals: bestMatch?.matched_signals ?? {},
      rationale: bestMatch?.rationale ?? "Grouped via transitive duplicate match.",
    });
  }

  // Review candidates: pairs that matched at MEDIUM or LOW but didn't meet threshold,
  // AND aren't already in an auto-group together
  const groupedPairs = new Set<string>();
  for (const g of dupGroups) {
    const ids = [g.primary_issue_id, ...g.duplicate_issue_ids];
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        groupedPairs.add(`${ids[i]}|${ids[j]}`);
        groupedPairs.add(`${ids[j]}|${ids[i]}`);
      }
    }
  }
  const reviewCandidates: ReviewCandidatePair[] = [];
  for (const { a, b, match } of allPairs) {
    if (TIER_RANK[match.tier] >= TIER_RANK[threshold]) continue;
    const ai = issueId(a);
    const bi = issueId(b);
    if (groupedPairs.has(`${ai}|${bi}`)) continue;
    reviewCandidates.push({
      issue_a_id: ai,
      issue_b_id: bi,
      confidence_tier: match.tier,
      matched_signals: match.matched_signals,
      rationale: match.rationale,
    });
  }

  const groupsByTier: Record<Tier, number> = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const g of dupGroups) groupsByTier[g.confidence_tier]++;

  // unique issue count = total - sum(group_size - 1) — each group collapses to 1
  const dupReduction = dupGroups.reduce(
    (sum, g) => sum + g.duplicate_issue_ids.length,
    0,
  );
  const uniqueCount = byId.size - dupReduction;

  return {
    scope: {
      issue_count: byId.size,
      types_seen: [...new Set(issues.map((i) => i.issue_type).filter(Boolean))] as IssueType[],
    },
    duplicate_groups: dupGroups,
    review_candidates: reviewCandidates,
    stats: {
      input_issue_count: byId.size,
      output_unique_issue_count: uniqueCount,
      dedup_ratio: byId.size > 0 ? dupReduction / byId.size : 0,
      groups_by_tier: groupsByTier,
    },
    framework:
      "DefectDojo-style hash-field tiering (https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/) + Trivy/Snyk per-scanner field practice",
    warnings,
  };
}
