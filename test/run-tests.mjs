// Test runner — imports compiled dist/, loads fixtures, runs assertions.
// Run: npm test
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { findDuplicateGroups } from "../dist/tools/find-duplicate-groups.js";
import { normalizeStoIssues } from "../dist/tools/normalize-sto-issues.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

let failed = 0;
function pass(label) { console.log(`  \x1b[32m✓\x1b[0m ${label}`); }
function fail(label, msg) {
  console.log(`  \x1b[31m✗\x1b[0m ${label}\n      ${msg}`);
  failed++;
}
function check(cond, label, detail = "") {
  if (cond) pass(label); else fail(label, detail);
}
function section(title) {
  console.log(`\n── ${title} ${"─".repeat(Math.max(0, 56 - title.length))}`);
}

function loadFixture(name) {
  const path = join(__dirname, "fixtures", name, "input.json");
  return JSON.parse(readFileSync(path, "utf8"));
}

// ════════════════════════════════════════════════════════════════════════
// Fixture: SCA — Snyk + Grype + Aqua Trivy
// ════════════════════════════════════════════════════════════════════════
section("SCA: Snyk + Grype + Aqua Trivy on lodash");
{
  const fx = loadFixture("sca-snyk-grype-aqua");
  const result = findDuplicateGroups({ issues: fx.issues });
  console.log(JSON.stringify(result, null, 2));

  check(result.duplicate_groups.length === fx.expected.duplicate_groups,
        `${fx.expected.duplicate_groups} duplicate group`,
        `got ${result.duplicate_groups.length}`);
  const grp = result.duplicate_groups[0];
  check(grp?.confidence_tier === fx.expected.primary_tier,
        `tier is ${fx.expected.primary_tier}`,
        `got ${grp?.confidence_tier}`);
  check((grp?.duplicate_issue_ids.length ?? 0) + 1 === fx.expected.members_in_group,
        `${fx.expected.members_in_group} members in the group`,
        `got ${(grp?.duplicate_issue_ids.length ?? 0) + 1}`);
  check(grp?.scanners.length === 3,
        "all 3 scanners present in the group",
        `got ${grp?.scanners}`);
  check(result.stats.dedup_ratio > 0.4 && result.stats.dedup_ratio < 0.7,
        "dedup ratio reasonable for 3-of-4 reduction",
        `got ${result.stats.dedup_ratio}`);
  check(grp?.matched_signals?.library_name === "lodash",
        "matched_signals.library_name = lodash");
}

// ════════════════════════════════════════════════════════════════════════
// Fixture: SAST — Bandit + Semgrep
// ════════════════════════════════════════════════════════════════════════
section("SAST: Bandit + Semgrep on auth.py SQLi (line ±3)");
{
  const fx = loadFixture("sast-bandit-semgrep");
  const result = findDuplicateGroups({ issues: fx.issues });
  console.log(JSON.stringify(result, null, 2));

  check(result.duplicate_groups.length === fx.expected.duplicate_groups,
        `${fx.expected.duplicate_groups} duplicate group`,
        `got ${result.duplicate_groups.length}`);
  const grp = result.duplicate_groups[0];
  check(grp?.confidence_tier === fx.expected.primary_tier,
        `tier is ${fx.expected.primary_tier} (lines 147 vs 148, within ±3)`,
        `got ${grp?.confidence_tier}`);
  check(grp?.matched_signals?.file_name === "src/auth.py",
        "matched_signals.file_name = src/auth.py");
}

// ════════════════════════════════════════════════════════════════════════
// Fixture: Container — Trivy + Grype
// ════════════════════════════════════════════════════════════════════════
section("Container: Trivy + Grype (same layer = HIGH; diff layer = MEDIUM)");
{
  const fx = loadFixture("container-trivy-grype");
  const result = findDuplicateGroups({ issues: fx.issues });
  console.log(JSON.stringify(result, null, 2));

  check(result.duplicate_groups.length === fx.expected.duplicate_groups,
        `${fx.expected.duplicate_groups} HIGH-tier group only`,
        `got ${result.duplicate_groups.length}`);
  const grp = result.duplicate_groups[0];
  check(grp?.confidence_tier === fx.expected.primary_tier,
        `same-layer pair scored HIGH`,
        `got ${grp?.confidence_tier}`);
  check(result.review_candidates.length >= fx.expected.review_candidates_min,
        `at least ${fx.expected.review_candidates_min} review candidate (different-layer pair)`,
        `got ${result.review_candidates.length}`);
}

// ════════════════════════════════════════════════════════════════════════
// Fixture: No duplicates — must NOT false-positive
// ════════════════════════════════════════════════════════════════════════
section("No duplicates: control fixture");
{
  const fx = loadFixture("no-duplicates");
  const result = findDuplicateGroups({ issues: fx.issues });
  console.log(JSON.stringify(result, null, 2));

  check(result.duplicate_groups.length === fx.expected.duplicate_groups,
        "zero duplicate groups (no false positives)",
        `got ${result.duplicate_groups.length}`);
  check(result.review_candidates.length === fx.expected.review_candidates,
        "zero review candidates");
  check(result.stats.dedup_ratio === 0,
        "dedup ratio = 0");
}

// ════════════════════════════════════════════════════════════════════════
// Fixture: CVE↔GHSA cross-reference
// ════════════════════════════════════════════════════════════════════════
section("CVE ↔ GHSA cross-reference (Snyk uses GHSA, Grype uses CVE)");
{
  const fx = loadFixture("cve-ghsa-cross");
  const result = findDuplicateGroups({ issues: fx.issues });
  console.log(JSON.stringify(result, null, 2));

  check(result.duplicate_groups.length === fx.expected.duplicate_groups,
        "1 duplicate group via CVE↔GHSA expansion",
        `got ${result.duplicate_groups.length}`);
  const grp = result.duplicate_groups[0];
  check(grp?.confidence_tier === fx.expected.primary_tier,
        "tier HIGH despite different identifier types",
        `got ${grp?.confidence_tier}`);
}

// ════════════════════════════════════════════════════════════════════════
// SAST IMPROVEMENTS v2: Eval Injection, Semgrep namespace, cross-type rescue
// ════════════════════════════════════════════════════════════════════════
section("SAST v2 — Eval Injection / Semgrep namespace / cross-type rescue");
{
  const fx = loadFixture("sast-improvements-v2");
  const normalized = normalizeStoIssues({ issues: fx });
  console.log("normalize stats:", JSON.stringify(normalized.stats));

  // CWE inference from new keyword groups
  for (const expectedCwe of fx.expected.must_infer_cwes) {
    const found = normalized.refined_issues.some(i =>
      i.reference_identifiers?.some(r => r.id === expectedCwe)
    );
    check(found, `${expectedCwe} inferred from at least one title`);
  }

  // Cross-type rescue: ev1 (SECRET) and ev2 (SAST) have identical titles
  // → should appear as a review_candidate at HIGH threshold
  const dedupHigh = findDuplicateGroups({ issues: normalized.refined_issues });
  console.log("at HIGH threshold:", JSON.stringify(
    { groups: dedupHigh.duplicate_groups.length, review: dedupHigh.review_candidates.length }
  ));
  const crossType = dedupHigh.review_candidates.find(r =>
    (r.issue_a_id === "ev1" && r.issue_b_id === "ev2") ||
    (r.issue_a_id === "ev2" && r.issue_b_id === "ev1")
  );
  check(!!crossType, "cross-type rescue surfaces ev1↔ev2 (SECRET vs SAST, same title)");
  check(crossType?.matched_signals?.cross_type === "SECRET vs SAST" ||
        crossType?.matched_signals?.cross_type === "SAST vs SECRET",
        "cross_type label set on rescue match");

  // At LOW: cookie-session, eval, and other clusters should auto-group
  const dedupLow = findDuplicateGroups({ issues: normalized.refined_issues, group_threshold: "LOW" });
  console.log("at LOW threshold: ", JSON.stringify(
    { groups: dedupLow.duplicate_groups.length, by_tier: dedupLow.stats.groups_by_tier, ratio: dedupLow.stats.dedup_ratio }
  ));
  for (const g of dedupLow.duplicate_groups) {
    console.log(`  primary=${g.primary_issue_id} tier=${g.confidence_tier} signals=${JSON.stringify(g.matched_signals)}`);
  }
  check(dedupLow.duplicate_groups.length >= fx.expected.duplicate_groups_min_at_low,
        `at least ${fx.expected.duplicate_groups_min_at_low} groups at LOW threshold`,
        `got ${dedupLow.duplicate_groups.length}`);
}

// ════════════════════════════════════════════════════════════════════════
// REAL-SHAPE: SAST compact-list payload (CWE-keyword + backtick-file +
//             title-equality + library-version SAST tiers)
// ════════════════════════════════════════════════════════════════════════
section("Real SAST shapes — keyword CWE + backtick file + title equality + lib/ver");
{
  const fx = loadFixture("sast-real-mixed");
  const normalized = normalizeStoIssues({ issues: fx });
  console.log("normalize stats:", JSON.stringify(normalized.stats));
  check(normalized.stats.title_enriched_count >= fx.expected.title_enriched_count_min,
        `at least ${fx.expected.title_enriched_count_min} issues enriched from title`,
        `got ${normalized.stats.title_enriched_count}`);
  // Spot-checks: did we extract specific things?
  const xss = normalized.refined_issues.find(i => i.internal_id === "x1");
  check(xss?.file_name === "profile.js",
        "backtick file extracted: profile.js",
        `got ${xss?.file_name}`);
  check(xss?.reference_identifiers?.some(r => r.id === "CWE-79"),
        "CWE-79 inferred from 'Cross-Site Scripting'");
  const sql = normalized.refined_issues.find(i => i.internal_id === "s1");
  check(sql?.reference_identifiers?.some(r => r.id === "CWE-89"),
        "CWE-89 inferred from 'SQL Injection'");
  const trav = normalized.refined_issues.find(i => i.internal_id === "t1");
  check(trav?.reference_identifiers?.some(r => r.id === "CWE-22"),
        "CWE-22 inferred from 'Path Traversal'");
  const sec = normalized.refined_issues.find(i => i.internal_id === "k1");
  check(sec?.reference_identifiers?.some(r => r.id === "CWE-798"),
        "CWE-798 inferred from 'API key gets revoked' phrase");

  const dedup = findDuplicateGroups({ issues: normalized.refined_issues, group_threshold: "LOW" });
  console.log("dedup result:", JSON.stringify(
    { groups: dedup.duplicate_groups.length, by_tier: dedup.stats.groups_by_tier, ratio: dedup.stats.dedup_ratio }
  ));
  for (const g of dedup.duplicate_groups) {
    console.log(`  primary=${g.primary_issue_id} tier=${g.confidence_tier} signals=${JSON.stringify(g.matched_signals)}`);
  }
  check(dedup.duplicate_groups.length >= fx.expected.duplicate_groups_min_at_low,
        `at least ${fx.expected.duplicate_groups_min_at_low} groups (minimist family + xss-file + rce-file + sqli + path-traversal)`,
        `got ${dedup.duplicate_groups.length}`);
}

// ════════════════════════════════════════════════════════════════════════
// REAL-SHAPE: STO compact-list payload (title-enrichment path)
// ════════════════════════════════════════════════════════════════════════
section("Real STO compact list — title enrichment populates CVE + pkg + ver");
{
  const fx = loadFixture("sto-compact-list-real");
  const normalized = normalizeStoIssues({ issues: fx });
  console.log("normalize stats:", JSON.stringify(normalized.stats));
  check(normalized.stats.title_enriched_count === fx.expected.title_enriched_count,
        `${fx.expected.title_enriched_count} issues enriched from title`,
        `got ${normalized.stats.title_enriched_count}`);
  check(normalized.refined_issues.filter(i => i.reference_identifiers?.length).length >= 8,
        "at least 8 issues have CVE in reference_identifiers (parsed from title)");

  // Default threshold = HIGH → sibling-package clusters land in review_candidates
  const dedupHigh = findDuplicateGroups({ issues: normalized.refined_issues });
  console.log("at HIGH threshold:", JSON.stringify(
    { groups: dedupHigh.duplicate_groups.length, review: dedupHigh.review_candidates.length }
  ));
  check(dedupHigh.review_candidates.length >= fx.expected.review_candidates_min_at_high_threshold,
        `at least ${fx.expected.review_candidates_min_at_high_threshold} review candidates at HIGH threshold (sibling-pkg pairs surface here, not auto-grouped)`,
        `got ${dedupHigh.review_candidates.length}`);

  // Lowered threshold = LOW → sibling-package clusters DO auto-group
  const dedupLow = findDuplicateGroups({ issues: normalized.refined_issues, group_threshold: "LOW" });
  console.log("at LOW threshold: ", JSON.stringify(
    { groups: dedupLow.duplicate_groups.length, by_tier: dedupLow.stats.groups_by_tier, ratio: dedupLow.stats.dedup_ratio }
  ));
  check(dedupLow.duplicate_groups.length >= fx.expected.duplicate_groups_min_at_low_threshold,
        `at least ${fx.expected.duplicate_groups_min_at_low_threshold} duplicate groups at LOW threshold (sibling-pkg CVE clusters)`,
        `got ${dedupLow.duplicate_groups.length}`);
  console.log("LOW-threshold groups:");
  for (const g of dedupLow.duplicate_groups) {
    console.log(`  primary=${g.primary_issue_id} tier=${g.confidence_tier} signals=${JSON.stringify(g.matched_signals)}`);
  }
  for (const cve of fx.expected.groups_must_include_cves) {
    const grp = dedupLow.duplicate_groups.find(g =>
      JSON.stringify(g.matched_signals).toUpperCase().includes(cve)
    );
    check(!!grp, `group covering ${cve} exists at LOW threshold`);
  }
}

// ════════════════════════════════════════════════════════════════════════
// NORMALIZER (raw STO API JSON → RefinedIssue)
// ════════════════════════════════════════════════════════════════════════
section("Normalizer: tolerates JSON-stringified input (LLM round-trip quirk)");
{
  const fx = loadFixture("normalize-sto-api");
  // Simulate the LLM passing a stringified version (real-world quirk seen in QA)
  const normalized = normalizeStoIssues({ issues: JSON.stringify(fx) });
  console.log("from stringified input:", JSON.stringify(normalized.stats));
  check(normalized.stats.output_count === 2,
        "auto-parses JSON string and produces 2 normalized issues",
        `got ${normalized.stats.output_count}`);
  check(normalized.refined_issues[0]?.library_name === "lodash",
        "field-mapping still works on stringified input");
}

section("Normalizer: raw STO API → RefinedIssue, then dedup");
{
  const fx = loadFixture("normalize-sto-api");
  // Step 1: normalize the raw API payload
  const normalized = normalizeStoIssues({ issues: fx });
  console.log("normalize stats:", JSON.stringify(normalized.stats));
  check(normalized.stats.output_count === fx.expected.output_count,
        `${fx.expected.output_count} normalized issues`,
        `got ${normalized.stats.output_count}`);
  check(normalized.refined_issues.every(i => i.product_name && i.library_name && i.current_version),
        "all camelCase fields mapped to snake_case (productName→product_name, libraryName→library_name, currentVersion→current_version)");
  check(fx.expected.scanners.every(s => normalized.stats.scanners[s] !== undefined),
        `expected scanners (${fx.expected.scanners.join(", ")}) all present in stats`);
  check(normalized.refined_issues.every(i => i.issue_type === "SCA"),
        "issueType → issue_type as enum");

  // Step 2: feed into dedup
  const dedup = findDuplicateGroups({ issues: normalized.refined_issues });
  console.log("dedup result:", JSON.stringify(dedup.duplicate_groups, null, 2));
  check(dedup.duplicate_groups.length === fx.expected.after_dedup_groups,
        `${fx.expected.after_dedup_groups} duplicate group after dedup`);
  check(dedup.duplicate_groups[0]?.confidence_tier === fx.expected.after_dedup_tier,
        `tier ${fx.expected.after_dedup_tier} after dedup`);
}

console.log("");
if (failed === 0) {
  console.log("\x1b[32mAll checks passed.\x1b[0m");
  process.exit(0);
} else {
  console.log(`\x1b[31m${failed} check(s) failed.\x1b[0m`);
  process.exit(1);
}
