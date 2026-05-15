/**
 * Extract structured fields from STO issue `title` strings.
 *
 * STO Core's `/all-issues/issues` list endpoint returns a compact payload
 * that drops `referenceIdentifiers`, `libraryName`, and `currentVersion`.
 * The data is still present — just embedded in `title` using a consistent
 * convention. Examples seen in QA:
 *
 *   "CVE-2024-10041: libpam0g@1.5.3-5ubuntu5.1 (os-pkgs, ubuntu)"
 *   "CVE-2016-20013: libc6@2.39-0ubuntu8 (os-pkgs)"
 *   "GHSA-jfh8-c2jp-5v3q: log4j-core@2.14.1"
 *   "CVE-2025-27144: github.com/go-jose/go-jose/v3@3.0.3"
 *   "Prototype Pollution in lodash"   (no IDs — extractor returns nulls)
 *
 * Strategy: regex-extract any number of CVE / GHSA tokens, plus the first
 * `<package>@<version>` pair. Used by `normalize-sto-issues.ts` ONLY when
 * the structured fields are absent from the API payload.
 */

import { ReferenceIdentifier } from "../frameworks/refined-issue.js";

// CVE: CVE-YYYY-N{4,7}
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
// GHSA: GHSA-xxxx-xxxx-xxxx (alnum, lowercase canonical but tolerate caps)
const GHSA_RE = /\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b/gi;
// CWE: CWE-N
const CWE_RE = /\bCWE-\d{1,4}\b/gi;
// SNYK ID: SNYK-X-Y-N
const SNYK_RE = /\bSNYK-[A-Z]+-[A-Z0-9]+-\d+\b/gi;

/**
 * CWE keyword map — when titles describe vulns in English (no CWE-NNN token)
 * we infer the CWE from canonical names. Sources for the mappings:
 *   - MITRE CWE catalogue (https://cwe.mitre.org/data/definitions/)
 *   - OWASP Top 10 mapping
 *
 * The list is curated for the most common SAST/secret-scanner output. Adding
 * a new entry: pick a regex that is unambiguous (whole-word, not a substring
 * that could appear in unrelated prose).
 */
const CWE_KEYWORDS: Array<[RegExp, string]> = [
  [/\b(?:SQL Injection|SQLi)\b/i,                                                "CWE-89"],
  [/\b(?:Cross[-\s]?Site Scripting|Stored[_\s]?XSS|Reflected[_\s]?XSS|DOM[_\s]?XSS|XSS)\b/i, "CWE-79"],
  [/\b(?:Path Traversal|Directory Traversal|Pathname.*Restricted Directory)\b/i, "CWE-22"],
  [/\b(?:Remote Code Execution|RCE|Code[_\s]?Injection|JavaScript[_\s]Server[_\s]Side[_\s]Vulnerabilities)\b/i, "CWE-94"],
  [/\b(?:Command Injection|OS Command Injection)\b/i,                            "CWE-78"],
  [/\b(?:Open Redirect|Unvalidated Redirect)\b/i,                                "CWE-601"],
  [/\b(?:Prototype Pollution)\b/i,                                               "CWE-1321"],
  [/\b(?:Hardcoded (?:Credential|Secret|Password|API[\s]?Key))/i,                "CWE-798"],
  [/(?:API[\s]?Key|Token|Secret|Credential).{0,40}(?:revoked|removed|exposed|leak)/i, "CWE-798"],
  [/\b(?:ReDoS|Regular Expression Denial of Service)\b/i,                        "CWE-1333"],
  [/\b(?:Insecure Deserialization|Deserialization of Untrusted Data)\b/i,        "CWE-502"],
  [/\b(?:Server[-\s]?Side Request Forgery|SSRF)\b/i,                             "CWE-918"],
  [/\b(?:Cross[-\s]?Site Request Forgery|CSRF)\b/i,                              "CWE-352"],
  [/\b(?:XML External Entity|XXE)\b/i,                                           "CWE-611"],
  [/\b(?:LDAP Injection)\b/i,                                                    "CWE-90"],
  [/\b(?:NoSQL Injection)\b/i,                                                   "CWE-943"],
  [/\b(?:Improper Authentication)\b/i,                                           "CWE-287"],
  [/\b(?:Improper Authorization|Missing Authorization|Broken Access Control|Insecure Direct Object Reference|IDOR)\b/i, "CWE-285"],
  [/\b(?:Buffer Overflow|Buffer Over[-\s]?read|Buffer Under[-\s]?write)\b/i,     "CWE-119"],
  [/\b(?:Use After Free)\b/i,                                                    "CWE-416"],
  [/\b(?:Race Condition)\b/i,                                                    "CWE-362"],
  // Eval / dynamic code injection (Improvement #1)
  [/\b(?:Eval Injection|Improper neutralization of directives in dynamically evaluated code)\b/i, "CWE-95"],

  // ── Semgrep rule-namespace mining (Improvement #2) ─────────────────
  // Patterns like "Semgrep Finding: nodejsscan.javascript-no-csrf-token"
  // or rule ids like "express-cookie-session-no-secure" carry the CWE
  // mapping in the rule name itself. Curated from the OWASP Semgrep
  // ruleset (https://github.com/semgrep/semgrep-rules).
  [/\b(?:csrf-token|no[-_]csrf|csrf-protection)\b/i,                              "CWE-352"],
  [/\bexpress[-_]cookie[-_]session[-_]no[-_](?:secure|httponly|domain|path)\b/i,  "CWE-614"],
  [/\b(?:detected-(?:private-key|bcrypt-hash|secret|password|api[-_]?key|token)|hard[-_]?coded[-_]?(?:secret|credential|key))\b/i, "CWE-798"],
  [/\b(?:use-of-eval|eval[-_]detected|new-function|dynamic-code-execution)\b/i,   "CWE-95"],
  [/\b(?:code-string-concat|sql-string-(?:concat|format)|raw-sql|tainted-sql)\b/i,"CWE-89"],
  [/\b(?:tainted-(?:command|cmd)|os[-_]command|shell[-_]injection)\b/i,           "CWE-78"],
  [/\b(?:tainted-html|express-template-injection|jinja2-autoescape-off)\b/i,      "CWE-79"],
  [/\b(?:node[-_]deserialization|insecure[-_]?deserialization|pickle[-_]?load)\b/i, "CWE-502"],
  [/\b(?:weak[-_]?(?:cipher|hash|crypto|random)|md5[-_]used|sha1[-_]used|insecure[-_]random)\b/i, "CWE-327"],
  [/\b(?:tabnabbing|opener[-_]?relationship|external[-_]?link[-_]?retains)\b/i,   "CWE-1022"],
  [/\b(?:observable[-_]?timing[-_]?discrepancy|timing[-_]?attack)\b/i,            "CWE-208"],
];

/**
 * Backtick-wrapped file path extractor.
 * Matches:  `config.js`,  `profile.js:ProfileHandler.<lambda>2`
 *           `src/auth.py:147`,  `lib/foo.ts`
 * Captures the file portion only (before any colon).
 */
const BACKTICK_FILE_RE = /`([A-Za-z0-9_./\\-]+\.[a-z]{1,6})(?::[^`]+)?`/i;

/**
 * Match `<package>@<version>`. Package name follows ecosystem-friendly chars
 * (letters, digits, slash, hyphen, dot, underscore, plus). Version stops at
 * the first non-version character — colons / spaces / parens / brackets are
 * NOT part of versions in npm/pip/go/etc. (Debian epoch syntax `1:1.5.3` is
 * rare in scanner titles; not worth supporting.)
 *
 * Conservative: only captures the FIRST occurrence in the title.
 */
const PKG_VERSION_RE =
  /([A-Za-z0-9][A-Za-z0-9._+\-/]*[A-Za-z0-9])@([A-Za-z0-9][A-Za-z0-9._+\-~]*)/;

export interface TitleExtract {
  reference_identifiers: ReferenceIdentifier[];
  library_name: string | undefined;
  current_version: string | undefined;
  file_name: string | undefined;
}

export function extractFromTitle(rawTitle: string | undefined | null): TitleExtract {
  if (!rawTitle || typeof rawTitle !== "string") {
    return { reference_identifiers: [], library_name: undefined, current_version: undefined, file_name: undefined };
  }
  const title = rawTitle;

  const refs: ReferenceIdentifier[] = [];
  const seen = new Set<string>();

  function add(type: string, rawId: string) {
    const id = rawId.toUpperCase();
    const key = `${type}:${id}`;
    if (!seen.has(key)) {
      seen.add(key);
      refs.push({ type, id });
    }
  }
  function addAll(re: RegExp, type: string) {
    for (const m of title.matchAll(re)) add(type, m[0]);
  }
  addAll(CVE_RE, "cve");
  addAll(GHSA_RE, "ghsa");
  addAll(CWE_RE, "cwe");
  addAll(SNYK_RE, "snyk");

  // Inferred CWEs from English vulnerability descriptions
  for (const [re, cwe] of CWE_KEYWORDS) {
    if (re.test(title)) add("cwe", cwe);
  }

  let library_name: string | undefined;
  let current_version: string | undefined;
  const pkgMatch = title.match(PKG_VERSION_RE);
  if (pkgMatch) {
    library_name = pkgMatch[1];
    current_version = pkgMatch[2];
  }

  let file_name: string | undefined;
  const fileMatch = title.match(BACKTICK_FILE_RE);
  if (fileMatch) {
    file_name = fileMatch[1];
  }

  return { reference_identifiers: refs, library_name, current_version, file_name };
}
