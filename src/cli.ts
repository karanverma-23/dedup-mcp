#!/usr/bin/env node
/**
 * dedup-mcp — MCP server exposing same-type vulnerability deduplication
 * for Harness STO findings.
 *
 * Tools:
 *   - normalize_sto_issues   — convert raw STO API JSON to RefinedIssue shape
 *   - find_duplicate_groups  — cluster RefinedIssue records into duplicate groups
 *   - compare_pair           — single-pair tier check (debug helper)
 *
 * Transport:
 *   - stdio (default)        — for Cursor / Claude Desktop / local AI clients
 *   - http  --port <n>       — for remote/shared (Worker Agent + ngrok)
 *
 * Env vars:
 *   PORT — HTTP port if `http` mode is selected (default: 8080)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { findDuplicateGroups } from "./tools/find-duplicate-groups.js";
import { normalizeStoIssues } from "./tools/normalize-sto-issues.js";
import { matchPair } from "./lib/tier-match.js";

const server = new McpServer({
  name: "dedup-mcp",
  version: "0.1.0",
});

// ── shared input shape: a permissive RefinedIssue ──────────────────
const RefinedIssueSchema = z
  .object({
    internal_id: z.string().optional(),
    id: z.string().optional(),
    account_id: z.string().optional(),
    scan_id: z.string().optional(),
    product_id: z.string().optional(),
    product_name: z.string().optional(),
    issue_type: z.enum(["SAST","SCA","DAST","IAC","SECRET","MISCONFIG","CONTAINER"]).optional(),
    reference_identifiers: z
      .array(z.object({ type: z.string(), id: z.string() }))
      .optional(),
    severity: z.number().optional(),
    severity_code: z.string().optional(),
    title: z.string().optional(),
    issue_description: z.string().optional(),
    library_name: z.string().optional(),
    current_version: z.string().optional(),
    file_name: z.string().optional(),
    line_number: z.number().optional(),
    start_line: z.number().optional(),
    end_line: z.number().optional(),
    image_layer_id: z.string().optional(),
    image_registry: z.string().optional(),
    image_tag: z.string().optional(),
  })
  .passthrough();

// ──────────────────────────────────────────────────────────────────
// Tools
// ──────────────────────────────────────────────────────────────────

server.tool(
  "normalize_sto_issues",
  "Convert raw STO Core API issue payloads (the camelCase shape returned by `harness_list(security_issue, ...)`) into the snake_case `RefinedIssue` shape that `find_duplicate_groups` expects. Tolerant of multiple wrapping shapes: a flat array, `{data:[...]}`, `{issues:[...]}`, `{content:[...]}`, etc. Always call this BEFORE `find_duplicate_groups` when the data came from harness-mcp.",
  {
    issues: z.unknown().describe("Raw response from harness_list(security_issue, ...) — array or wrapper object"),
    default_product_name: z.string().optional()
      .describe("Optional fallback scanner name if the API doesn't include productName"),
  },
  async ({ issues, default_product_name }) => {
    const result = normalizeStoIssues({ issues, default_product_name });
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

server.tool(
  "find_duplicate_groups",
  "Cluster STO RefinedIssue records into same-type duplicate groups. Returns groups with confidence tier (HIGH / MEDIUM / LOW), matched signals as evidence, and a deterministically-picked primary per group. Group threshold defaults to HIGH; pairs at lower tiers are surfaced as review_candidates instead.",
  {
    issues: z.array(RefinedIssueSchema).describe("Flat list of RefinedIssue records"),
    group_threshold: z.enum(["HIGH","MEDIUM","LOW"]).optional()
      .describe("Lowest tier to auto-group (default HIGH)"),
  },
  async ({ issues, group_threshold }) => {
    const result = findDuplicateGroups({
      issues: issues as any,
      group_threshold,
    });
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

server.tool(
  "compare_pair",
  "Check whether two RefinedIssue records are duplicates. Returns the highest tier they match at (HIGH / MEDIUM / LOW) plus the matched signals, or null if they don't match. Useful for ad-hoc investigation.",
  {
    issue_a: RefinedIssueSchema,
    issue_b: RefinedIssueSchema,
  },
  async ({ issue_a, issue_b }) => {
    const result = matchPair(issue_a as any, issue_b as any);
    return {
      content: [{
        type: "text",
        text: JSON.stringify(result ?? { tier: null, rationale: "Not duplicates." }, null, 2),
      }],
    };
  },
);

// ──────────────────────────────────────────────────────────────────
// Transport selection
// ──────────────────────────────────────────────────────────────────

const mode = process.argv[2] === "http" ? "http" : "stdio";

if (mode === "stdio") {
  const transport = new StdioServerTransport();
  await server.connect(transport);
} else {
  // Lazy-load the HTTP transport — its dependency (@hono/node-server) needs
  // Node 18+ at IMPORT time. Keeping it out of the stdio code path lets the
  // server work on older Node versions when launched as a subprocess.
  const { StreamableHTTPServerTransport } = await import(
    "@modelcontextprotocol/sdk/server/streamableHttp.js"
  );
  const { createServer } = await import("node:http");
  const { randomUUID } = await import("node:crypto");
  const port = Number(process.env.PORT ?? 8080);
  const httpServer = createServer(async (req, res) => {
    if (req.url !== "/mcp") {
      res.writeHead(404).end("dedup-mcp: POST /mcp");
      return;
    }
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "application/json" })
         .end(JSON.stringify({ name: "dedup-mcp", status: "ok" }));
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405).end("Method not allowed — POST /mcp");
      return;
    }
    try {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });
      await server.connect(transport);
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
      await transport.handleRequest(req, res, body);
    } catch (err) {
      res.writeHead(500, { "content-type": "application/json" })
         .end(JSON.stringify({ error: String(err) }));
    }
  });
  httpServer.listen(port, () => {
    process.stderr.write(
      `dedup-mcp HTTP listening on port ${port}\n` +
      `  Health:  GET  http://localhost:${port}/mcp\n` +
      `  RPC:     POST http://localhost:${port}/mcp\n`,
    );
  });
}
