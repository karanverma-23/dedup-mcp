# Vulnerability Dedup Worker Agent

The submission piece for the Exemption Workflow Automation umbrella. Wraps the
`dedup-mcp` server's tools as a Harness Worker Agent that:

1. Fetches STO security issues for a given pipeline (via `harness-mcp`)
2. Normalizes them to the `RefinedIssue` schema (via `dedup-mcp`)
3. Clusters them into duplicate groups with confidence tiers (via `dedup-mcp`)
4. Emits a Slack-friendly Markdown summary + machine-readable JSON for the
   downstream exemption-workflow agent to consume

## Files

- `agent.yaml` — the agent definition. Paste this into the Harness Worker
  Agent UI when creating the agent.

## Required MCP Connectors

The agent expects two MCP connectors mounted via `inputs.mcpConnectors`:

| Connector | Identifier (default) | What it does |
|---|---|---|
| Harness MCP | `harness_mcp_server` | Fetches issues via `harness_list(security_issue, pipeline_ids=...)` |
| **Dedup MCP** | `dedup_mcp` | Our custom server — `normalize_sto_issues`, `find_duplicate_groups` |

The dedup-mcp connector points at the ngrok URL produced by
`./scripts/serve-tunnel.sh` (transport: HTTP, auth: None).

## Required Inputs

| Input | Required | Default | Notes |
|---|---|---|---|
| `pipelineId` | ✅ | — | The pipeline whose issues you want to dedup |
| `projectId` | ✅ | `STO` | STO project id |
| `orgId` | optional | `default` | STO org id |
| `llmConnector` | ✅ | `connector_Anthropic_6a93` | LLM that orchestrates |
| `modelName` | optional | `global.anthropic.claude-sonnet-4-6` | Sonnet 4.6 is a good fit for this orchestration |
| `mcpConnectors` | optional | `[harness_mcp_server, dedup_mcp]` | Both must be available |
| `pageSize` | optional | `200` | API page size |
| `groupThreshold` | optional | `LOW` | `LOW` for SCA noise reduction; `HIGH` for cross-scanner-exact only |
| `defaultProductName` | optional | `multi_scanner` | Fallback when STO API doesn't return per-issue scanner |

## Output

Two parts:

1. **Markdown summary** — pipeline metric table + top 10 duplicate groups +
   review candidates + one-line headline. Slack-friendly.
2. **Fenced JSON block** — full `find_duplicate_groups` output. Downstream
   agents (the exemption-workflow agent) parse this to drive bulk actions.

## How to register in Harness QA

1. Make sure `dedup-mcp` is reachable via ngrok (run `./scripts/serve-tunnel.sh`)
2. In QA: **Project STO → Connectors → New Connector → MCP Server**
   - Name: `dedup-mcp`, Identifier: `dedup_mcp`
   - URL: the ngrok HTTPS URL + `/mcp`
   - Auth: None
   - Transport: Streamable HTTP
3. In QA: **Project STO → AI Agents → New Worker Agent → paste `agent.yaml`**
4. Save. Run from a pipeline step or trigger directly with a `pipelineId` input.
