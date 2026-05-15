#!/usr/bin/env bash
# Start harness-mcp HTTP + cloudflared tunnel in one go.
# Solves the chicken-and-egg problem: cloudflared assigns a URL on startup,
# but harness-mcp needs that URL in HARNESS_MCP_ALLOWED_HOSTS BEFORE it boots
# (otherwise it returns "Invalid Host" for any incoming request).
#
# Order:
#   1) Start cloudflared, wait for the public URL
#   2) Start harness-mcp with HARNESS_MCP_ALLOWED_HOSTS set to that URL
#   3) Print everything you need: public URL, env vars, kill PIDs on Ctrl-C
#
# Usage:   ./scripts/serve-harness-tunnel.sh
# Outputs: prints the cloudflare URL once both processes are healthy.

set -euo pipefail

PORT="${PORT:-8081}"
# harness-mcp's Streamable HTTP transport requires Node 20+ (globalThis.crypto).
# Auto-pick the highest available nvm node >= 20, fall back to v18 with a warning.
if [[ -z "${NODE_BIN:-}" ]]; then
  shopt -s nullglob
  best_cand=""
  for V in v22 v21 v20; do
    matches=( "$HOME/.nvm/versions/node/${V}".* )
    if [[ ${#matches[@]} -gt 0 ]]; then
      best_cand="${matches[-1]}"
      break
    fi
  done
  shopt -u nullglob
  if [[ -n "$best_cand" && -x "$best_cand/bin/node" ]]; then
    NODE_BIN="$best_cand/bin/node"
  else
    NODE_BIN="$HOME/.nvm/versions/node/v18.20.8/bin/node"
    echo "  ⚠ No Node 20+ found via nvm — falling back to Node 18. Install Node 20 with: nvm install 20"
  fi
fi
NODE_VERSION="$("$NODE_BIN" --version 2>/dev/null || echo "MISSING")"
echo "  Using node: $NODE_BIN ($NODE_VERSION)"
HARNESS_MCP_ROOT="${HARNESS_MCP_ROOT:-$HOME/Desktop/mcp-server}"
LOG_DIR="${LOG_DIR:-/tmp}"
HARNESS_LOG="$LOG_DIR/harness-mcp.log"
CF_LOG="$LOG_DIR/harness-mcp-cloudflared.log"

cleanup() {
  echo ""
  echo "Shutting down..."
  [[ -n "${HARNESS_PID:-}" ]] && kill "$HARNESS_PID" 2>/dev/null || true
  [[ -n "${CF_PID:-}" ]] && kill "$CF_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "Stopped."
}
trap cleanup EXIT INT TERM

# 1) Start cloudflared first — we need its URL before booting harness-mcp
echo "Starting cloudflared tunnel on port $PORT..."
cloudflared tunnel --url "http://localhost:$PORT" > "$CF_LOG" 2>&1 &
CF_PID=$!

PUBLIC_URL=""
for i in {1..30}; do
  PUBLIC_URL="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$CF_LOG" 2>/dev/null | head -1 || true)"
  if [[ -n "$PUBLIC_URL" ]]; then break; fi
  sleep 1
done

if [[ -z "$PUBLIC_URL" ]]; then
  echo "cloudflared didn't publish a public URL. Tail of $CF_LOG:"
  tail -30 "$CF_LOG"
  exit 1
fi
echo "  ✓ cloudflared URL: $PUBLIC_URL  (logs: $CF_LOG)"

# 2) Start harness-mcp with the URL allowlisted.
# IMPORTANT: cd into HARNESS_MCP_ROOT before launching so dotenv finds the .env
# file (it loads from process.cwd()).
echo "Starting harness-mcp on port $PORT with allowlist..."
(
  cd "$HARNESS_MCP_ROOT"
  PORT="$PORT" \
  HARNESS_MCP_ALLOWED_HOSTS="$PUBLIC_URL" \
  PATH="$(dirname "$NODE_BIN"):$PATH" \
    "$NODE_BIN" "$HARNESS_MCP_ROOT/build/index.js" http
) > "$HARNESS_LOG" 2>&1 &
HARNESS_PID=$!

# 3) Wait for harness-mcp /health to come up
for i in {1..15}; do
  if curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.3
done
if ! curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then
  echo "harness-mcp failed to start. Tail of $HARNESS_LOG:"
  tail -20 "$HARNESS_LOG"
  exit 1
fi
echo "  ✓ harness-mcp ready  (logs: $HARNESS_LOG)"

# 4) Smoke-test the public URL end-to-end
sleep 1
HEALTH_BODY="$(curl -sf "$PUBLIC_URL/health" 2>/dev/null || echo "")"
if [[ -z "$HEALTH_BODY" ]]; then
  echo "  ⚠ Public health check didn't return JSON yet; cloudflared may need ~10s"
  echo "      to propagate. Try the curl manually in a few seconds."
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  harness-mcp public URL:  $PUBLIC_URL/mcp"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  Health check:  curl $PUBLIC_URL/health"
echo "  Local URL:     http://localhost:$PORT/mcp"
echo "  Allowed hosts: $PUBLIC_URL"
echo ""
echo "  Press Ctrl-C to stop both processes."
echo ""

# 5) Wait until either process dies (or user hits Ctrl-C)
wait -n "$HARNESS_PID" "$CF_PID"
