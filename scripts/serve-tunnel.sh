#!/usr/bin/env bash
# Start dedup-mcp HTTP + ngrok tunnel in one go.
# Logs each process to its own file in /tmp; kills both cleanly on Ctrl-C.
#
# Usage:   ./scripts/serve-tunnel.sh
# Outputs: prints the public ngrok URL once it's ready.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-8080}"
NODE_BIN="${NODE_BIN:-$HOME/.nvm/versions/node/v18.20.8/bin/node}"
LOG_DIR="${LOG_DIR:-/tmp}"
MCP_LOG="$LOG_DIR/dedup-mcp.log"
NGROK_LOG="$LOG_DIR/dedup-mcp-ngrok.log"

cleanup() {
  echo ""
  echo "Shutting down..."
  [[ -n "${MCP_PID:-}" ]] && kill "$MCP_PID" 2>/dev/null || true
  [[ -n "${NGROK_PID:-}" ]] && kill "$NGROK_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "Stopped."
}
trap cleanup EXIT INT TERM

# 1) Start dedup-mcp HTTP server
echo "Starting dedup-mcp on port $PORT..."
PORT="$PORT" "$NODE_BIN" "$ROOT/dist/cli.js" http > "$MCP_LOG" 2>&1 &
MCP_PID=$!

# 2) Wait for the server to be ready
for i in {1..15}; do
  if curl -sf "http://localhost:$PORT/mcp" >/dev/null 2>&1; then
    break
  fi
  sleep 0.3
done
if ! curl -sf "http://localhost:$PORT/mcp" >/dev/null 2>&1; then
  echo "dedup-mcp failed to start. Tail of $MCP_LOG:"
  tail -20 "$MCP_LOG"
  exit 1
fi
echo "  ✓ dedup-mcp ready  (logs: $MCP_LOG)"

# 3) Start ngrok
echo "Starting ngrok tunnel..."
ngrok http --log=stdout "$PORT" > "$NGROK_LOG" 2>&1 &
NGROK_PID=$!

# 4) Pull the public URL from ngrok's local API (port 4040)
PUBLIC_URL=""
for i in {1..30}; do
  PUBLIC_URL="$(curl -sf http://localhost:4040/api/tunnels 2>/dev/null \
    | grep -oE 'https://[a-z0-9-]+\.ngrok-free\.app' \
    | head -1 || true)"
  if [[ -n "$PUBLIC_URL" ]]; then break; fi
  sleep 0.5
done

if [[ -z "$PUBLIC_URL" ]]; then
  echo "ngrok didn't surface a public URL. Tail of $NGROK_LOG:"
  tail -30 "$NGROK_LOG"
  exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  dedup-mcp public URL:  $PUBLIC_URL/mcp"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  Health check:  curl $PUBLIC_URL/mcp"
echo "  ngrok web UI:  http://localhost:4040"
echo ""
echo "  Press Ctrl-C to stop both processes."
echo ""

# 5) Wait until either process dies (or user hits Ctrl-C)
wait -n "$MCP_PID" "$NGROK_PID"
