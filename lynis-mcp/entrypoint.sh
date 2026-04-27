#!/bin/bash
# entrypoint.sh — start cron + MCP server

set -e

mkdir -p "${REPORTS_DIR}"

# Install cron job for scheduled audits
echo "${CRON_SCHEDULE} /venv/bin/python3 /app/mcp_server.py --run-once >> /var/log/lynis-cron.log 2>&1" | crontab -

# Start cron in background
service cron start

echo "[lynis-mcp] Cron schedule: ${CRON_SCHEDULE}"
echo "[lynis-mcp] Reports dir:   ${REPORTS_DIR}"

if [ "${MCP_MODE}" = "1" ]; then
    echo "[lynis-mcp] Starting MCP server (stdio)..."
    exec /venv/bin/python3 /app/mcp_server.py
else
    echo "[lynis-mcp] Running in cron-only mode. Set MCP_MODE=1 for Claude Desktop."
    # Keep container alive
    tail -f /dev/null
fi
