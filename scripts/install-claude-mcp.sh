#!/usr/bin/env bash
# install-claude-mcp.sh — Wire lynis-mcp into Claude Desktop
# Usage: ./install-claude-mcp.sh [path-to-claude-config]

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
WRAPPER="$BASE_DIR/lynis-mcp-wrapper.sh"
CONFIG="${1:-}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[mcp]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }

# Find Claude Desktop config if not passed
if [[ -z "$CONFIG" ]]; then
    for p in \
        "$HOME/.config/Claude/claude_desktop_config.json" \
        "$HOME/Library/Application Support/Claude/claude_desktop_config.json"; do
        [[ -f "$p" ]] && CONFIG="$p" && break
    done
fi

if [[ -z "$CONFIG" ]]; then
    warn "Claude Desktop config not found."
    warn "Install Claude Desktop first, then re-run this script."
    exit 1
fi

# Ensure wrapper script exists and is executable
cat > "$WRAPPER" << 'WRAPPER_EOF'
#!/bin/bash
# lynis-mcp-wrapper.sh — invoked by Claude Desktop as MCP stdio server
exec sg docker "docker exec -i lt-lynis /venv/bin/python3 /app/mcp_server.py"
WRAPPER_EOF
chmod +x "$WRAPPER"

# Inject mcpServers into Claude Desktop config using Python
python3 << PYEOF
import json, sys

config_path = "$CONFIG"
wrapper_path = "$WRAPPER"

with open(config_path) as f:
    config = json.load(f)

config.setdefault("mcpServers", {})
config["mcpServers"]["lynis-mcp"] = {
    "command": "/bin/bash",
    "args": [wrapper_path],
    "env": {}
}

with open(config_path, "w") as f:
    json.dump(config, f, indent=2)

print(f"  Wrote lynis-mcp to {config_path}")
PYEOF

info "Claude Desktop MCP config updated."
info "Restart Claude Desktop to activate the lynis-mcp tools."
echo ""
echo "  Available tools after restart:"
echo "    run_audit         — run Lynis now, ingest results"
echo "    get_last_report   — view all findings from last run"
echo "    get_system_health — NTP, disk, memory, load, audit score"
