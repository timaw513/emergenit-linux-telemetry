#!/bin/bash
# lynis-mcp-wrapper — invoked by Claude Desktop as MCP stdio server
# Uses sg to ensure docker group is active
exec sg docker "docker exec -i lt-lynis /venv/bin/python3 /app/mcp_server.py"
