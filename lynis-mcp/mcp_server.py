#!/usr/bin/env python3
"""
lynis-mcp/mcp_server.py — EmergenIT Linux Telemetry
MCP tools: run_audit, get_last_report, get_system_health
Cron mode: python mcp_server.py --run-once
"""

import json, logging, os, subprocess, sys, shutil
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [lynis-mcp] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger(__name__)

REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/lynis-reports"))
HOSTNAME    = os.environ.get("HOST_HOSTNAME", "thinkcentre-m720s")

# ── Lynis audit ───────────────────────────────────────────────────────────

def parse_lynis_dat(dat_path: Path, ts: str) -> dict:
    if not dat_path.exists():
        return {"warnings": [], "suggestions": [], "hardening_index": None}
    data = dat_path.read_text(errors="replace")
    report = {"lynis_version": None, "hardening_index": None,
               "warnings": [], "suggestions": [], "timestamp": ts}
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if line.startswith("lynis_version="):
            report["lynis_version"] = line.split("=",1)[1].strip("|")
        elif line.startswith("hardening_index="):
            try: report["hardening_index"] = int(line.split("=",1)[1].strip("|"))
            except ValueError: pass
        elif line.startswith("warning[]="):
            val = line.split("=",1)[1].strip("|"); parts = val.split("|")
            report["warnings"].append({"test_id": parts[0] if parts else "UNKNOWN",
                "description": parts[1] if len(parts)>1 else val,
                "solution":    parts[2] if len(parts)>2 else ""})
        elif line.startswith("suggestion[]="):
            val = line.split("=",1)[1].strip("|"); parts = val.split("|")
            report["suggestions"].append({"test_id": parts[0] if parts else "UNKNOWN",
                "description": parts[1] if len(parts)>1 else val,
                "solution":    parts[2] if len(parts)>2 else ""})
    return report


def run_lynis() -> dict:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    report_path = REPORTS_DIR / HOSTNAME / f"{ts}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    dat = f"/tmp/lynis-report-{ts}.dat"
    log.info("Starting Lynis audit → %s", report_path)
    try:
        subprocess.run(["lynis","audit","system","--no-colors","--quiet",
            "--report-file", dat, "--logfile", f"/tmp/lynis-{ts}.log"],
            capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Lynis timed out after 300s"}
    except Exception as e:
        return {"success": False, "error": str(e)}
    report = parse_lynis_dat(Path(dat), ts)
    report["host"] = HOSTNAME
    report["report_file"] = report_path.name
    report_path.write_text(json.dumps(report, indent=2))
    log.info("Report written → %s (score: %s)", report_path, report.get("hardening_index"))
    return {"success": True, "report_file": str(report_path), "host": HOSTNAME,
            "hardening_index": report.get("hardening_index"),
            "lynis_version":   report.get("lynis_version"),
            "warnings_count":  len(report.get("warnings",[])),
            "suggestions_count": len(report.get("suggestions",[]))}

# ── Last report ───────────────────────────────────────────────────────────

def get_last_report() -> dict:
    reports = sorted(REPORTS_DIR.rglob("*.json"), key=lambda p: p.stat().st_mtime)
    if not reports:
        return {"success": False, "error": "No reports found. Run run_audit first."}
    try:
        data = json.loads(reports[-1].read_text())
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "report_file": reports[-1].name,
            "host": data.get("host", HOSTNAME),
            "hardening_index": data.get("hardening_index"),
            "lynis_version":   data.get("lynis_version"),
            "warnings":    data.get("warnings", []),
            "suggestions": data.get("suggestions", [])}


# ── System health snapshot ────────────────────────────────────────────────

def get_system_health() -> dict:
    health = {}

    # NTP
    try:
        r = subprocess.run(["timedatectl","show",
            "--property=NTPSynchronized,NTPService,ServerName"],
            capture_output=True, text=True, timeout=5)
        props = dict(l.split("=",1) for l in r.stdout.strip().splitlines() if "=" in l)
        synced = props.get("NTPSynchronized") == "yes"
        health["ntp"] = {
            "synchronized":   synced,
            "service_active": props.get("NTPService") == "active",
            "server":         props.get("ServerName", "unknown"),
            "status": "OK" if synced else "WARNING — not synchronized",
        }
    except Exception as e:
        health["ntp"] = {"error": str(e)}

    # Disk
    try:
        total, used, free = shutil.disk_usage("/")
        pct = round(used/total*100, 1)
        health["disk"] = {"total_gb": round(total/1e9,1), "used_gb": round(used/1e9,1),
            "free_gb": round(free/1e9,1), "used_pct": pct,
            "status": "OK" if pct < 85 else "WARNING — disk over 85%"}
    except Exception as e:
        health["disk"] = {"error": str(e)}

    # Memory
    try:
        mem = Path("/proc/meminfo").read_text()
        def _kb(k):
            for l in mem.splitlines():
                if l.startswith(k): return int(l.split()[1])
            return 0
        total_kb = _kb("MemTotal"); avail_kb = _kb("MemAvailable")
        pct = round((total_kb - avail_kb) / total_kb * 100, 1)
        health["memory"] = {"total_gb": round(total_kb/1e6,1),
            "available_gb": round(avail_kb/1e6,1), "used_pct": pct,
            "status": "OK" if pct < 85 else "WARNING — memory over 85%"}
    except Exception as e:
        health["memory"] = {"error": str(e)}

    # Load
    try:
        l1, l5, l15 = Path("/proc/loadavg").read_text().split()[:3]
        health["load"] = {"1m": float(l1), "5m": float(l5), "15m": float(l15),
            "status": "OK" if float(l1) < 8 else "WARNING — high load"}
    except Exception as e:
        health["load"] = {"error": str(e)}

    # Last audit
    reports = sorted(REPORTS_DIR.rglob("*.json"), key=lambda p: p.stat().st_mtime)
    if reports:
        try:
            last = json.loads(reports[-1].read_text())
            hi = last.get("hardening_index")
            health["last_audit"] = {"timestamp": last.get("timestamp"),
                "hardening_index": hi,
                "warnings":    len(last.get("warnings",[])),
                "suggestions": len(last.get("suggestions",[])),
                "status": "OK" if hi and hi>=80 else ("FAIR" if hi and hi>=60 else "POOR — harden this system")}
        except Exception as e:
            health["last_audit"] = {"error": str(e)}
    else:
        health["last_audit"] = {"status": "No audits run yet"}

    health["overall"] = "OK" if all(
        v.get("status","").startswith("OK")
        for v in health.values() if isinstance(v, dict) and "status" in v
    ) else "NEEDS ATTENTION"

    return {"success": True, "health": health}

# ── CLI (cron) mode ───────────────────────────────────────────────────────

if __name__ == "__main__" and "--run-once" in sys.argv:
    log.info("Cron mode: running Lynis audit now")
    result = run_lynis()
    log.info("Result: %s", json.dumps(result))
    sys.exit(0 if result.get("success") else 1)

# ── MCP server mode ───────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import Tool, TextContent
        import asyncio
    except ImportError:
        log.error("mcp package not found"); sys.exit(1)

    app = Server("lynis-mcp")

    @app.list_tools()
    async def list_tools():
        return [
            Tool(name="run_audit",
                description="Run a Lynis security audit on the host system. Returns hardening score, warnings, and suggestions. Report is auto-ingested into the telemetry database.",
                inputSchema={"type":"object","properties":{},"required":[]}),
            Tool(name="get_last_report",
                description="Get all findings from the most recent Lynis audit — hardening index, warnings and suggestions with test IDs and descriptions.",
                inputSchema={"type":"object","properties":{},"required":[]}),
            Tool(name="get_system_health",
                description="Get a current health snapshot of the ThinkCentre: NTP sync status, disk usage, memory, load average, and last audit score — with overall OK/NEEDS ATTENTION status.",
                inputSchema={"type":"object","properties":{},"required":[]}),
        ]

    @app.call_tool()
    async def call_tool(name: str, arguments: dict):
        if   name == "run_audit":        result = run_lynis()
        elif name == "get_last_report":  result = get_last_report()
        elif name == "get_system_health": result = get_system_health()
        else: result = {"error": f"Unknown tool: {name}"}
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    asyncio.run(main())
