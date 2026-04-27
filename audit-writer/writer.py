#!/usr/bin/env python3
"""
audit-writer/writer.py — EmergenIT Linux Telemetry Stack
Watches REPORTS_DIR for new Lynis JSON reports → parses → SQLite.
Run with --once for on-demand: docker exec lt-audit-writer python writer.py --once
"""

import json, logging, os, re, signal, sqlite3, sys, time
from datetime import datetime, timezone
from pathlib import Path
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/lynis-reports"))
DB_PATH     = Path(os.environ.get("DB_PATH", "/data/audit.db"))
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "300"))

SEVERITY_MAP = {
    "warning":    {"default": "HIGH",   "AUTH": "CRITICAL", "SSH": "HIGH",   "FIRE": "HIGH",   "KRNL": "MEDIUM", "NETW": "MEDIUM"},
    "suggestion": {"default": "LOW",    "AUTH": "MEDIUM",   "SSH": "MEDIUM", "FIRE": "MEDIUM", "KRNL": "LOW",    "NETW": "LOW"},
}

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [audit-writer] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger(__name__)

def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_schema(conn):
    conn.executescript((Path(__file__).parent / "schema.sql").read_text())
    conn.commit()
    log.info("Schema initialised at %s", DB_PATH)

def already_ingested(conn, report_file):
    return conn.execute("SELECT id FROM audit_runs WHERE report_file=?", (report_file,)).fetchone() is not None

def infer_severity(test_id, finding_type):
    prefix = re.match(r"^([A-Z]+)", test_id or "")
    cat = prefix.group(1) if prefix else ""
    m = SEVERITY_MAP.get(finding_type, {})
    return m.get(cat, m.get("default", "INFO"))

def infer_category(test_id):
    prefix = re.match(r"^([A-Z]+)", test_id or "")
    return prefix.group(1) if prefix else "MISC"

def ingest_report(conn, path):
    if already_ingested(conn, path.name):
        log.debug("Already ingested: %s", path.name)
        return
    log.info("Ingesting: %s", path)
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        log.error("Failed to read %s: %s", path, e)
        return

    host = path.parent.name if path.parent != REPORTS_DIR else "thinkcentre-m720s"
    ts = re.search(r"(\d{8}[_T]\d{6}|\d{10,13})", path.name)
    if ts:
        raw = ts.group(1).replace("_","T")
        try:
            run_at = datetime.strptime(raw, "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            run_at = datetime.now(timezone.utc).isoformat()
    else:
        run_at = datetime.now(timezone.utc).isoformat()

    hi    = data.get("hardening_index") or data.get("score")
    lver  = data.get("lynis_version") or data.get("version")
    warns = data.get("warnings", [])
    suggs = data.get("suggestions", [])

    prior = conn.execute("SELECT id,hardening_index FROM audit_runs WHERE host=? ORDER BY run_at DESC LIMIT 1", (host,)).fetchone()
    prior_id    = prior["id"] if prior else None
    index_delta = (hi - prior["hardening_index"]) if (prior and hi is not None and prior["hardening_index"] is not None) else None

    cur = conn.execute(
        "INSERT INTO audit_runs (run_at,host,report_file,lynis_version,hardening_index,warnings_count,suggestions_count,prior_run_id,index_delta) VALUES (?,?,?,?,?,?,?,?,?)",
        (run_at, host, path.name, lver, hi, len(warns), len(suggs), prior_id, index_delta))
    run_id = cur.lastrowid

    rows = []
    for w in warns:
        tid = w.get("test_id","UNKNOWN")
        rows.append((run_id, tid, "warning",    infer_severity(tid,"warning"),    w.get("description",w.get("text","")),       w.get("solution",""),                infer_category(tid)))
    for s in suggs:
        tid = s.get("test_id","UNKNOWN")
        rows.append((run_id, tid, "suggestion", infer_severity(tid,"suggestion"), s.get("description",s.get("text",s.get("details",""))), s.get("solution",s.get("suggestion","")), infer_category(tid)))

    conn.executemany("INSERT INTO findings (run_id,test_id,finding_type,severity,description,solution,category) VALUES (?,?,?,?,?,?,?)", rows)
    conn.commit()
    log.info("Ingested %s → run_id=%d score=%s warns=%d suggs=%d delta=%s", path.name, run_id, hi, len(warns), len(suggs), f"{index_delta:+d}" if index_delta is not None else "n/a")

def scan_all(conn):
    found = 0
    for path in sorted(REPORTS_DIR.rglob("*.json")):
        if not already_ingested(conn, path.name):
            ingest_report(conn, path)
            found += 1
    log.info("Scan complete — %d new report(s)", found) if found else log.debug("Scan complete — nothing new")

class ReportHandler(FileSystemEventHandler):
    def __init__(self, conn): self.conn = conn
    def on_created(self, event):
        if not event.is_directory and Path(event.src_path).suffix == ".json":
            time.sleep(1); ingest_report(self.conn, Path(event.src_path))
    def on_moved(self, event):
        if not event.is_directory and Path(event.dest_path).suffix == ".json":
            time.sleep(1); ingest_report(self.conn, Path(event.dest_path))

def main():
    once_mode = "--once" in sys.argv
    log.info("audit-writer starting — reports_dir=%s db=%s", REPORTS_DIR, DB_PATH)
    conn = get_db()
    init_schema(conn)
    scan_all(conn)
    if once_mode:
        log.info("--once mode: done"); conn.close(); return

    observer = Observer()
    observer.schedule(ReportHandler(conn), str(REPORTS_DIR), recursive=True)
    observer.start()
    log.info("Watching %s (poll fallback every %ds)", REPORTS_DIR, POLL_INTERVAL)

    def _shutdown(sig, frame):
        observer.stop(); conn.close(); sys.exit(0)
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    try:
        while True:
            time.sleep(POLL_INTERVAL)
            scan_all(conn)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    conn.close()

if __name__ == "__main__":
    main()
