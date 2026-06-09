import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "xrefs0_history.db")

class HistoricalTracker:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else ".", exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                duration_seconds INTEGER,
                modules_run TEXT,
                subdomain_count INTEGER,
                live_hosts INTEGER,
                open_ports INTEGER,
                emails_found INTEGER,
                takeover_vulns INTEGER,
                status TEXT DEFAULT 'completed',
                data_json TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                module_name TEXT,
                status TEXT,
                duration_ms INTEGER,
                results_summary TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)
        """)
        conn.commit()
        conn.close()

    def save_scan(self, domain, duration, modules_run, data):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO scans (domain, timestamp, duration_seconds, modules_run, subdomain_count, live_hosts, open_ports, emails_found, takeover_vulns, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            domain,
            datetime.now().isoformat(),
            duration,
            ",".join(modules_run),
            len(data.get("subdomains", [])),
            sum(1 for h in data.get("http", {}).values() if h.get("alive")),
            len(data.get("port_scan", {}).get("results", [])),
            len(data.get("emails", [])),
            len(data.get("takeover", [])),
            json.dumps(data, default=str),
        ))
        scan_id = c.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def save_module_result(self, scan_id, module_name, status, duration_ms, summary=""):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO modules (scan_id, module_name, status, duration_ms, results_summary)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, module_name, status, duration_ms, summary))
        conn.commit()
        conn.close()

    def get_history(self, domain=None, limit=20):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        if domain:
            c.execute("SELECT * FROM scans WHERE domain = ? ORDER BY timestamp DESC LIMIT ?", (domain, limit))
        else:
            c.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        return rows

    def get_scan_by_id(self, scan_id):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = c.fetchone()
        if scan:
            c.execute("SELECT * FROM modules WHERE scan_id = ?", (scan_id,))
            modules = c.fetchall()
            scan = {"scan": scan, "modules": modules}
        conn.close()
        return scan

    def resume_data(self, domain):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT data_json FROM scans WHERE domain = ? ORDER BY timestamp DESC LIMIT 1", (domain,))
        row = c.fetchone()
        conn.close()
        if row and row[0]:
            try:
                return json.loads(row[0])
            except Exception:
                pass
        return None
