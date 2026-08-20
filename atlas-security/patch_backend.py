import json
import urllib.request
import urllib.error
import base64
import time

# Read backend.py from local workspace
with open(r"C:\Users\Lenovo\workspace\home-server\atlas-security\backend_original.py", "r") as f:
    content = f.read()

# Find the right places to insert
# 1. Add SECURITY_DB constant after DB_PATH
content = content.replace(
    'DB_PATH = "/opt/atlas/status.db"',
    'DB_PATH = "/opt/atlas/status.db"\nSECURITY_DB = "/opt/atlas/security.db"'
)

# 2. Add _security_cache after CURRENT
content = content.replace(
    'CURRENT = {"ts": 0, "services": {}}',
    'CURRENT = {"ts": 0, "services": {}}\n\n_security_cache = {"data": None, "ts": 0}'
)

# 3. Add get_security_summary function before monitor_loop
security_func = '''

def get_security_summary():
    now = time.time()
    if _security_cache["data"] and (now - _security_cache["ts"]) < 5:
        return _security_cache["data"]
    try:
        conn = sqlite3.connect(SECURITY_DB, timeout=2)
        conn.row_factory = sqlite3.Row
        today_start = int(now) - (int(now) % 86400)
        row = conn.execute("SELECT COUNT(*) as cnt FROM events WHERE timestamp >= ?", (today_start,)).fetchone()
        events_today = row["cnt"] if row else 0
        alert_rows = conn.execute("SELECT severity, status FROM alerts WHERE status != 'resolved'").fetchall()
        active_alerts = len(alert_rows)
        high_severity = sum(1 for a in alert_rows if a["severity"] == "high")
        medium_severity = sum(1 for a in alert_rows if a["severity"] == "medium")
        low_severity = sum(1 for a in alert_rows if a["severity"] == "low")
        if high_severity > 0:
            status = "critical"
        elif medium_severity > 0 or active_alerts > 3:
            status = "warning"
        else:
            status = "ok"
        det_rows = conn.execute("SELECT timestamp, rule_name, severity, src_ip FROM detections ORDER BY timestamp DESC LIMIT 5").fetchall()
        recent_detections = [
            {"time": time.strftime("%H:%M", time.localtime(d["timestamp"])), "rule": d["rule_name"], "severity": d["severity"], "src_ip": d["src_ip"] or "-"}
            for d in det_rows
        ]
        collector_ok = False
        try:
            r = subprocess.run(["systemctl", "is-active", "atlas-collector"], capture_output=True, text=True, timeout=2)
            collector_ok = r.stdout.strip() == "active"
        except Exception:
            pass
        data = {"status": status, "active_alerts": active_alerts, "high_severity": high_severity, "medium_severity": medium_severity, "low_severity": low_severity, "events_today": events_today, "recent_detections": recent_detections, "collector_healthy": collector_ok}
        conn.close()
        _security_cache["data"] = data
        _security_cache["ts"] = now
        return data
    except Exception:
        return {"status": "unknown", "active_alerts": 0, "high_severity": 0, "medium_severity": 0, "low_severity": 0, "events_today": 0, "recent_detections": [], "collector_healthy": False}

'''

content = content.replace(
    '\nasync def monitor_loop():',
    security_func + '\nasync def monitor_loop():'
)

# 4. Add security to collect() return dict
content = content.replace(
    '        "services": services,\n    }',
    '        "services": services,\n        "security": get_security_summary(),\n    }'
)

# Write the patched file
with open(r"C:\Users\Lenovo\workspace\home-server\atlas-security\backend_patched.py", "w") as f:
    f.write(content)

print("Patched backend.py written successfully")
