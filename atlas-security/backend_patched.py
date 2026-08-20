#!/usr/bin/env python3
import asyncio
import json
import sqlite3
import subprocess
import time
from collections import deque
from contextlib import asynccontextmanager

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

DB_PATH = "/opt/atlas/status.db"
SECURITY_DB = "/opt/atlas/security.db"
CHECK_INTERVAL = 30
RETENTION_DAYS = 30


def db_connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            ts INTEGER NOT NULL,
            service TEXT NOT NULL,
            ok INTEGER NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events ON events(service, ts)")
    conn.commit()
    return conn


def db_prune(conn):
    cutoff = int(time.time()) - RETENTION_DAYS * 86400
    conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
    conn.commit()


def record_event(conn, service, ok):
    conn.execute(
        "INSERT INTO events (ts, service, ok) VALUES (?, ?, ?)",
        (int(time.time()), service, 1 if ok else 0),
    )
    conn.commit()


SERVICES = {
    "nginx": "nginx",
    "grafana": "grafana-server",
    "prometheus": "prometheus",
    "filebrowser": "filebrowser",
    "samba": "smbd",
    "ssh": "ssh",
    "tailscale": "tailscaled",
    "fail2ban": "fail2ban",
}

SERVICE_NAMES = {
    "nginx": "Nginx",
    "grafana": "Grafana",
    "prometheus": "Prometheus",
    "filebrowser": "File Browser",
    "samba": "Samba",
    "ssh": "SSH",
    "tailscale": "Tailscale",
    "fail2ban": "Fail2Ban",
}

BOOT_TIME = psutil.boot_time()
prev_net = psutil.net_io_counters()
prev_net_ts = time.time()

CURRENT = {"ts": 0, "services": {}}

_security_cache = {"data": None, "ts": 0}


def service_status():
    status = {}
    for key, unit in SERVICES.items():
        try:
            r = subprocess.run(
                ["systemctl", "is-active", unit],
                capture_output=True, text=True, timeout=2,
            )
            status[key] = "online" if r.stdout.strip() == "active" else "offline"
        except Exception:
            status[key] = "offline"
    return status



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


async def monitor_loop():
    conn = db_connect()
    while True:
        try:
            status = await asyncio.to_thread(service_status)
            CURRENT["services"] = status
            CURRENT["ts"] = int(time.time())
            for key, val in status.items():
                record_event(conn, key, val == "online")
            db_prune(conn)
        except Exception:
            pass
        await asyncio.sleep(CHECK_INTERVAL)


@asynccontextmanager
async def lifespan(app):
    global CURRENT
    conn = db_connect()
    db_prune(conn)
    status = await asyncio.to_thread(service_status)
    CURRENT["services"] = status
    CURRENT["ts"] = int(time.time())
    for key, val in status.items():
        record_event(conn, key, val == "online")
    conn.close()
    task = asyncio.create_task(monitor_loop())
    yield
    task.cancel()


app = FastAPI(title="Atlas Dashboard", version="1.0", lifespan=lifespan)

# --- Security Observatory API ---
try:
    from security_api import router as _security_router
    app.include_router(_security_router, prefix="/api/security", tags=["security"])
except ImportError:
    import logging
    logging.getLogger("atlas-backend").warning("security_api not found, security endpoints disabled")


def fmt_rate(bps):
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if bps < 1024:
            return f"{bps:.1f} {unit}"
        bps /= 1024
    return f"{bps:.1f} {unit}"


def collect():
    global prev_net, prev_net_ts

    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    nas = psutil.disk_usage("/srv/storage")

    net = psutil.net_io_counters()
    now = time.time()
    dt = max(now - prev_net_ts, 1e-6)
    rx_bps = (net.bytes_recv - prev_net.bytes_recv) / dt
    tx_bps = (net.bytes_sent - prev_net.bytes_sent) / dt
    prev_net, prev_net_ts = net, now

    uptime = int(now - BOOT_TIME)
    days, rem = divmod(uptime, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)

    services = CURRENT["services"] if CURRENT["ts"] else service_status()

    return {
        "ts": int(now),
        "cpu": round(cpu, 1),
        "cpu_cores": psutil.cpu_count(logical=True),
        "ram_percent": mem.percent,
        "ram_used_gb": round(mem.used / 1024**3, 1),
        "ram_total_gb": round(mem.total / 1024**3, 1),
        "disk_percent": disk.percent,
        "disk_used_gb": round(disk.used / 1024**3, 1),
        "disk_total_gb": round(disk.total / 1024**3, 1),
        "nas_percent": nas.percent,
        "nas_used_gb": round(nas.used / 1024**3, 1),
        "nas_total_gb": round(nas.total / 1024**3, 1),
        "net_rx": fmt_rate(rx_bps),
        "net_tx": fmt_rate(tx_bps),
        "net_rx_bps": int(rx_bps),
        "net_tx_bps": int(tx_bps),
        "uptime": {"days": days, "hours": hours, "minutes": minutes, "seconds": seconds},
        "hostname": psutil.users()[0].name if psutil.users() else "debian",
        "services": services,
        "security": get_security_summary(),
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/status")
async def api_status():
    return {
        "ts": CURRENT["ts"],
        "interval": CHECK_INTERVAL,
        "services": CURRENT["services"],
    }


@app.get("/api/status/history")
async def api_status_history(range: str = "24h"):
    if range == "7d":
        seconds = 7 * 86400
    else:
        seconds = 24 * 3600

    cutoff = int(time.time()) - seconds
    conn = db_connect()
    rows = conn.execute(
        "SELECT service, ts, ok FROM events WHERE ts >= ? ORDER BY ts ASC",
        (cutoff,),
    ).fetchall()
    conn.close()

    per_service = {}
    for key in SERVICES:
        per_service[key] = {"events": [], "samples": 0, "ok_count": 0}

    for service, ts, ok in rows:
        if service not in per_service:
            continue
        per_service[service]["events"].append([ts, ok])
        per_service[service]["samples"] += 1
        per_service[service]["ok_count"] += ok

    services = {}
    for key in SERVICES:
        info = per_service[key]
        total = info["samples"]
        ok = info["ok_count"]
        services[key] = {
            "name": SERVICE_NAMES[key],
            "uptime_pct": round((ok / total * 100) if total else 100.0, 2),
            "samples": total,
            "events": info["events"],
        }

    return {"range": range, "cutoff": cutoff, "services": services}


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = collect()
            await websocket.send_text(json.dumps(data))
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
