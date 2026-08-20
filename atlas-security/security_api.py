"""
Atlas Security Observatory — REST API Router

Thin query layer over security.db SQLite database.
All endpoints are read-only except alert/incident status updates.

Security:
- All SQL queries are parameterized (no string interpolation)
- limit/offset bounded (max 500/1000)
- No detection logic (reads existing data only)
- CORS disabled (same-origin via NGINX proxy only)
"""
import json
import os
import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, Field

router = APIRouter()

DB_PATH = os.environ.get("SECURITY_DB_PATH", "/opt/atlas/security.db")

VALID_ALERT_STATUSES = {"new", "acknowledged", "investigating", "resolved", "dismissed"}
VALID_INCIDENT_STATUSES = {"open", "investigating", "resolved", "dismissed"}


def _db():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _parse_json_field(val):
    if val is None:
        return None
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return val


def _dict_from_row(row):
    d = dict(row)
    for key in ("related_event_ids", "evidence", "detection_ids", "event_ids", "evidence_summary"):
        if key in d and d[key] is not None:
            d[key] = _parse_json_field(d[key])
    return d


def _service_active(unit: str) -> bool:
    try:
        r = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True, text=True, timeout=3,
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False


def _db_size_bytes() -> int:
    try:
        return os.path.getsize(DB_PATH)
    except OSError:
        return 0


# --- Response models ---

class SecurityStatus(BaseModel):
    status: str = "ok"
    events_today: int = 0
    total_events: int = 0
    active_alerts: int = 0
    high_severity_alerts: int = 0
    medium_severity_alerts: int = 0
    low_severity_alerts: int = 0
    open_incidents: int = 0
    last_event_at: Optional[str] = None
    total_detections: int = 0
    collector_healthy: bool = False
    detector_healthy: bool = False
    database_size_bytes: int = 0


class AlertUpdate(BaseModel):
    status: str = Field(..., min_length=1, max_length=30)


class IncidentUpdate(BaseModel):
    status: str = Field(..., min_length=1, max_length=30)


class PaginatedResponse(BaseModel):
    total: int
    limit: int
    offset: int


# --- Endpoints ---

@router.get("/status", response_model=SecurityStatus)
async def security_status():
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

    conn = _db()
    try:
        events_today = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (today_start,)
        ).fetchone()[0]

        total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        last_event = conn.execute(
            "SELECT timestamp FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        last_event_at = last_event[0] if last_event else None

        active_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status NOT IN ('resolved', 'dismissed')"
        ).fetchone()[0]

        severity_counts = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts WHERE status NOT IN ('resolved', 'dismissed') GROUP BY severity"
        ):
            severity_counts[row[0]] = row[1]

        open_incidents = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved', 'dismissed')"
        ).fetchone()[0]

        total_detections = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
    finally:
        conn.close()

    collector_ok = _service_active("atlas-collector.service")
    detector_ok = collector_ok  # detector is embedded in collector (Phase 4)

    return SecurityStatus(
        status="ok",
        events_today=events_today,
        total_events=total_events,
        active_alerts=active_alerts,
        high_severity_alerts=severity_counts.get("high", 0),
        medium_severity_alerts=severity_counts.get("medium", 0),
        low_severity_alerts=severity_counts.get("low", 0),
        open_incidents=open_incidents,
        last_event_at=last_event_at,
        total_detections=total_detections,
        collector_healthy=collector_ok,
        detector_healthy=detector_ok,
        database_size_bytes=_db_size_bytes(),
    )


@router.get("/events")
async def list_events(
    source: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    since: Optional[str] = Query(None),
    until: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    conditions = []
    params = []

    if source:
        conditions.append("source = ?")
        params.append(source)
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if src_ip:
        conditions.append("src_ip = ?")
        params.append(src_ip)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if since:
        conditions.append("timestamp >= ?")
        params.append(since)
    if until:
        conditions.append("timestamp <= ?")
        params.append(until)
    if search:
        conditions.append("message LIKE ?")
        params.append(f"%{search}%")

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    conn = _db()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM events {where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    finally:
        conn.close()

    return {
        "events": [_dict_from_row(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/detections")
async def list_detections(
    rule_name: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    conditions = []
    params = []

    if rule_name:
        conditions.append("rule_name = ?")
        params.append(rule_name)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if src_ip:
        conditions.append("src_ip = ?")
        params.append(src_ip)

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    conn = _db()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM detections {where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT * FROM detections {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    finally:
        conn.close()

    return {
        "detections": [_dict_from_row(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/detections/{detection_id}")
async def get_detection(detection_id: int):
    conn = _db()
    try:
        row = conn.execute(
            "SELECT * FROM detections WHERE id = ?", (detection_id,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Detection not found")

    return _dict_from_row(row)


@router.get("/incidents")
async def list_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    conditions = []
    params = []

    if status:
        conditions.append("status = ?")
        params.append(status)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if src_ip:
        conditions.append("src_ip = ?")
        params.append(src_ip)

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    conn = _db()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM incidents {where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT * FROM incidents {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    finally:
        conn.close()

    return {
        "incidents": [_dict_from_row(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: int):
    conn = _db()
    try:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")

        incident = _dict_from_row(row)

        detection_ids = incident.get("detection_ids") or []
        if isinstance(detection_ids, str):
            try:
                detection_ids = json.loads(detection_ids)
            except (json.JSONDecodeError, TypeError):
                detection_ids = []

        event_ids = incident.get("event_ids") or []
        if isinstance(event_ids, str):
            try:
                event_ids = json.loads(event_ids)
            except (json.JSONDecodeError, TypeError):
                event_ids = []

        incident["detections"] = []
        for did in detection_ids:
            drow = conn.execute(
                "SELECT * FROM detections WHERE id = ?", (did,)
            ).fetchone()
            if drow:
                incident["detections"].append(_dict_from_row(drow))

        incident["events"] = []
        for eid in event_ids:
            erow = conn.execute(
                "SELECT * FROM events WHERE id = ?", (eid,)
            ).fetchone()
            if erow:
                incident["events"].append(_dict_from_row(erow))
    finally:
        conn.close()

    return incident


@router.put("/incidents/{incident_id}")
async def update_incident(incident_id: int, update: IncidentUpdate):
    if update.status not in VALID_INCIDENT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {VALID_INCIDENT_STATUSES}",
        )

    conn = _db()
    try:
        existing = conn.execute(
            "SELECT id, status FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Incident not found")

        now = datetime.now(timezone.utc).isoformat()
        resolved_at = now if update.status in ("resolved", "dismissed") else None

        if resolved_at:
            conn.execute(
                "UPDATE incidents SET status = ?, last_updated_at = ?, resolved_at = ? WHERE id = ?",
                (update.status, now, resolved_at, incident_id),
            )
        else:
            conn.execute(
                "UPDATE incidents SET status = ?, last_updated_at = ? WHERE id = ?",
                (update.status, now, incident_id),
            )
        conn.commit()
    finally:
        conn.close()

    return {"ok": True, "id": incident_id, "status": update.status}


@router.get("/alerts")
async def list_alerts(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    conditions = []
    params = []

    if status:
        conditions.append("a.status = ?")
        params.append(status)
    if severity:
        conditions.append("a.severity = ?")
        params.append(severity)
    if src_ip:
        conditions.append("a.src_ip = ?")
        params.append(src_ip)

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    conn = _db()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM alerts a {where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"""SELECT a.*, d.rule_name as detection_rule_name,
                       d.confidence as detection_confidence,
                       d.evidence as detection_evidence
                FROM alerts a
                LEFT JOIN detections d ON a.detection_id = d.id
                {where}
                ORDER BY a.id DESC LIMIT ? OFFSET ?""",
            params + [limit, offset],
        ).fetchall()
    finally:
        conn.close()

    alerts = []
    for r in rows:
        alert = _dict_from_row(r)
        detection_info = None
        if alert.get("detection_rule_name"):
            detection_info = {
                "rule_name": alert.pop("detection_rule_name", None),
                "confidence": alert.pop("detection_confidence", None),
                "evidence": _parse_json_field(alert.pop("detection_evidence", None)),
            }
        alert["detection"] = detection_info
        alerts.append(alert)

    return {
        "alerts": alerts,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: int):
    conn = _db()
    try:
        row = conn.execute(
            """SELECT a.*, d.rule_name as detection_rule_name,
                      d.confidence as detection_confidence,
                      d.evidence as detection_evidence,
                      d.explanation as detection_explanation,
                      d.related_event_ids as detection_related_event_ids
               FROM alerts a
               LEFT JOIN detections d ON a.detection_id = d.id
               WHERE a.id = ?""",
            (alert_id,),
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")

        alert = _dict_from_row(row)
        detection_info = None
        if alert.get("detection_rule_name"):
            detection_info = {
                "rule_name": alert.pop("detection_rule_name", None),
                "confidence": alert.pop("detection_confidence", None),
                "evidence": _parse_json_field(alert.pop("detection_evidence", None)),
                "explanation": alert.pop("detection_explanation", None),
                "related_event_ids": _parse_json_field(alert.pop("detection_related_event_ids", None)),
            }
        alert["detection"] = detection_info
    finally:
        conn.close()

    return alert


@router.put("/alerts/{alert_id}")
async def update_alert(alert_id: int, update: AlertUpdate):
    if update.status not in VALID_ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {VALID_ALERT_STATUSES}",
        )

    conn = _db()
    try:
        existing = conn.execute(
            "SELECT id, status FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Alert not found")

        now = datetime.now(timezone.utc).isoformat()
        acknowledged_at = now if update.status == "acknowledged" else None
        resolved_at = now if update.status in ("resolved", "dismissed") else None

        if acknowledged_at:
            conn.execute(
                "UPDATE alerts SET status = ?, updated_at = ?, acknowledged_at = ? WHERE id = ?",
                (update.status, now, acknowledged_at, alert_id),
            )
        elif resolved_at:
            conn.execute(
                "UPDATE alerts SET status = ?, updated_at = ?, resolved_at = ? WHERE id = ?",
                (update.status, now, resolved_at, alert_id),
            )
        else:
            conn.execute(
                "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
                (update.status, now, alert_id),
            )
        conn.commit()
    finally:
        conn.close()

    return {"ok": True, "id": alert_id, "status": update.status}


@router.get("/stats")
async def security_stats(
    period: str = Query("24h"),
):
    period_map = {
        "1h": 3600,
        "6h": 6 * 3600,
        "24h": 24 * 3600,
        "7d": 7 * 86400,
        "30d": 30 * 86400,
    }
    seconds = period_map.get(period)
    if seconds is None:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid period. Must be one of: {list(period_map.keys())}",
        )

    since = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()

    conn = _db()
    try:
        events_by_source = {}
        for row in conn.execute(
            "SELECT source, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY source ORDER BY cnt DESC",
            (since,),
        ):
            events_by_source[row[0]] = row[1]

        events_by_type = {}
        for row in conn.execute(
            "SELECT event_type, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY event_type ORDER BY cnt DESC",
            (since,),
        ):
            events_by_type[row[0]] = row[1]

        events_by_severity = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY severity ORDER BY cnt DESC",
            (since,),
        ):
            events_by_severity[row[0]] = row[1]

        detections_by_rule = {}
        for row in conn.execute(
            "SELECT rule_name, COUNT(*) as cnt FROM detections WHERE timestamp >= ? GROUP BY rule_name ORDER BY cnt DESC",
            (since,),
        ):
            detections_by_rule[row[0]] = row[1]

        hourly_timeline = []
        for row in conn.execute(
            """SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour,
                      COUNT(*) as cnt
               FROM events WHERE timestamp >= ?
               GROUP BY hour ORDER BY hour""",
            (since,),
        ):
            hourly_timeline.append({"hour": row[0], "count": row[1]})

        top_src_ips = []
        for row in conn.execute(
            """SELECT src_ip, COUNT(*) as cnt FROM events
               WHERE timestamp >= ? AND src_ip IS NOT NULL AND src_ip != ''
               GROUP BY src_ip ORDER BY cnt DESC LIMIT 10""",
            (since,),
        ):
            top_src_ips.append({"src_ip": row[0], "count": row[1]})

        total_events = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since,)
        ).fetchone()[0]

        total_detections = conn.execute(
            "SELECT COUNT(*) FROM detections WHERE timestamp >= ?", (since,)
        ).fetchone()[0]
    finally:
        conn.close()

    return {
        "period": period,
        "since": since,
        "total_events": total_events,
        "total_detections": total_detections,
        "events_by_source": events_by_source,
        "events_by_type": events_by_type,
        "events_by_severity": events_by_severity,
        "detections_by_rule": detections_by_rule,
        "hourly_timeline": hourly_timeline,
        "top_src_ips": top_src_ips,
    }


@router.get("/security-summary")
async def security_summary():
    """Lightweight summary for WebSocket broadcast. No pagination, minimal data."""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

    conn = _db()
    try:
        active_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status NOT IN ('resolved', 'dismissed')"
        ).fetchone()[0]

        severity_counts = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) FROM alerts WHERE status NOT IN ('resolved', 'dismissed') GROUP BY severity"
        ):
            severity_counts[row[0]] = row[1]

        events_today = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (today_start,)
        ).fetchone()[0]

        last_event = conn.execute(
            "SELECT timestamp FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        last_event_at = last_event[0] if last_event else None

        recent_detections = []
        for row in conn.execute(
            "SELECT timestamp, rule_name, severity, src_ip FROM detections ORDER BY id DESC LIMIT 5"
        ):
            recent_detections.append({
                "time": row[0],
                "rule": row[1],
                "severity": row[2],
                "src_ip": row[3],
            })
    finally:
        conn.close()

    status = "ok"
    if severity_counts.get("high", 0) > 0:
        status = "critical"
    elif severity_counts.get("medium", 0) > 0 or active_alerts > 2:
        status = "warning"

    return {
        "status": status,
        "active_alerts": active_alerts,
        "high_severity": severity_counts.get("high", 0),
        "medium_severity": severity_counts.get("medium", 0),
        "low_severity": severity_counts.get("low", 0),
        "events_today": events_today,
        "last_event_at": last_event_at,
        "recent_detections": recent_detections,
    }


# --- Prometheus metrics endpoint ---

@router.get("/metrics")
async def prometheus_metrics():
    """Prometheus text exposition format for security observatory data."""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    h24_ago = (now - timedelta(hours=24)).isoformat()

    conn = _db()
    try:
        events_today = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (today_start,)
        ).fetchone()[0]

        total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_detections = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]

        active_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status NOT IN ('resolved', 'dismissed')"
        ).fetchone()[0]

        sev = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) FROM alerts WHERE status NOT IN ('resolved','dismissed') GROUP BY severity"
        ):
            sev[row[0]] = row[1]

        open_incidents = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved', 'dismissed')"
        ).fetchone()[0]

        events_24h = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (h24_ago,)
        ).fetchone()[0]
        detections_24h = conn.execute(
            "SELECT COUNT(*) FROM detections WHERE timestamp >= ?", (h24_ago,)
        ).fetchone()[0]

        events_by_source = {}
        for row in conn.execute(
            "SELECT source, COUNT(*) FROM events WHERE timestamp >= ? GROUP BY source",
            (h24_ago,),
        ):
            events_by_source[row[0]] = row[1]

        events_by_type = {}
        for row in conn.execute(
            "SELECT event_type, COUNT(*) FROM events WHERE timestamp >= ? GROUP BY event_type",
            (h24_ago,),
        ):
            events_by_type[row[0]] = row[1]

        detections_by_rule = {}
        for row in conn.execute(
            "SELECT rule_name, COUNT(*) FROM detections WHERE timestamp >= ? GROUP BY rule_name",
            (h24_ago,),
        ):
            detections_by_rule[row[0]] = row[1]

        top_src_ips = {}
        for row in conn.execute(
            """SELECT src_ip, COUNT(*) FROM events
               WHERE timestamp >= ? AND src_ip IS NOT NULL AND src_ip != ''
               GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 10""",
            (h24_ago,),
        ):
            top_src_ips[row[0]] = row[1]
    finally:
        conn.close()

    collector_ok = _service_active("atlas-collector.service")
    detector_ok = collector_ok

    lines = []
    a = lines.append

    a("# HELP atlas_security_events_total Total events in database")
    a("# TYPE atlas_security_events_total gauge")
    a(f"atlas_security_events_total {total_events}")

    a("# HELP atlas_security_events_today Events received today")
    a("# TYPE atlas_security_events_today gauge")
    a(f"atlas_security_events_today {events_today}")

    a("# HELP atlas_security_events_24h Events in last 24 hours")
    a("# TYPE atlas_security_events_24h gauge")
    a(f"atlas_security_events_24h {events_24h}")

    a("# HELP atlas_security_detections_total Total detections in database")
    a("# TYPE atlas_security_detections_total gauge")
    a(f"atlas_security_detections_total {total_detections}")

    a("# HELP atlas_security_detections_24h Detections in last 24 hours")
    a("# TYPE atlas_security_detections_24h gauge")
    a(f"atlas_security_detections_24h {detections_24h}")

    a("# HELP atlas_security_active_alerts Active unresolved alerts")
    a("# TYPE atlas_security_active_alerts gauge")
    a(f"atlas_security_active_alerts {active_alerts}")

    a("# HELP atlas_security_alerts_by_severity Active alerts by severity")
    a("# TYPE atlas_security_alerts_by_severity gauge")
    for severity in ("high", "medium", "low"):
        a(f'atlas_security_alerts_by_severity{{severity="{severity}"}} {sev.get(severity, 0)}')

    a("# HELP atlas_security_open_incidents Open unresolved incidents")
    a("# TYPE atlas_security_open_incidents gauge")
    a(f"atlas_security_open_incidents {open_incidents}")

    a("# HELP atlas_security_collector_healthy Collector service status (1=healthy)")
    a("# TYPE atlas_security_collector_healthy gauge")
    a(f"atlas_security_collector_healthy {1 if collector_ok else 0}")

    a("# HELP atlas_security_detector_healthy Detector service status (1=healthy)")
    a("# TYPE atlas_security_detector_healthy gauge")
    a(f"atlas_security_detector_healthy {1 if detector_ok else 0}")

    a("# HELP atlas_security_events_by_source Events by source in last 24h")
    a("# TYPE atlas_security_events_by_source gauge")
    for source, count in events_by_source.items():
        a(f'atlas_security_events_by_source{{source="{source}"}} {count}')

    a("# HELP atlas_security_events_by_type Events by type in last 24h")
    a("# TYPE atlas_security_events_by_type gauge")
    for etype, count in events_by_type.items():
        a(f'atlas_security_events_by_type{{event_type="{etype}"}} {count}')

    a("# HELP atlas_security_detections_by_rule Detections by rule in last 24h")
    a("# TYPE atlas_security_detections_by_rule gauge")
    for rule, count in detections_by_rule.items():
        a(f'atlas_security_detections_by_rule{{rule="{rule}"}} {count}')

    a("# HELP atlas_security_top_src_ips Top source IPs in last 24h")
    a("# TYPE atlas_security_top_src_ips gauge")
    for ip, count in top_src_ips.items():
        a(f'atlas_security_top_src_ips{{src_ip="{ip}"}} {count}')

    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4; charset=utf-8")
