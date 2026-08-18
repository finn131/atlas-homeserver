"""
Pydantic models for security events, detections, incidents, and alerts.
"""
import json
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class SecurityEvent(BaseModel):
    timestamp: datetime
    hostname: str
    source: str
    event_type: str
    severity: Severity = Severity.INFO
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    username: Optional[str] = None
    process: Optional[str] = None
    message: Optional[str] = None
    raw_log: Optional[str] = None
    correlation_id: Optional[str] = None
    metadata: dict = Field(default_factory=dict)

    def to_db_tuple(self) -> tuple:
        """Convert to tuple for SQLite INSERT."""
        return (
            self.timestamp.isoformat(),
            self.hostname,
            self.source,
            self.event_type,
            self.severity.value,
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.username,
            self.process,
            self.message,
            self.raw_log,
            self.correlation_id,
            json.dumps(self.metadata) if self.metadata else None,
        )


class Detection(BaseModel):
    timestamp: datetime
    rule_name: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    hostname: str
    src_ip: Optional[str] = None
    explanation: str
    related_event_ids: list = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)


class Incident(BaseModel):
    title: str
    summary: Optional[str] = None
    severity: Severity
    status: IncidentStatus = IncidentStatus.OPEN
    src_ip: Optional[str] = None
    started_at: datetime
    detection_ids: list = Field(default_factory=list)
    event_ids: list = Field(default_factory=list)
    evidence_summary: dict = Field(default_factory=dict)
    explanation: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)


class Alert(BaseModel):
    incident_id: Optional[int] = None
    detection_id: Optional[int] = None
    status: AlertStatus = AlertStatus.NEW
    severity: Severity
    title: str
    description: Optional[str] = None
    src_ip: Optional[str] = None
