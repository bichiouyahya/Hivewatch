from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import BaseModel, Field


class Event(BaseModel):
    """Raw event published by a honeypot service."""

    sensor_id: str
    service: str
    event_type: str
    source_ip: IPv4Address | IPv6Address
    session_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EnrichedEvent(Event):
    """Event after the pipeline added geo data and MITRE techniques."""

    id: int
    country: str | None = None
    city: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)


class EventOut(BaseModel):
    id: int
    sensor_id: str
    service: str
    event_type: str
    source_ip: str
    session_id: str | None
    payload: dict[str, Any]
    mitre_techniques: list[str]
    country: str | None
    city: str | None
    created_at: datetime


class EventsPage(BaseModel):
    total: int
    items: list[EventOut]


class SessionOut(BaseModel):
    id: str
    service: str
    source_ip: str
    country: str | None
    started_at: datetime
    ended_at: datetime | None
    command_count: int
    has_recording: bool = False


class SessionsPage(BaseModel):
    total: int
    items: list[SessionOut]


class IocOut(BaseModel):
    ioc_type: str
    value: str
    source_service: str
    hit_count: int
    confidence: int
    first_seen: datetime
    last_seen: datetime


class IocsPage(BaseModel):
    total: int
    items: list[IocOut]


class StatsOverview(BaseModel):
    total_events: int
    unique_attackers: int
    active_sessions: int
    commands_captured: int
    events_last_minute: int
    events_by_service: dict[str, int]


class CountryCount(BaseModel):
    country: str
    count: int


class CommandStat(BaseModel):
    command: str
    executions: int
    unique_attackers: int
    first_seen: datetime
    last_seen: datetime
    mitre_techniques: list[str]


class AttackerStat(BaseModel):
    source_ip: str
    country: str | None
    attacks: int
    services: list[str]
    technique_count: int
    score: int


class TechniqueHeat(BaseModel):
    technique: str
    name: str
    detections: int
    attackers: int
    last_seen: datetime | None


class TacticHeat(BaseModel):
    tactic: str
    techniques: list[TechniqueHeat]


class AttackOrigin(BaseModel):
    source_ip: str
    country: str | None
    city: str | None
    latitude: float
    longitude: float
    events: int


class AlertOut(BaseModel):
    severity: str
    technique: str
    title: str
    service: str
    source_ip: str
    created_at: datetime
