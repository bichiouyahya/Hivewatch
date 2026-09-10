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


class SessionsPage(BaseModel):
    total: int
    items: list[SessionOut]


class StatsOverview(BaseModel):
    total_events: int
    unique_attackers: int
    active_sessions: int
    commands_captured: int
    events_by_service: dict[str, int]


class CountryCount(BaseModel):
    country: str
    count: int
