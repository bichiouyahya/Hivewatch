"""REST API and WebSocket endpoints used by the dashboard."""

import json
from typing import Any

import asyncpg
from fastapi import APIRouter, Query, Request, WebSocket, WebSocketDisconnect

from app.schemas import (
    CountryCount,
    EventOut,
    EventsPage,
    SessionOut,
    SessionsPage,
    StatsOverview,
)

router = APIRouter()


@router.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "hive-backend"}


def _row_to_event(row: asyncpg.Record) -> EventOut:
    return EventOut(
        id=row["id"],
        sensor_id=row["sensor_id"],
        service=row["service"],
        event_type=row["event_type"],
        source_ip=row["source_ip"],
        session_id=str(row["session_id"]) if row["session_id"] else None,
        payload=json.loads(row["payload"]),
        mitre_techniques=row["mitre_techniques"] or [],
        country=row["country"],
        city=row["city"],
        created_at=row["created_at"],
    )


@router.get("/api/events", response_model=EventsPage)
async def list_events(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ip: str | None = None,
) -> EventsPage:
    pool: asyncpg.Pool = request.app.state.db_pool

    where_clause = ""
    where_params: list[Any] = []
    if ip:
        where_params.append(ip)
        where_clause = "WHERE e.source_ip = $1"

    rows = await pool.fetch(
        f"""
        SELECT e.id, e.sensor_id, e.service, e.event_type,
               host(e.source_ip) AS source_ip, e.session_id,
               e.payload::text AS payload, e.mitre_techniques, e.created_at,
               a.country, a.city
        FROM events e
        JOIN attackers a ON a.id = e.attacker_id
        {where_clause}
        ORDER BY e.id DESC
        LIMIT ${len(where_params) + 1} OFFSET ${len(where_params) + 2}
        """,
        *where_params,
        limit,
        offset,
    )
    total = await pool.fetchval(f"SELECT count(*) FROM events e {where_clause}", *where_params)
    return EventsPage(total=total, items=[_row_to_event(row) for row in rows])


@router.get("/api/sessions", response_model=SessionsPage)
async def list_sessions(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> SessionsPage:
    pool: asyncpg.Pool = request.app.state.db_pool

    rows = await pool.fetch(
        """
        SELECT s.id, s.service, host(a.ip_address) AS source_ip, a.country,
               s.started_at, s.ended_at,
               (SELECT count(*) FROM events e
                WHERE e.session_id = s.id AND e.event_type = 'command') AS command_count
        FROM sessions s
        JOIN attackers a ON a.id = s.attacker_id
        ORDER BY s.started_at DESC
        LIMIT $1 OFFSET $2
        """,
        limit,
        offset,
    )
    total = await pool.fetchval("SELECT count(*) FROM sessions")
    items = [
        SessionOut(
            id=str(row["id"]),
            service=row["service"],
            source_ip=row["source_ip"],
            country=row["country"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            command_count=row["command_count"],
        )
        for row in rows
    ]
    return SessionsPage(total=total, items=items)


@router.get("/api/stats/overview", response_model=StatsOverview)
async def stats_overview(request: Request) -> StatsOverview:
    pool: asyncpg.Pool = request.app.state.db_pool

    total_events = await pool.fetchval("SELECT count(*) FROM events")
    unique_attackers = await pool.fetchval("SELECT count(*) FROM attackers")
    active_sessions = await pool.fetchval("SELECT count(*) FROM sessions WHERE ended_at IS NULL")
    commands_captured = await pool.fetchval(
        "SELECT count(*) FROM events WHERE event_type = 'command'"
    )
    service_rows = await pool.fetch("SELECT service, count(*) AS n FROM events GROUP BY service")

    return StatsOverview(
        total_events=total_events,
        unique_attackers=unique_attackers,
        active_sessions=active_sessions,
        commands_captured=commands_captured,
        events_by_service={row["service"]: row["n"] for row in service_rows},
    )


@router.get("/api/stats/countries", response_model=list[CountryCount])
async def stats_countries(
    request: Request, limit: int = Query(10, ge=1, le=50)
) -> list[CountryCount]:
    pool: asyncpg.Pool = request.app.state.db_pool

    rows = await pool.fetch(
        """
        SELECT a.country, count(*) AS n
        FROM events e
        JOIN attackers a ON a.id = e.attacker_id
        WHERE a.country IS NOT NULL
        GROUP BY a.country
        ORDER BY n DESC
        LIMIT $1
        """,
        limit,
    )
    return [CountryCount(country=row["country"], count=row["n"]) for row in rows]


@router.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    await websocket.accept()
    enriched_bus = websocket.app.state.enriched_bus
    async with enriched_bus.subscribe() as stream:
        try:
            async for event in stream:
                await websocket.send_json(event.model_dump(mode="json"))
        except (WebSocketDisconnect, RuntimeError):
            pass
