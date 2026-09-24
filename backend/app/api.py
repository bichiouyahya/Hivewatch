"""REST API and WebSocket endpoints used by the dashboard."""

import json
import os
import secrets
import uuid
from typing import Any

import asyncpg
from fastapi import (
    APIRouter,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import PlainTextResponse

from app.intel import build_blocklist, build_stix_bundle
from app.mitre import TACTIC_ORDER, TECHNIQUE_CATALOG, TECHNIQUE_NAMES, severity_for
from app.schemas import (
    AlertOut,
    AttackerStat,
    AttackOrigin,
    CommandStat,
    CountryCount,
    EventOut,
    EventsPage,
    IocOut,
    IocsPage,
    SessionOut,
    SessionsPage,
    StatsOverview,
    TacticHeat,
    TechniqueHeat,
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
               s.started_at, s.ended_at, s.recording IS NOT NULL AS has_recording,
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
            has_recording=row["has_recording"],
        )
        for row in rows
    ]
    return SessionsPage(total=total, items=items)


@router.get("/api/sessions/{session_id}/replay", response_class=PlainTextResponse)
async def session_replay(request: Request, session_id: str) -> PlainTextResponse:
    """Raw asciicast v2 recording for a session."""
    pool: asyncpg.Pool = request.app.state.db_pool
    try:
        session_uuid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid session id") from None

    recording = await pool.fetchval(
        "SELECT recording FROM sessions WHERE id = $1", session_uuid
    )
    if recording is None:
        raise HTTPException(status_code=404, detail="no recording for this session")
    return PlainTextResponse(recording, media_type="application/x-asciicast")


@router.get("/api/iocs", response_model=IocsPage)
async def list_iocs(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    ioc_type: str | None = None,
) -> IocsPage:
    pool: asyncpg.Pool = request.app.state.db_pool

    where_clause = ""
    where_params: list[Any] = []
    if ioc_type:
        where_params.append(ioc_type)
        where_clause = "WHERE ioc_type = $1"

    rows = await pool.fetch(
        f"""
        SELECT ioc_type, value, source_service, hit_count, confidence,
               first_seen, last_seen
        FROM iocs
        {where_clause}
        ORDER BY confidence DESC, last_seen DESC
        LIMIT ${len(where_params) + 1} OFFSET ${len(where_params) + 2}
        """,
        *where_params,
        limit,
        offset,
    )
    total = await pool.fetchval(f"SELECT count(*) FROM iocs {where_clause}", *where_params)
    return IocsPage(total=total, items=[IocOut(**dict(row)) for row in rows])


async def _fetch_all_iocs(pool: asyncpg.Pool) -> list[dict[str, Any]]:
    rows = await pool.fetch(
        """
        SELECT ioc_type, value, source_service, hit_count, confidence,
               first_seen, last_seen
        FROM iocs
        ORDER BY confidence DESC, last_seen DESC
        """
    )
    return [dict(row) for row in rows]


@router.get("/api/iocs/export/stix")
async def export_stix(request: Request) -> Response:
    """STIX 2.1 bundle of all indicators."""
    pool: asyncpg.Pool = request.app.state.db_pool
    bundle = build_stix_bundle(await _fetch_all_iocs(pool))
    body = bundle if isinstance(bundle, str) else json.dumps(bundle)
    return Response(
        content=body,
        media_type="application/stix+json",
        headers={"Content-Disposition": 'attachment; filename="hive-iocs.stix.json"'},
    )


@router.get("/api/iocs/export/blocklist", response_class=PlainTextResponse)
async def export_blocklist(
    request: Request,
    format: str = Query("plain", pattern="^(plain|iptables|nginx|csv)$"),
) -> PlainTextResponse:
    pool: asyncpg.Pool = request.app.state.db_pool
    body = build_blocklist(await _fetch_all_iocs(pool), format)
    extension = "csv" if format == "csv" else "txt"
    return PlainTextResponse(
        body,
        media_type="text/csv" if format == "csv" else "text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="hive-blocklist.{extension}"'
        },
    )


@router.get("/api/stats/overview", response_model=StatsOverview)
async def stats_overview(request: Request) -> StatsOverview:
    pool: asyncpg.Pool = request.app.state.db_pool

    total_events = await pool.fetchval("SELECT count(*) FROM events")
    unique_attackers = await pool.fetchval("SELECT count(*) FROM attackers")
    active_sessions = await pool.fetchval("SELECT count(*) FROM sessions WHERE ended_at IS NULL")
    commands_captured = await pool.fetchval(
        "SELECT count(*) FROM events WHERE event_type = 'command'"
    )
    events_last_minute = await pool.fetchval(
        "SELECT count(*) FROM events WHERE created_at > now() - interval '1 minute'"
    )
    service_rows = await pool.fetch("SELECT service, count(*) AS n FROM events GROUP BY service")

    return StatsOverview(
        total_events=total_events,
        unique_attackers=unique_attackers,
        active_sessions=active_sessions,
        commands_captured=commands_captured,
        events_last_minute=events_last_minute,
        events_by_service={row["service"]: row["n"] for row in service_rows},
    )


@router.get("/api/stats/commands", response_model=list[CommandStat])
async def stats_commands(
    request: Request, limit: int = Query(10, ge=1, le=100)
) -> list[CommandStat]:
    pool: asyncpg.Pool = request.app.state.db_pool

    # techniques are the same for a given command, so read them off the
    # most recent matching event
    rows = await pool.fetch(
        """
        WITH grouped AS (
            SELECT payload->>'command' AS command,
                   count(*) AS executions,
                   count(DISTINCT attacker_id) AS unique_attackers,
                   min(created_at) AS first_seen,
                   max(created_at) AS last_seen,
                   max(id) AS sample_event_id
            FROM events
            WHERE event_type = 'command' AND payload ? 'command'
            GROUP BY 1
        )
        SELECT g.command, g.executions, g.unique_attackers, g.first_seen, g.last_seen,
               COALESCE(e.mitre_techniques, '{}') AS mitre_techniques
        FROM grouped g
        JOIN events e ON e.id = g.sample_event_id
        ORDER BY g.executions DESC, g.last_seen DESC
        LIMIT $1
        """,
        limit,
    )
    return [CommandStat(**dict(row)) for row in rows]


def _threat_score(attacks: int, technique_count: int) -> int:
    """Score 0-100. Technique variety counts more than volume, and
    volume is capped.
    """
    return min(100, technique_count * 12 + min(attacks, 200) // 5)


@router.get("/api/stats/attackers", response_model=list[AttackerStat])
async def stats_attackers(
    request: Request, limit: int = Query(10, ge=1, le=100)
) -> list[AttackerStat]:
    pool: asyncpg.Pool = request.app.state.db_pool

    rows = await pool.fetch(
        """
        SELECT host(a.ip_address) AS source_ip, a.country,
               count(e.id) AS attacks,
               array_agg(DISTINCT e.service) AS services,
               (SELECT count(DISTINCT t)
                  FROM events e2, unnest(e2.mitre_techniques) AS t
                 WHERE e2.attacker_id = a.id) AS technique_count
        FROM attackers a
        JOIN events e ON e.attacker_id = a.id
        GROUP BY a.id, a.ip_address, a.country
        ORDER BY attacks DESC
        LIMIT $1
        """,
        limit,
    )
    return [
        AttackerStat(
            source_ip=row["source_ip"],
            country=row["country"],
            attacks=row["attacks"],
            services=sorted(row["services"]),
            technique_count=row["technique_count"],
            score=_threat_score(row["attacks"], row["technique_count"]),
        )
        for row in rows
    ]


@router.get("/api/alerts", response_model=list[AlertOut])
async def list_alerts(
    request: Request, limit: int = Query(5, ge=1, le=50)
) -> list[AlertOut]:
    """Recent events that triggered a detection rule."""
    pool: asyncpg.Pool = request.app.state.db_pool

    rows = await pool.fetch(
        """
        SELECT host(e.source_ip) AS source_ip, e.service, e.mitre_techniques, e.created_at
        FROM events e
        WHERE array_length(e.mitre_techniques, 1) > 0
        ORDER BY e.created_at DESC
        LIMIT $1
        """,
        limit,
    )

    alerts = []
    for row in rows:
        techniques = list(row["mitre_techniques"])
        primary = techniques[0]
        alerts.append(
            AlertOut(
                severity=severity_for(techniques),
                technique=primary,
                title=TECHNIQUE_NAMES.get(primary, primary),
                service=row["service"],
                source_ip=row["source_ip"],
                created_at=row["created_at"],
            )
        )
    return alerts


@router.get("/api/mitre/heatmap", response_model=list[TacticHeat])
async def mitre_heatmap(request: Request) -> list[TacticHeat]:
    """Detection counts per technique, grouped by tactic. Techniques that
    never fired are included with a count of zero.
    """
    pool: asyncpg.Pool = request.app.state.db_pool

    rows = await pool.fetch(
        """
        SELECT t AS technique,
               count(*) AS detections,
               count(DISTINCT e.attacker_id) AS attackers,
               max(e.created_at) AS last_seen
        FROM events e, unnest(e.mitre_techniques) AS t
        GROUP BY t
        """
    )
    counts = {row["technique"]: row for row in rows}

    by_tactic: dict[str, list[TechniqueHeat]] = {tactic: [] for tactic in TACTIC_ORDER}
    for technique_id, (name, tactic) in TECHNIQUE_CATALOG.items():
        row = counts.get(technique_id)
        by_tactic.setdefault(tactic, []).append(
            TechniqueHeat(
                technique=technique_id,
                name=name,
                detections=row["detections"] if row else 0,
                attackers=row["attackers"] if row else 0,
                last_seen=row["last_seen"] if row else None,
            )
        )

    return [
        TacticHeat(
            tactic=tactic,
            techniques=sorted(by_tactic[tactic], key=lambda t: -t.detections),
        )
        for tactic in TACTIC_ORDER
        if by_tactic.get(tactic)
    ]


@router.get("/api/stats/origins", response_model=list[AttackOrigin])
async def stats_origins(
    request: Request, limit: int = Query(200, ge=1, le=1000)
) -> list[AttackOrigin]:
    """Attacker coordinates for the map. Empty without GeoIP data."""
    pool: asyncpg.Pool = request.app.state.db_pool

    rows = await pool.fetch(
        """
        SELECT host(a.ip_address) AS source_ip, a.country, a.city,
               a.latitude, a.longitude, count(e.id) AS events
        FROM attackers a
        JOIN events e ON e.attacker_id = a.id
        WHERE a.latitude IS NOT NULL AND a.longitude IS NOT NULL
        GROUP BY a.id, a.ip_address, a.country, a.city, a.latitude, a.longitude
        ORDER BY events DESC
        LIMIT $1
        """,
        limit,
    )
    return [AttackOrigin(**dict(row)) for row in rows]


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
    # browsers can't set headers on a websocket handshake, so use ?token=
    expected = os.environ.get("API_TOKEN", "")
    if expected and not secrets.compare_digest(
        websocket.query_params.get("token", ""), expected
    ):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    enriched_bus = websocket.app.state.enriched_bus
    async with enriched_bus.subscribe() as stream:
        try:
            async for event in stream:
                await websocket.send_json(event.model_dump(mode="json"))
        except (WebSocketDisconnect, RuntimeError):
            pass
