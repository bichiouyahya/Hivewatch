"""Event pipeline: GeoIP lookup, MITRE detection, then save to Postgres
and forward the enriched event.
"""

import logging

import asyncpg

from app import storage
from app.bus import Broadcaster
from app.credentials import extract as extract_credentials
from app.geoip import lookup as geoip_lookup
from app.mitre import SlidingWindowDetector, match_command, match_http_path
from app.schemas import EnrichedEvent, Event

logger = logging.getLogger("hive.pipeline")


def detect_techniques(event: Event, detector: SlidingWindowDetector) -> list[str]:
    techniques: set[str] = set()
    ip = str(event.source_ip)

    if event.event_type == "auth_attempt" and detector.record_auth_attempt(
        ip, event.occurred_at
    ):
        techniques.add("T1110")

    if event.event_type == "command":
        techniques |= match_command(event.payload.get("command", ""))

    if event.event_type == "http_request":
        techniques |= match_http_path(event.payload.get("path", ""))

    if detector.record_service_touch(ip, event.service, event.occurred_at):
        techniques.add("T1046")

    return sorted(techniques)


async def process_event(
    pool: asyncpg.Pool,
    event: Event,
    detector: SlidingWindowDetector,
    enriched_bus: Broadcaster,
) -> None:
    country, city = geoip_lookup(str(event.source_ip))
    techniques = detect_techniques(event, detector)

    async with pool.acquire() as conn, conn.transaction():
        attacker_id = await storage.upsert_attacker(
            conn, str(event.source_ip), country, city
        )

        if event.event_type == "session_start" and event.session_id:
            await storage.start_session(
                conn,
                event.session_id,
                event.sensor_id,
                attacker_id,
                event.service,
                event.occurred_at,
            )
        elif event.event_type == "session_end" and event.session_id:
            await storage.end_session(conn, event.session_id, event.occurred_at)

        event_id = await storage.insert_event(
            conn,
            event.sensor_id,
            attacker_id,
            event.session_id,
            event.service,
            event.event_type,
            str(event.source_ip),
            event.payload,
            techniques,
        )

        credentials = extract_credentials(event)
        if credentials is not None:
            username, password = credentials
            await storage.insert_credentials(
                conn, event_id, event.service, username, password
            )

    logger.info(
        "[%s] %s from %s (%s, %s) techniques=%s",
        event.service,
        event.event_type,
        event.source_ip,
        country or "?",
        city or "?",
        techniques or "-",
    )

    await enriched_bus.publish(
        EnrichedEvent(
            **event.model_dump(),
            id=event_id,
            country=country,
            city=city,
            mitre_techniques=techniques,
        )
    )


async def run_pipeline(bus: Broadcaster, pool: asyncpg.Pool, enriched_bus: Broadcaster) -> None:
    detector = SlidingWindowDetector()
    async with bus.subscribe() as stream:
        async for event in stream:
            try:
                await process_event(pool, event, detector, enriched_bus)
            except Exception:
                logger.exception("failed to process event: %s", event)
