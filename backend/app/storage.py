"""Postgres queries (asyncpg, no ORM)."""

import json
import os
import uuid

import asyncpg

DATABASE_URL = os.environ["DATABASE_URL"]


async def create_pool() -> asyncpg.Pool:
    return await asyncpg.create_pool(DATABASE_URL)


async def ensure_sensor(pool: asyncpg.Pool, sensor_id: str, hostname: str) -> None:
    await pool.execute(
        """
        INSERT INTO sensors (id, hostname) VALUES ($1, $2)
        ON CONFLICT (id) DO NOTHING
        """,
        sensor_id,
        hostname,
    )


async def upsert_attacker(
    conn: asyncpg.Connection,
    ip: str,
    country: str | None,
    city: str | None,
    latitude: float | None = None,
    longitude: float | None = None,
) -> uuid.UUID:
    """COALESCE keeps existing geo data if a later lookup returns nothing."""
    row = await conn.fetchrow(
        """
        INSERT INTO attackers (ip_address, country, city, latitude, longitude)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (ip_address) DO UPDATE SET
            last_seen = now(),
            country = COALESCE(EXCLUDED.country, attackers.country),
            city = COALESCE(EXCLUDED.city, attackers.city),
            latitude = COALESCE(EXCLUDED.latitude, attackers.latitude),
            longitude = COALESCE(EXCLUDED.longitude, attackers.longitude)
        RETURNING id
        """,
        ip,
        country,
        city,
        latitude,
        longitude,
    )
    return row["id"]


async def start_session(
    conn: asyncpg.Connection,
    session_id: str,
    sensor_id: str,
    attacker_id: uuid.UUID,
    service: str,
    started_at,
) -> None:
    await conn.execute(
        """
        INSERT INTO sessions (id, sensor_id, attacker_id, service, started_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (id) DO NOTHING
        """,
        uuid.UUID(session_id),
        sensor_id,
        attacker_id,
        service,
        started_at,
    )


async def end_session(
    conn: asyncpg.Connection,
    session_id: str,
    ended_at,
    recording: str | None = None,
) -> None:
    await conn.execute(
        """
        UPDATE sessions
        SET ended_at = $1,
            recording = COALESCE($3, recording)
        WHERE id = $2
        """,
        ended_at,
        uuid.UUID(session_id),
        recording,
    )


async def upsert_ioc(
    conn: asyncpg.Connection,
    ioc_type: str,
    value: str,
    source_service: str,
    base_confidence: int,
    seen_at,
) -> None:
    """Confidence goes up with repeat sightings, capped at 100."""
    await conn.execute(
        """
        INSERT INTO iocs (ioc_type, value, source_service, confidence, first_seen, last_seen)
        VALUES ($1, $2, $3, $4, $5, $5)
        ON CONFLICT (ioc_type, value) DO UPDATE SET
            hit_count = iocs.hit_count + 1,
            last_seen = EXCLUDED.last_seen,
            confidence = LEAST(100, $4 + (iocs.hit_count + 1) * 2)
        """,
        ioc_type,
        value,
        source_service,
        base_confidence,
        seen_at,
    )


async def insert_event(
    conn: asyncpg.Connection,
    sensor_id: str,
    attacker_id: uuid.UUID,
    session_id: str | None,
    service: str,
    event_type: str,
    source_ip: str,
    payload: dict,
    mitre_techniques: list[str],
) -> int:
    row = await conn.fetchrow(
        """
        INSERT INTO events (
            sensor_id, attacker_id, session_id, service, event_type,
            source_ip, payload, mitre_techniques
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
        RETURNING id
        """,
        sensor_id,
        attacker_id,
        uuid.UUID(session_id) if session_id else None,
        service,
        event_type,
        source_ip,
        json.dumps(payload),
        mitre_techniques or None,
    )
    return row["id"]


async def insert_credentials(
    conn: asyncpg.Connection, event_id: int, service: str, username: str, password: str
) -> None:
    await conn.execute(
        """
        INSERT INTO credentials (event_id, service, username, password)
        VALUES ($1, $2, $3, $4)
        """,
        event_id,
        service,
        username,
        password,
    )
