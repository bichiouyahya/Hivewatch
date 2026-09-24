"""GeoIP lookups using MaxMind GeoLite2-City.

The database is optional (it can't be redistributed). If it's missing,
events are stored without country/city. Private IPs never resolve.
"""

import logging
import os
from pathlib import Path
from typing import NamedTuple

import geoip2.database
import geoip2.errors

logger = logging.getLogger("hive.geoip")

GEOIP_DB_PATH = Path(os.environ.get("GEOIP_DB_PATH", "/data/GeoLite2-City.mmdb"))

_reader: geoip2.database.Reader | None = None
_warned_missing = False


def _get_reader() -> geoip2.database.Reader | None:
    global _reader, _warned_missing
    if _reader is not None:
        return _reader
    if not GEOIP_DB_PATH.exists():
        if not _warned_missing:
            logger.warning(
                "GeoIP database not found at %s -- events will be stored "
                "without country/city. Get a free GeoLite2-City.mmdb from "
                "MaxMind (dev.maxmind.com) and place it there to enable geo "
                "enrichment.",
                GEOIP_DB_PATH,
            )
            _warned_missing = True
        return None
    _reader = geoip2.database.Reader(str(GEOIP_DB_PATH))
    return _reader


class GeoResult(NamedTuple):
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None


def lookup(ip: str) -> GeoResult:
    """Look up an IP. Any field of the result may be None."""
    reader = _get_reader()
    if reader is None:
        return GeoResult()
    try:
        response = reader.city(ip)
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return GeoResult()
    return GeoResult(
        country=response.country.name,
        city=response.city.name,
        latitude=response.location.latitude,
        longitude=response.location.longitude,
    )
