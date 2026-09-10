"""GeoIP lookups using MaxMind GeoLite2-City.

The database is optional (it can't be redistributed). If it's missing,
events are stored without country/city. Private IPs never resolve.
"""

import logging
import os
from pathlib import Path

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


def lookup(ip: str) -> tuple[str | None, str | None]:
    """Returns (country, city), either of which may be None."""
    reader = _get_reader()
    if reader is None:
        return None, None
    try:
        response = reader.city(ip)
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return None, None
    return response.country.name, response.city.name
