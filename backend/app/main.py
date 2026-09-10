import asyncio
import logging
import os
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import storage
from app.api import router as api_router
from app.bus import Broadcaster
from app.httpd import start_http_server
from app.pipeline import run_pipeline
from app.sshd import start_ssh_server

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
logger = logging.getLogger("hive")

SENSOR_ID = os.environ.get("SENSOR_ID", "hive-dev")
DASHBOARD_ORIGIN = os.environ.get("DASHBOARD_ORIGIN", "http://localhost:3000")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # bus: raw events from the honeypots
    # enriched_bus: events after the pipeline (geo + mitre), used by the websocket
    bus = Broadcaster()
    enriched_bus = Broadcaster()
    app.state.bus = bus
    app.state.enriched_bus = enriched_bus

    pool = await storage.create_pool()
    app.state.db_pool = pool
    await storage.ensure_sensor(pool, SENSOR_ID, socket.gethostname())

    pipeline_task = asyncio.create_task(run_pipeline(bus, pool, enriched_bus))
    ssh_listener = await start_ssh_server(bus)
    http_server = await start_http_server(bus)

    yield

    ssh_listener.close()
    await ssh_listener.wait_closed()
    http_server.close()
    await http_server.wait_closed()
    pipeline_task.cancel()
    await pool.close()


app = FastAPI(title="Hive", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[DASHBOARD_ORIGIN],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(api_router)
