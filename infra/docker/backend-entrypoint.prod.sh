#!/bin/sh
set -e

echo "==> applying database migrations"
uv run alembic upgrade head

# single worker: the honeypot listeners run inside this process, so extra
# workers would fight over the same ports
echo "==> starting hive backend"
exec uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-access-log
