#!/bin/sh
# kept outside /app because ./backend is mounted over it in development
set -e

# no-op after the first boot, since alembic tracks applied revisions
echo "==> applying database migrations"
uv run alembic upgrade head

echo "==> starting hive backend"
exec uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
