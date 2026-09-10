"""events

Revision ID: dd178ca151d8
Revises: 0db8b5cdaad8
Create Date: 2026-09-10 18:04:44.306412

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'dd178ca151d8'
down_revision: Union[str, Sequence[str], None] = '0db8b5cdaad8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        """
        CREATE TABLE events (
            id                bigserial PRIMARY KEY,
            sensor_id         text NOT NULL REFERENCES sensors (id),
            attacker_id       uuid NOT NULL REFERENCES attackers (id),
            session_id        uuid REFERENCES sessions (id),
            service           text NOT NULL,
            event_type        text NOT NULL,
            source_ip         inet NOT NULL,
            payload           jsonb NOT NULL DEFAULT '{}'::jsonb,
            mitre_techniques  text[],
            created_at        timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX events_created_at_idx ON events (created_at DESC)")
    op.execute("CREATE INDEX events_attacker_id_idx ON events (attacker_id)")
    op.execute("CREATE INDEX events_service_idx ON events (service)")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TABLE events")
