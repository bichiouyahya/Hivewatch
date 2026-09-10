"""sessions

Revision ID: 0db8b5cdaad8
Revises: 605bd077abd2
Create Date: 2026-09-10 18:04:44.029963

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0db8b5cdaad8'
down_revision: Union[str, Sequence[str], None] = '605bd077abd2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        """
        CREATE TABLE sessions (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            sensor_id   text NOT NULL REFERENCES sensors (id),
            attacker_id uuid NOT NULL REFERENCES attackers (id),
            service     text NOT NULL,
            started_at  timestamptz NOT NULL DEFAULT now(),
            ended_at    timestamptz
        )
        """
    )
    op.execute("CREATE INDEX sessions_attacker_id_idx ON sessions (attacker_id)")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TABLE sessions")
