"""attackers

Revision ID: 605bd077abd2
Revises: 34e92ea8a3bb
Create Date: 2026-09-10 18:04:43.757349

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '605bd077abd2'
down_revision: Union[str, Sequence[str], None] = '34e92ea8a3bb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        """
        CREATE TABLE attackers (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            ip_address  inet NOT NULL UNIQUE,
            country     text,
            city        text,
            first_seen  timestamptz NOT NULL DEFAULT now(),
            last_seen   timestamptz NOT NULL DEFAULT now()
        )
        """
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TABLE attackers")
