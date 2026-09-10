"""sensors

Revision ID: 34e92ea8a3bb
Revises: 
Create Date: 2026-09-10 18:04:43.468717

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '34e92ea8a3bb'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        """
        CREATE TABLE sensors (
            id          text PRIMARY KEY,
            hostname    text NOT NULL,
            created_at  timestamptz NOT NULL DEFAULT now()
        )
        """
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TABLE sensors")
