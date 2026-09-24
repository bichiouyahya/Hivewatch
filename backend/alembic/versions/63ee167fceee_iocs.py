"""iocs

Revision ID: 63ee167fceee
Revises: 9b53aa918321
Create Date: 2026-09-24 22:03:22.197436

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '63ee167fceee'
down_revision: Union[str, Sequence[str], None] = '9b53aa918321'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        """
        CREATE TABLE iocs (
            id              bigserial PRIMARY KEY,
            ioc_type        text NOT NULL,
            value           text NOT NULL,
            source_service  text NOT NULL,
            hit_count       integer NOT NULL DEFAULT 1,
            confidence      integer NOT NULL DEFAULT 50,
            first_seen      timestamptz NOT NULL DEFAULT now(),
            last_seen       timestamptz NOT NULL DEFAULT now(),
            UNIQUE (ioc_type, value)
        )
        """
    )
    op.execute("CREATE INDEX iocs_type_idx ON iocs (ioc_type)")
    op.execute("CREATE INDEX iocs_last_seen_idx ON iocs (last_seen DESC)")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TABLE iocs")
