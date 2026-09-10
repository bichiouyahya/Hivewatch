"""credentials

Revision ID: cb3fe179ac20
Revises: dd178ca151d8
Create Date: 2026-09-10 18:04:44.579896

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cb3fe179ac20'
down_revision: Union[str, Sequence[str], None] = 'dd178ca151d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        """
        CREATE TABLE credentials (
            id          bigserial PRIMARY KEY,
            event_id    bigint NOT NULL REFERENCES events (id),
            service     text NOT NULL,
            username    text NOT NULL,
            password    text NOT NULL,
            created_at  timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        "CREATE INDEX credentials_username_password_idx ON credentials (username, password)"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TABLE credentials")
