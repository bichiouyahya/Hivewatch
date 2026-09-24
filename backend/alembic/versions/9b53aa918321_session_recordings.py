"""session recordings

Revision ID: 9b53aa918321
Revises: cb3fe179ac20
Create Date: 2026-09-24 22:03:21.906758

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9b53aa918321'
down_revision: Union[str, Sequence[str], None] = 'cb3fe179ac20'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("ALTER TABLE sessions ADD COLUMN recording text")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("ALTER TABLE sessions DROP COLUMN recording")
