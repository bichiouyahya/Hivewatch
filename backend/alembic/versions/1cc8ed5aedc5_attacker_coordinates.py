"""attacker coordinates

Revision ID: 1cc8ed5aedc5
Revises: 63ee167fceee
Create Date: 2026-09-24 22:52:40.483434

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1cc8ed5aedc5'
down_revision: Union[str, Sequence[str], None] = '63ee167fceee'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("ALTER TABLE attackers ADD COLUMN latitude double precision")
    op.execute("ALTER TABLE attackers ADD COLUMN longitude double precision")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("ALTER TABLE attackers DROP COLUMN latitude")
    op.execute("ALTER TABLE attackers DROP COLUMN longitude")
