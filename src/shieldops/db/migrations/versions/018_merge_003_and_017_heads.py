"""merge 003 and 017 heads

Revision ID: 018
Revises: 003, 017
Create Date: 2026-04-06 23:36:16.483377
"""

from __future__ import annotations

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "018"
down_revision: str | None = ("003", "017")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
