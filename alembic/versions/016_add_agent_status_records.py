"""Add agent_status_records table for fitness-gated promotion system.

Revision ID: 016_add_agent_status_records
Revises: 015
Create Date: 2026-04-05
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "016_add_agent_status_records"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_status_records",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("agent_name", sa.String(128), nullable=False),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="beta"),
        sa.Column("current_fitness", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("fitness_history", JSONB, nullable=False, server_default="[]"),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("demoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_agent_status_records_agent_name",
        "agent_status_records",
        ["agent_name"],
    )
    op.create_index(
        "ix_agent_status_records_org_id",
        "agent_status_records",
        ["org_id"],
    )
    op.create_index(
        "ix_agent_status_records_status",
        "agent_status_records",
        ["status"],
    )
    op.create_index(
        "ix_agent_status_name_org",
        "agent_status_records",
        ["agent_name", "org_id"],
        unique=True,
    )
    op.create_index(
        "ix_agent_status_org_status",
        "agent_status_records",
        ["org_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_agent_status_org_status", table_name="agent_status_records")
    op.drop_index("ix_agent_status_name_org", table_name="agent_status_records")
    op.drop_index("ix_agent_status_records_status", table_name="agent_status_records")
    op.drop_index("ix_agent_status_records_org_id", table_name="agent_status_records")
    op.drop_index("ix_agent_status_records_agent_name", table_name="agent_status_records")
    op.drop_table("agent_status_records")
