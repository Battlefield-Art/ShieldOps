"""Unified audit log + NL query audit tables.

Revision ID: 017
Revises: 015
Create Date: 2026-04-06

Adds:
- shieldops_audit_log: append-only tenant-aware audit log shared across subsystems
- nl_query_audit: per-query metadata persistence (questions, SQL, timing, cache hit)
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "017"
down_revision: str | None = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── shieldops_audit_log ───────────────────────────────────────────
    op.create_table(
        "shieldops_audit_log",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False, server_default=""),
        sa.Column("target", sa.String(256), nullable=False, server_default=""),
        sa.Column("result", sa.String(32), nullable=False, server_default=""),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_audit_org_created", "shieldops_audit_log", ["org_id", "created_at"])
    op.create_index("ix_audit_org_action", "shieldops_audit_log", ["org_id", "action"])

    # ── nl_query_audit ────────────────────────────────────────────────
    op.create_table(
        "nl_query_audit",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("generated_sql", sa.Text(), nullable=False, server_default=""),
        sa.Column("result_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("latency_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("cache_hit", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("source", sa.String(32), nullable=False, server_default="llm"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_nlq_audit_org_id", "nl_query_audit", ["org_id"])
    op.create_index("ix_nlq_audit_org_created", "nl_query_audit", ["org_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_nlq_audit_org_created", table_name="nl_query_audit")
    op.drop_index("ix_nlq_audit_org_id", table_name="nl_query_audit")
    op.drop_table("nl_query_audit")

    op.drop_index("ix_audit_org_action", table_name="shieldops_audit_log")
    op.drop_index("ix_audit_org_created", table_name="shieldops_audit_log")
    op.drop_table("shieldops_audit_log")
