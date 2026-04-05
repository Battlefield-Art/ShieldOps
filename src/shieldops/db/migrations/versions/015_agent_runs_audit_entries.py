"""Add agent_runs and audit_entries tables for execution persistence and audit trail.

Revision ID: 015
Revises: 014
Create Date: 2026-04-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op  # type: ignore[attr-defined]

revision: str = "015"
down_revision: str | None = "014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── agent_runs ────────────────────────────────────────────────────
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("agent_name", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("input_data", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("output_data", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("duration_ms", sa.Integer, server_default="0"),
        sa.Column(
            "token_usage",
            JSONB,
            nullable=False,
            server_default=sa.text(
                '\'{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}\'::jsonb'
            ),
        ),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_agent_runs_agent_name", "agent_runs", ["agent_name"])
    op.create_index("ix_agent_runs_status", "agent_runs", ["status"])
    op.create_index("ix_agent_runs_org_id", "agent_runs", ["org_id"])
    op.create_index("ix_agent_runs_name_org", "agent_runs", ["agent_name", "org_id"])
    op.create_index("ix_agent_runs_created", "agent_runs", ["created_at"])
    op.create_index("ix_agent_runs_org_created", "agent_runs", ["org_id", "created_at"])

    # ── audit_entries (APPEND-ONLY) ───────────────────────────────────
    op.create_table(
        "audit_entries",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("action", sa.String(256), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("result", sa.String(32), nullable=False),
        sa.Column("metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_entries_action", "audit_entries", ["action"])
    op.create_index("ix_audit_entries_actor", "audit_entries", ["actor"])
    op.create_index("ix_audit_entries_result", "audit_entries", ["result"])
    op.create_index("ix_audit_entries_org_id", "audit_entries", ["org_id"])
    op.create_index("ix_audit_entries_org_created", "audit_entries", ["org_id", "created_at"])
    op.create_index("ix_audit_entries_actor_action", "audit_entries", ["actor", "action"])


def downgrade() -> None:
    op.drop_table("audit_entries")
    op.drop_table("agent_runs")
