"""Add AI Security Control Plane tables.

Creates 7 tables: situations, situation_findings, situation_actions,
nhi_identities, shadow_ai_detections, firewall_events, mcp_servers.

Revision ID: 003
Revises: 014
Create Date: 2026-03-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op  # type: ignore[attr-defined]

revision: str = "003"
down_revision: str = "014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── situations ─────────────────────────────────────────────────────
    op.create_table(
        "situations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), server_default="open"),
        sa.Column("risk_score", sa.Float, server_default="0"),
        sa.Column("vendor_sources", JSONB, server_default="[]"),
        sa.Column("mitre_techniques", JSONB, server_default="[]"),
        sa.Column("affected_entities", JSONB, server_default="[]"),
        sa.Column("findings_count", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assigned_to", sa.String(128), nullable=True),
        sa.Column("mttd_seconds", sa.Integer, nullable=True),
        sa.Column("mtta_seconds", sa.Integer, nullable=True),
        sa.Column("mttr_seconds", sa.Integer, nullable=True),
    )
    op.create_index("ix_situations_severity", "situations", ["severity"])
    op.create_index("ix_situations_status", "situations", ["status"])
    op.create_index("ix_situations_severity_status", "situations", ["severity", "status"])
    op.create_index("ix_situations_risk_score", "situations", ["risk_score"])

    # ── situation_findings ─────────────────────────────────────────────
    op.create_table(
        "situation_findings",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("situation_id", sa.String(64), nullable=False),
        sa.Column("vendor", sa.String(128), nullable=False),
        sa.Column("detection_id", sa.String(256), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("raw_data", JSONB, server_default="{}"),
        sa.ForeignKeyConstraint(["situation_id"], ["situations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_situation_findings_situation_id", "situation_findings", ["situation_id"])
    op.create_index("ix_situation_findings_vendor", "situation_findings", ["vendor"])
    op.create_index(
        "ix_situation_findings_vendor_ts", "situation_findings", ["vendor", "timestamp"]
    )

    # ── situation_actions ──────────────────────────────────────────────
    op.create_table(
        "situation_actions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("situation_id", sa.String(64), nullable=False),
        sa.Column("action_type", sa.String(128), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("confidence", sa.Float, server_default="0"),
        sa.Column("status", sa.String(32), server_default="proposed"),
        sa.Column("executed_by", sa.String(128), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", JSONB, nullable=True),
        sa.ForeignKeyConstraint(["situation_id"], ["situations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_situation_actions_situation_id", "situation_actions", ["situation_id"])
    op.create_index("ix_situation_actions_action_type", "situation_actions", ["action_type"])

    # ── nhi_identities ─────────────────────────────────────────────────
    op.create_table(
        "nhi_identities",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("nhi_type", sa.String(64), nullable=False),
        sa.Column("provider", sa.String(128), nullable=False),
        sa.Column("permissions", JSONB, server_default="[]"),
        sa.Column("owner", sa.String(256), nullable=True),
        sa.Column("risk_score", sa.Float, server_default="0"),
        sa.Column("status", sa.String(32), server_default="active"),
        sa.Column("last_active_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_nhi_identities_name", "nhi_identities", ["name"])
    op.create_index("ix_nhi_identities_nhi_type", "nhi_identities", ["nhi_type"])
    op.create_index("ix_nhi_identities_provider", "nhi_identities", ["provider"])
    op.create_index("ix_nhi_identities_status", "nhi_identities", ["status"])
    op.create_index("ix_nhi_type_provider", "nhi_identities", ["nhi_type", "provider"])
    op.create_index("ix_nhi_risk_score", "nhi_identities", ["risk_score"])

    # ── shadow_ai_detections ───────────────────────────────────────────
    op.create_table(
        "shadow_ai_detections",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("provider", sa.String(128), nullable=False),
        sa.Column("api_endpoint", sa.String(512), nullable=False),
        sa.Column("calling_service", sa.String(256), nullable=False),
        sa.Column("detection_source", sa.String(128), nullable=False),
        sa.Column("request_count", sa.Integer, server_default="0"),
        sa.Column("estimated_cost", sa.Float, server_default="0"),
        sa.Column("status", sa.String(32), server_default="detected"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_shadow_ai_provider", "shadow_ai_detections", ["provider"])
    op.create_index("ix_shadow_ai_calling_service", "shadow_ai_detections", ["calling_service"])
    op.create_index("ix_shadow_ai_status", "shadow_ai_detections", ["status"])
    op.create_index(
        "ix_shadow_ai_provider_service",
        "shadow_ai_detections",
        ["provider", "calling_service"],
    )

    # ── firewall_events ────────────────────────────────────────────────
    op.create_table(
        "firewall_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("agent_id", sa.String(128), nullable=False),
        sa.Column("tool_name", sa.String(256), nullable=False),
        sa.Column("action_taken", sa.String(32), nullable=False),
        sa.Column("risk_score", sa.Float, server_default="0"),
        sa.Column("anomaly_type", sa.String(128), nullable=True),
        sa.Column("policy_rule_id", sa.String(128), nullable=True),
        sa.Column("data_bytes", sa.Integer, server_default="0"),
        sa.Column("latency_ms", sa.Integer, server_default="0"),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_firewall_events_agent_id", "firewall_events", ["agent_id"])
    op.create_index("ix_firewall_events_action_taken", "firewall_events", ["action_taken"])
    op.create_index("ix_firewall_events_timestamp", "firewall_events", ["timestamp"])
    op.create_index("ix_firewall_agent_ts", "firewall_events", ["agent_id", "timestamp"])
    op.create_index("ix_firewall_action_ts", "firewall_events", ["action_taken", "timestamp"])

    # ── mcp_servers ────────────────────────────────────────────────────
    op.create_table(
        "mcp_servers",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(256), unique=True, nullable=False),
        sa.Column("endpoint", sa.String(512), nullable=False),
        sa.Column("transport", sa.String(32), nullable=False),
        sa.Column("auth_type", sa.String(64), nullable=False),
        sa.Column("tools_exposed", JSONB, server_default="[]"),
        sa.Column("downstream_resources", JSONB, server_default="[]"),
        sa.Column("risk_score", sa.Float, server_default="0"),
        sa.Column("trust_level", sa.String(32), server_default="'untrusted'"),
        sa.Column("owner", sa.String(256), nullable=True),
        sa.Column("zero_trust_compliant", sa.Boolean, server_default=sa.text("false")),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_mcp_servers_name", "mcp_servers", ["name"], unique=True)
    op.create_index("ix_mcp_servers_trust_level", "mcp_servers", ["trust_level"])


def downgrade() -> None:
    op.drop_table("mcp_servers")
    op.drop_table("firewall_events")
    op.drop_table("shadow_ai_detections")
    op.drop_table("nhi_identities")
    op.drop_table("situation_actions")
    op.drop_table("situation_findings")
    op.drop_table("situations")
