"""Tests for the Identity Graph Agent toolkit — NHI discovery and risk scoring."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from shieldops.agents.identity_graph.tools import IdentityGraphToolkit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def toolkit() -> IdentityGraphToolkit:
    """Toolkit without connectors (heuristic fallback)."""
    return IdentityGraphToolkit()


@pytest.fixture
def _now() -> datetime:
    return datetime.now(UTC)


def _make_identity(
    *,
    id: str = "svc-test",
    name: str = "test-svc",
    type: str = "service_account",
    provider: str = "aws",
    permissions: list[str] | None = None,
    mfa_enabled: bool = False,
    created_at: str | None = None,
    last_used: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "name": name,
        "type": type,
        "provider": provider,
        "permissions": permissions or [],
        "mfa_enabled": mfa_enabled,
        "created_at": created_at,
        "last_used": last_used,
        "metadata": metadata or {},
    }


# ---------------------------------------------------------------------------
# discover_identities
# ---------------------------------------------------------------------------


class TestDiscoverIdentities:
    @pytest.mark.asyncio
    async def test_returns_sample_inventory_without_connectors(
        self, toolkit: IdentityGraphToolkit
    ) -> None:
        result = await toolkit.discover_identities({"environment": "production"})
        assert result["total_discovered"] > 0
        assert len(result["identities"]) == result["total_discovered"]

    @pytest.mark.asyncio
    async def test_identities_have_required_fields(self, toolkit: IdentityGraphToolkit) -> None:
        result = await toolkit.discover_identities({})
        for ident in result["identities"]:
            assert "id" in ident
            assert "name" in ident
            assert "type" in ident
            assert "provider" in ident

    @pytest.mark.asyncio
    async def test_queries_connector_when_available(self) -> None:
        mock_connector = AsyncMock()
        mock_resource = MagicMock()
        mock_resource.id = "iam-user-001"
        mock_resource.name = "ci-user"
        mock_resource.metadata = {"env": "prod"}
        mock_resource.created_at = None
        mock_resource.last_used = None
        mock_connector.list_resources = AsyncMock(return_value=[mock_resource])

        router = MagicMock()

        def get_side_effect(provider: str) -> Any:
            if provider == "aws":
                return mock_connector
            raise ValueError(f"No connector for {provider}")

        router.get = MagicMock(side_effect=get_side_effect)

        tk = IdentityGraphToolkit(connector_router=router)
        result = await tk.discover_identities({"environment": "production"})

        assert result["total_discovered"] >= 1
        ids = [i["id"] for i in result["identities"]]
        assert "iam-user-001" in ids
        mock_connector.list_resources.assert_called_once()

    @pytest.mark.asyncio
    async def test_falls_back_on_connector_error(self) -> None:
        router = MagicMock()
        router.get = MagicMock(side_effect=ValueError("No connector"))

        tk = IdentityGraphToolkit(connector_router=router)
        result = await tk.discover_identities({})
        # Should fall back to sample inventory
        assert result["total_discovered"] > 0


# ---------------------------------------------------------------------------
# classify_identity_type
# ---------------------------------------------------------------------------


class TestClassifyIdentityType:
    def test_bot_classification(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.classify_identity_type(
            _make_identity(name="deploy-bot", type="service_account")
        )
        assert result["classification"] == "bot_account"
        assert result["confidence"] >= 0.8

    def test_oauth_classification(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.classify_identity_type(
            _make_identity(
                name="analytics-app",
                type="oauth_token",
                metadata={"grant_type": "client_credentials"},
            )
        )
        assert result["classification"] == "oauth_token"

    def test_api_key_classification(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.classify_identity_type(
            _make_identity(
                name="ci-key",
                type="api_key",
                metadata={"access_key_id": "AKIA..."},
            )
        )
        assert result["classification"] == "api_key"

    def test_iam_role_classification(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.classify_identity_type(_make_identity(name="lambda-exec", type="iam_role"))
        assert result["classification"] == "iam_role"
        assert result["confidence"] >= 0.9

    def test_default_service_account(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.classify_identity_type(
            _make_identity(name="worker-process", type="service_account")
        )
        assert result["classification"] == "service_account"

    def test_returns_identity_id(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.classify_identity_type(_make_identity(id="svc-123"))
        assert result["identity_id"] == "svc-123"

    def test_classification_signals_present(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.classify_identity_type(_make_identity(name="automation-runner"))
        assert len(result["classification_signals"]) > 0


# ---------------------------------------------------------------------------
# assess_risk
# ---------------------------------------------------------------------------


class TestAssessRisk:
    def test_admin_privileges_increase_score(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.assess_risk(_make_identity(permissions=["admin", "read"]))
        assert result["risk_score"] >= 35
        assert "admin_privileges" in result["risk_factors"]

    def test_no_mfa_increases_score(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.assess_risk(_make_identity(mfa_enabled=False, permissions=[]))
        assert result["risk_score"] >= 15
        assert "no_mfa" in result["risk_factors"]

    def test_mfa_enabled_no_penalty(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.assess_risk(_make_identity(mfa_enabled=True, permissions=[]))
        assert "no_mfa" not in result["risk_factors"]

    def test_stale_credential_increases_score(
        self, toolkit: IdentityGraphToolkit, _now: datetime
    ) -> None:
        stale_date = (_now - timedelta(days=120)).isoformat()
        result = toolkit.assess_risk(_make_identity(last_used=stale_date))
        assert result["risk_score"] >= 20
        assert any("stale" in f for f in result["risk_factors"])

    def test_old_credential_increases_score(
        self, toolkit: IdentityGraphToolkit, _now: datetime
    ) -> None:
        old_date = (_now - timedelta(days=180)).isoformat()
        result = toolkit.assess_risk(_make_identity(created_at=old_date))
        assert any("credential_age" in f for f in result["risk_factors"])

    def test_excessive_permissions(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.assess_risk(
            _make_identity(permissions=["a", "b", "c", "d", "e", "f", "g"])
        )
        assert any("excessive" in f for f in result["risk_factors"])

    def test_score_capped_at_100(self, toolkit: IdentityGraphToolkit, _now: datetime) -> None:
        # Stack all risk factors
        result = toolkit.assess_risk(
            _make_identity(
                permissions=["admin", "root", "a", "b", "c", "d", "e", "f"],
                mfa_enabled=False,
                created_at=(_now - timedelta(days=500)).isoformat(),
                last_used=(_now - timedelta(days=200)).isoformat(),
            )
        )
        assert result["risk_score"] <= 100

    def test_risk_levels(self, toolkit: IdentityGraphToolkit) -> None:
        low = toolkit.assess_risk(_make_identity(mfa_enabled=True, permissions=["read"]))
        assert low["risk_level"] == "low"

        critical = toolkit.assess_risk(
            _make_identity(
                permissions=["admin", "a", "b", "c", "d", "e", "f"],
                mfa_enabled=False,
            )
        )
        assert critical["risk_level"] in ("critical", "high")

    def test_returns_recommendations(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.assess_risk(_make_identity(permissions=["admin"], mfa_enabled=False))
        assert len(result["recommendations"]) > 0

    def test_never_used_adds_risk(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.assess_risk(_make_identity(last_used=None))
        assert "never_used" in result["risk_factors"]


# ---------------------------------------------------------------------------
# map_relationships
# ---------------------------------------------------------------------------


class TestMapRelationships:
    def test_detects_overlapping_permissions(self, toolkit: IdentityGraphToolkit) -> None:
        identities = [
            _make_identity(id="a", permissions=["s3:*", "ec2:*"], provider="aws"),
            _make_identity(id="b", permissions=["s3:*", "lambda:*"], provider="aws"),
        ]
        result = toolkit.map_relationships(identities)
        assert result["relationship_count"] >= 1
        rel = result["relationships"][0]
        assert rel["relationship_type"] == "role_assumption"
        assert "s3:*" in rel["shared_permissions"]

    def test_no_relationships_for_disjoint_perms(self, toolkit: IdentityGraphToolkit) -> None:
        identities = [
            _make_identity(id="a", permissions=["s3:read"], provider="aws"),
            _make_identity(id="b", permissions=["ec2:start"], provider="aws"),
        ]
        result = toolkit.map_relationships(identities)
        assert result["relationship_count"] == 0

    def test_cross_account_admin_detection(self, toolkit: IdentityGraphToolkit) -> None:
        identities = [
            _make_identity(id="aws-admin", permissions=["admin"], provider="aws"),
            _make_identity(id="gcp-admin", permissions=["admin"], provider="gcp"),
        ]
        result = toolkit.map_relationships(identities)
        assert result["cross_account_count"] >= 1
        cross = [
            r for r in result["relationships"] if r["relationship_type"] == "cross_account_access"
        ]
        assert len(cross) >= 1

    def test_empty_identities(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.map_relationships([])
        assert result["relationship_count"] == 0
        assert result["cross_account_count"] == 0

    def test_identities_without_permissions(self, toolkit: IdentityGraphToolkit) -> None:
        identities = [
            _make_identity(id="a", permissions=[]),
            _make_identity(id="b", permissions=[]),
        ]
        result = toolkit.map_relationships(identities)
        assert result["relationship_count"] == 0


# ---------------------------------------------------------------------------
# detect_anomalies
# ---------------------------------------------------------------------------


class TestDetectAnomalies:
    def test_over_privileged_service_account(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.detect_anomalies(
            _make_identity(type="service_account", permissions=["admin", "read"])
        )
        assert result["anomaly_count"] >= 1
        types = [a["type"] for a in result["anomalies"]]
        assert "over_privileged_service_account" in types
        assert result["severity"] == "critical"

    def test_unused_credentials(self, toolkit: IdentityGraphToolkit, _now: datetime) -> None:
        stale = (_now - timedelta(days=120)).isoformat()
        result = toolkit.detect_anomalies(_make_identity(last_used=stale))
        types = [a["type"] for a in result["anomalies"]]
        assert "unused_credentials" in types

    def test_key_without_rotation(self, toolkit: IdentityGraphToolkit, _now: datetime) -> None:
        old = (_now - timedelta(days=180)).isoformat()
        result = toolkit.detect_anomalies(
            _make_identity(created_at=old, last_used=_now.isoformat())
        )
        types = [a["type"] for a in result["anomalies"]]
        assert "key_without_rotation" in types

    def test_bot_with_write_access(self, toolkit: IdentityGraphToolkit) -> None:
        result = toolkit.detect_anomalies(
            _make_identity(name="deploy-bot", permissions=["s3:PutObject", "s3:DeleteObject"])
        )
        types = [a["type"] for a in result["anomalies"]]
        assert "bot_with_write_access" in types

    def test_never_used_identity(self, toolkit: IdentityGraphToolkit, _now: datetime) -> None:
        result = toolkit.detect_anomalies(
            _make_identity(created_at=_now.isoformat(), last_used=None)
        )
        types = [a["type"] for a in result["anomalies"]]
        assert "never_used_identity" in types

    def test_clean_identity_no_anomalies(
        self, toolkit: IdentityGraphToolkit, _now: datetime
    ) -> None:
        result = toolkit.detect_anomalies(
            _make_identity(
                name="reader-svc",
                type="service_account",
                permissions=["s3:GetObject"],
                created_at=(_now - timedelta(days=10)).isoformat(),
                last_used=(_now - timedelta(days=1)).isoformat(),
                metadata={"last_rotated": _now.isoformat()},
            )
        )
        assert result["anomaly_count"] == 0
        assert result["severity"] == "none"

    def test_severity_hierarchy(self, toolkit: IdentityGraphToolkit, _now: datetime) -> None:
        # Critical + high should yield critical
        result = toolkit.detect_anomalies(
            _make_identity(
                type="service_account",
                permissions=["admin"],
                last_used=(_now - timedelta(days=200)).isoformat(),
            )
        )
        assert result["severity"] == "critical"


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestGenerateReport:
    def test_report_structure(self, toolkit: IdentityGraphToolkit, _now: datetime) -> None:
        inventory = [
            _make_identity(
                id="svc-1",
                permissions=["admin"],
                mfa_enabled=False,
                created_at=(_now - timedelta(days=200)).isoformat(),
                last_used=(_now - timedelta(days=150)).isoformat(),
            ),
            _make_identity(
                id="svc-2",
                permissions=["read"],
                mfa_enabled=True,
                created_at=(_now - timedelta(days=10)).isoformat(),
                last_used=(_now - timedelta(days=1)).isoformat(),
            ),
        ]
        report = toolkit.generate_report(inventory)

        assert report["total_identities"] == 2
        assert "risk_distribution" in report
        assert set(report["risk_distribution"].keys()) == {"critical", "high", "medium", "low"}
        assert "top_risks" in report
        assert "anomaly_summary" in report
        assert "recommendations" in report
        assert "generated_at" in report

    def test_report_identifies_high_risk(
        self, toolkit: IdentityGraphToolkit, _now: datetime
    ) -> None:
        inventory = [
            _make_identity(
                id="risky-svc",
                type="service_account",
                permissions=["admin", "root", "a", "b", "c", "d"],
                mfa_enabled=False,
                created_at=(_now - timedelta(days=300)).isoformat(),
                last_used=(_now - timedelta(days=200)).isoformat(),
            ),
        ]
        report = toolkit.generate_report(inventory)
        assert len(report["top_risks"]) >= 1
        assert report["top_risks"][0]["identity_id"] == "risky-svc"
        assert report["risk_distribution"]["critical"] >= 1

    def test_report_empty_inventory(self, toolkit: IdentityGraphToolkit) -> None:
        report = toolkit.generate_report([])
        assert report["total_identities"] == 0
        assert sum(report["risk_distribution"].values()) == 0
        assert len(report["top_risks"]) == 0

    def test_report_anomaly_summary(self, toolkit: IdentityGraphToolkit, _now: datetime) -> None:
        inventory = [
            _make_identity(
                id="old-key",
                type="service_account",
                permissions=["admin"],
                created_at=(_now - timedelta(days=200)).isoformat(),
                last_used=(_now - timedelta(days=150)).isoformat(),
            ),
        ]
        report = toolkit.generate_report(inventory)
        summary = report["anomaly_summary"]
        assert summary["total_anomalous_identities"] >= 1
        assert len(summary["anomaly_types"]) >= 1

    def test_report_recommendations_not_empty(
        self, toolkit: IdentityGraphToolkit, _now: datetime
    ) -> None:
        inventory = [
            _make_identity(
                permissions=["admin"],
                mfa_enabled=False,
                created_at=(_now - timedelta(days=200)).isoformat(),
            ),
        ]
        report = toolkit.generate_report(inventory)
        assert len(report["recommendations"]) > 0
