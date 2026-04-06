"""Production tests for the Identity Graph Agent.

Tests AWS IAM enumeration, CrowdStrike correlation, NHI discovery,
risk assessment (LLM + heuristic fallback), and graph compilation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from shieldops.agents.identity_graph.models import (
    IdentityGraphState,
)
from shieldops.agents.identity_graph.tools import IdentityGraphToolkit

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def toolkit() -> IdentityGraphToolkit:
    """Toolkit without connectors (uses mock/heuristic data)."""
    return IdentityGraphToolkit()


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC)


def _make_iam_user(
    *,
    user_name: str = "svc-test",
    path: str = "/service/",
    access_keys: list[dict[str, Any]] | None = None,
    attached_policies: list[dict[str, Any]] | None = None,
    groups: list[str] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "user_name": user_name,
        "user_id": f"AIDA_{user_name.upper()}",
        "arn": f"arn:aws:iam::123456789012:user/{user_name}",
        "created_at": created_at or (now - timedelta(days=30)).isoformat(),
        "path": path,
        "access_keys": access_keys or [],
        "attached_policies": attached_policies or [],
        "groups": groups or [],
    }


def _make_access_key(
    *,
    key_id: str = "AKIA_TEST_001",
    status: str = "Active",
    age_days: int = 30,
    last_used: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "access_key_id": key_id,
        "status": status,
        "created_at": (now - timedelta(days=age_days)).isoformat(),
        "age_days": age_days,
        "last_used": last_used,
    }


# ---------------------------------------------------------------------------
# AWS IAM Enumeration
# ---------------------------------------------------------------------------


class TestIAMEnumeration:
    """Tests for AWS IAM user and role enumeration."""

    @pytest.mark.asyncio
    async def test_enumerate_iam_users_returns_structured_data(
        self, toolkit: IdentityGraphToolkit
    ) -> None:
        """IAM enumeration returns structured user records without connectors."""
        users = await toolkit.enumerate_iam_users()
        assert len(users) > 0
        for user in users:
            assert "user_name" in user
            assert "user_id" in user
            assert "arn" in user
            assert "created_at" in user
            assert "access_keys" in user
            assert "attached_policies" in user
            assert "groups" in user
            assert isinstance(user["access_keys"], list)
            assert isinstance(user["attached_policies"], list)

    @pytest.mark.asyncio
    async def test_enumerate_iam_users_access_key_metadata(
        self, toolkit: IdentityGraphToolkit
    ) -> None:
        """Each access key has last_used, age_days, and status fields."""
        users = await toolkit.enumerate_iam_users()
        keys_found = False
        for user in users:
            for key in user["access_keys"]:
                keys_found = True
                assert "access_key_id" in key
                assert "status" in key
                assert "age_days" in key
                assert "created_at" in key
                # last_used can be None (never used)
                assert "last_used" in key
        assert keys_found, "Expected at least one access key in mock data"

    @pytest.mark.asyncio
    async def test_enumerate_iam_roles_returns_structured_data(
        self, toolkit: IdentityGraphToolkit
    ) -> None:
        """IAM role enumeration returns role records with trust policies."""
        roles = await toolkit.enumerate_iam_roles()
        assert len(roles) > 0
        for role in roles:
            assert "role_name" in role
            assert "role_id" in role
            assert "arn" in role
            assert "trust_policy" in role
            assert "attached_policies" in role

    @pytest.mark.asyncio
    async def test_enumerate_iam_roles_trust_policy(self, toolkit: IdentityGraphToolkit) -> None:
        """At least one role has a non-empty trust policy document."""
        roles = await toolkit.enumerate_iam_roles()
        has_trust = any(role.get("trust_policy", {}).get("Statement") for role in roles)
        assert has_trust, "Expected at least one role with trust policy"


# ---------------------------------------------------------------------------
# Stale Credential Detection
# ---------------------------------------------------------------------------


class TestStaleCredentials:
    """Tests for stale/unused credential identification."""

    @pytest.mark.asyncio
    async def test_identifies_stale_keys(self, now: datetime) -> None:
        """Keys unused for 90+ days are flagged as stale."""
        toolkit = IdentityGraphToolkit()
        users = [
            _make_iam_user(
                user_name="stale-user",
                access_keys=[
                    _make_access_key(
                        age_days=120,
                        last_used=(now - timedelta(days=100)).isoformat(),
                    ),
                ],
            ),
        ]
        stale = await toolkit.identify_stale_credentials(users)
        assert len(stale) >= 1
        assert stale[0]["user_name"] == "stale-user"
        assert stale[0]["is_stale"]

    @pytest.mark.asyncio
    async def test_fresh_keys_not_flagged(self, now: datetime) -> None:
        """Keys used recently and not old are not flagged."""
        toolkit = IdentityGraphToolkit()
        users = [
            _make_iam_user(
                user_name="active-user",
                access_keys=[
                    _make_access_key(
                        age_days=10,
                        last_used=(now - timedelta(days=1)).isoformat(),
                    ),
                ],
            ),
        ]
        stale = await toolkit.identify_stale_credentials(users)
        assert len(stale) == 0

    @pytest.mark.asyncio
    async def test_never_used_key_flagged(self, now: datetime) -> None:
        """Keys that have never been used and are old enough get flagged."""
        toolkit = IdentityGraphToolkit()
        users = [
            _make_iam_user(
                user_name="unused-key-user",
                access_keys=[
                    _make_access_key(age_days=100, last_used=None),
                ],
            ),
        ]
        stale = await toolkit.identify_stale_credentials(users)
        assert len(stale) >= 1
        assert stale[0]["is_stale"]

    @pytest.mark.asyncio
    async def test_inactive_keys_skipped(self, now: datetime) -> None:
        """Inactive (disabled) keys are not flagged."""
        toolkit = IdentityGraphToolkit()
        users = [
            _make_iam_user(
                user_name="disabled-key-user",
                access_keys=[
                    _make_access_key(age_days=200, status="Inactive"),
                ],
            ),
        ]
        stale = await toolkit.identify_stale_credentials(users)
        assert len(stale) == 0

    @pytest.mark.asyncio
    async def test_stale_and_old_is_critical(self, now: datetime) -> None:
        """Keys that are both stale and old get critical risk."""
        toolkit = IdentityGraphToolkit()
        users = [
            _make_iam_user(
                user_name="critical-user",
                access_keys=[
                    _make_access_key(
                        age_days=200,
                        last_used=(now - timedelta(days=150)).isoformat(),
                    ),
                ],
            ),
        ]
        stale = await toolkit.identify_stale_credentials(users)
        assert len(stale) >= 1
        assert stale[0]["risk_level"] == "critical"


# ---------------------------------------------------------------------------
# NHI Discovery
# ---------------------------------------------------------------------------


class TestNHIDiscovery:
    """Tests for non-human identity discovery and cataloging."""

    @pytest.mark.asyncio
    async def test_discovers_service_accounts_from_iam(self, toolkit: IdentityGraphToolkit) -> None:
        """Service accounts with 'svc' or 'service' in name are detected as NHIs."""
        users = [
            _make_iam_user(user_name="svc-deploy", path="/service/"),
            _make_iam_user(user_name="regular-human", path="/"),
        ]
        roles: list[dict[str, Any]] = []
        nhis = await toolkit.discover_nhis(users, roles)

        nhi_ids = [n["identity_id"] for n in nhis]
        assert "svc-deploy" in nhi_ids
        assert "regular-human" not in nhi_ids

    @pytest.mark.asyncio
    async def test_nhi_has_required_fields(self, toolkit: IdentityGraphToolkit) -> None:
        """Each NHI record has type, owner, last_used, risk_score, over_privileged."""
        users = [
            _make_iam_user(
                user_name="svc-test",
                path="/service/",
                groups=["platform-team"],
            ),
        ]
        nhis = await toolkit.discover_nhis(users, [])

        assert len(nhis) >= 1
        nhi = nhis[0]
        assert "identity_id" in nhi
        assert "nhi_type" in nhi
        assert "owner" in nhi
        assert "last_used" in nhi
        assert "risk_score" in nhi
        assert "over_privileged" in nhi
        assert isinstance(nhi["risk_score"], float)

    @pytest.mark.asyncio
    async def test_flags_over_privileged_service_accounts(
        self, toolkit: IdentityGraphToolkit
    ) -> None:
        """Service accounts with admin policies are flagged as over-privileged."""
        users = [
            _make_iam_user(
                user_name="svc-admin-bot",
                path="/service/",
                attached_policies=[
                    {
                        "policy_name": "AdministratorAccess",
                        "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    },
                ],
            ),
        ]
        nhis = await toolkit.discover_nhis(users, [])

        admin_nhis = [n for n in nhis if n["over_privileged"]]
        assert len(admin_nhis) >= 1
        assert admin_nhis[0]["risk_score"] >= 40.0

    @pytest.mark.asyncio
    async def test_discovers_iam_roles_as_nhis(self, toolkit: IdentityGraphToolkit) -> None:
        """All IAM roles are cataloged as NHIs."""
        roles = [
            {
                "role_name": "lambda-exec",
                "role_id": "AROA123",
                "arn": "arn:aws:iam::123456789012:role/lambda-exec",
                "created_at": datetime.now(UTC).isoformat(),
                "path": "/service-role/",
                "trust_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
                "attached_policies": [],
            },
        ]
        nhis = await toolkit.discover_nhis([], roles)
        assert len(nhis) >= 1
        assert nhis[0]["nhi_type"] == "iam_role"

    @pytest.mark.asyncio
    async def test_classifies_bot_accounts(self, toolkit: IdentityGraphToolkit) -> None:
        """Users with 'bot' in name are classified as bot_account NHI type."""
        users = [
            _make_iam_user(user_name="ci-bot-runner", path="/service/"),
        ]
        nhis = await toolkit.discover_nhis(users, [])
        bot_nhis = [n for n in nhis if n["nhi_type"] == "bot_account"]
        assert len(bot_nhis) >= 1

    @pytest.mark.asyncio
    async def test_cross_account_trust_increases_risk(self, toolkit: IdentityGraphToolkit) -> None:
        """Roles with cross-account :root trust get elevated risk."""
        roles = [
            {
                "role_name": "cross-account-role",
                "role_id": "AROA_CROSS",
                "arn": "arn:aws:iam::123456789012:role/cross-account-role",
                "created_at": datetime.now(UTC).isoformat(),
                "path": "/",
                "trust_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::999888777666:root"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
                "attached_policies": [],
            },
        ]
        nhis = await toolkit.discover_nhis([], roles)
        assert nhis[0]["risk_score"] >= 20.0

    @pytest.mark.asyncio
    async def test_discover_nhis_from_mock_fallback(self, toolkit: IdentityGraphToolkit) -> None:
        """Full NHI discovery pipeline works with mock data (no connectors)."""
        users = await toolkit.enumerate_iam_users()
        roles = await toolkit.enumerate_iam_roles()
        nhis = await toolkit.discover_nhis(users, roles)

        # Should discover at least the mock service accounts + roles
        assert len(nhis) >= 3
        types = {n["nhi_type"] for n in nhis}
        assert "iam_role" in types


# ---------------------------------------------------------------------------
# CrowdStrike Identity Correlation
# ---------------------------------------------------------------------------


class TestCrowdStrikeCorrelation:
    """Tests for CrowdStrike host-to-IAM identity correlation."""

    @pytest.mark.asyncio
    async def test_fetch_crowdstrike_hosts_returns_data(
        self, toolkit: IdentityGraphToolkit
    ) -> None:
        """CrowdStrike host fetch returns structured host records."""
        hosts = await toolkit.fetch_crowdstrike_hosts()
        assert len(hosts) > 0
        for host in hosts:
            assert "device_id" in host
            assert "hostname" in host
            assert "platform" in host

    @pytest.mark.asyncio
    async def test_correlates_hostname_with_iam_user(self, toolkit: IdentityGraphToolkit) -> None:
        """Hostname containing IAM username produces a correlation match."""
        iam_users = [
            _make_iam_user(user_name="dev-user"),
        ]
        cs_hosts = [
            {
                "device_id": "cs-001",
                "hostname": "dev-user-workstation",
                "platform": "Windows",
            },
        ]
        correlations = await toolkit.correlate_crowdstrike_aws_identities(iam_users, cs_hosts)
        assert len(correlations) >= 1
        assert correlations[0]["match_type"] == "hostname_contains_username"
        assert correlations[0]["confidence_score"] >= 0.5

    @pytest.mark.asyncio
    async def test_correlates_service_account_convention(
        self, toolkit: IdentityGraphToolkit
    ) -> None:
        """Service account naming convention (svc-X) matches host with X."""
        iam_users = [
            _make_iam_user(user_name="svc-deploy-pipeline"),
        ]
        cs_hosts = [
            {
                "device_id": "cs-002",
                "hostname": "deploy-pipeline-host",
                "platform": "Linux",
            },
        ]
        correlations = await toolkit.correlate_crowdstrike_aws_identities(iam_users, cs_hosts)
        assert len(correlations) >= 1
        assert correlations[0]["match_type"] == "service_account_convention"

    @pytest.mark.asyncio
    async def test_no_correlation_for_unrelated(self, toolkit: IdentityGraphToolkit) -> None:
        """Unrelated IAM users and hosts produce no correlations."""
        iam_users = [
            _make_iam_user(user_name="alice"),
        ]
        cs_hosts = [
            {
                "device_id": "cs-003",
                "hostname": "prod-server-42",
                "platform": "Linux",
            },
        ]
        correlations = await toolkit.correlate_crowdstrike_aws_identities(iam_users, cs_hosts)
        assert len(correlations) == 0

    @pytest.mark.asyncio
    async def test_full_correlation_pipeline(self, toolkit: IdentityGraphToolkit) -> None:
        """End-to-end: mock IAM + mock CS hosts produce correlations."""
        iam_users = await toolkit.enumerate_iam_users()
        cs_hosts = await toolkit.fetch_crowdstrike_hosts()
        correlations = await toolkit.correlate_crowdstrike_aws_identities(iam_users, cs_hosts)
        # Mock data has matching hostnames
        assert len(correlations) >= 1


# ---------------------------------------------------------------------------
# Identity Risk Assessment (LLM + Heuristic Fallback)
# ---------------------------------------------------------------------------


class TestIdentityRiskAssessment:
    """Tests for LLM-enhanced and heuristic identity risk assessment."""

    @pytest.mark.asyncio
    async def test_heuristic_fallback_flags_over_privileged(
        self, toolkit: IdentityGraphToolkit
    ) -> None:
        """Heuristic fallback correctly flags over-privileged NHIs."""
        nhis = [
            {
                "identity_id": "svc-admin",
                "nhi_type": "service_account",
                "risk_score": 60.0,
                "over_privileged": True,
                "permissions": ["AdministratorAccess"],
            },
            {
                "identity_id": "svc-reader",
                "nhi_type": "service_account",
                "risk_score": 10.0,
                "over_privileged": False,
                "permissions": ["ReadOnlyAccess"],
            },
        ]
        result = toolkit._heuristic_risk_assessment(nhis, [])
        assert len(result["over_privileged_accounts"]) >= 1
        assert result["over_privileged_accounts"][0]["identity_id"] == "svc-admin"

    @pytest.mark.asyncio
    async def test_heuristic_fallback_flags_stale(self, toolkit: IdentityGraphToolkit) -> None:
        """Heuristic fallback correctly flags stale credentials."""
        stale_creds = [
            {
                "user_name": "svc-old",
                "access_key_id": "AKIA_OLD",
                "idle_days": 150,
                "age_days": 200,
            },
        ]
        result = toolkit._heuristic_risk_assessment([], stale_creds)
        assert len(result["stale_accounts"]) >= 1
        assert result["source"] == "heuristic"

    @pytest.mark.asyncio
    async def test_heuristic_flags_high_risk(self, toolkit: IdentityGraphToolkit) -> None:
        """NHIs with risk_score >= 50 are in high_risk_identities."""
        nhis = [
            {
                "identity_id": "risky",
                "risk_score": 75.0,
                "over_privileged": True,
                "permissions": [],
            },
            {
                "identity_id": "safe",
                "risk_score": 10.0,
                "over_privileged": False,
                "permissions": [],
            },
        ]
        result = toolkit._heuristic_risk_assessment(nhis, [])
        assert "risky" in result["high_risk_identities"]
        assert "safe" not in result["high_risk_identities"]

    @pytest.mark.asyncio
    async def test_llm_assessment_falls_back_on_error(self, toolkit: IdentityGraphToolkit) -> None:
        """When LLM fails, assess_identity_risk_llm falls back to heuristic."""
        nhis = [
            {
                "identity_id": "svc-test",
                "nhi_type": "service_account",
                "risk_score": 55.0,
                "over_privileged": True,
                "permissions": ["admin"],
                "owner": "team",
            },
        ]
        with patch(
            "shieldops.agents.identity_graph.tools.llm_structured",
            side_effect=Exception("LLM unavailable"),
        ):
            result = await toolkit.assess_identity_risk_llm(nhis, [], [])
        assert result["source"] == "heuristic"
        assert "svc-test" in result["high_risk_identities"]

    @pytest.mark.asyncio
    async def test_llm_assessment_uses_llm_when_available(
        self, toolkit: IdentityGraphToolkit
    ) -> None:
        """When LLM succeeds, returns LLM-sourced result."""
        mock_result = MagicMock()
        mock_result.risk_summary = "High risk detected"
        mock_result.high_risk_identities = ["svc-danger"]
        mock_result.over_privileged = [{"identity_id": "svc-danger", "permissions": ["admin"]}]
        mock_result.stale_credentials = ["svc-old"]
        mock_result.risk_factors = ["admin_on_service_account"]

        with patch(
            "shieldops.agents.identity_graph.tools.llm_structured",
            return_value=mock_result,
        ):
            result = await toolkit.assess_identity_risk_llm(
                [
                    {
                        "identity_id": "svc-danger",
                        "nhi_type": "service_account",
                        "risk_score": 70,
                        "over_privileged": True,
                        "permissions": ["admin"],
                        "owner": "team",
                    }
                ],
                [],
                [],
            )
        assert result["source"] == "llm"
        assert "svc-danger" in result["high_risk_identities"]


# ---------------------------------------------------------------------------
# OPA Policy Check
# ---------------------------------------------------------------------------


class TestPolicyCheck:
    """Tests for OPA policy evaluation integration."""

    @pytest.mark.asyncio
    async def test_policy_check_read_action_fails_open(self, toolkit: IdentityGraphToolkit) -> None:
        """Read-only actions are allowed even when policy engine is unavailable."""
        with patch(
            "shieldops.agents.identity_graph.tools.policy_evaluate",
            side_effect=Exception("OPA unavailable"),
        ):
            result = await toolkit.check_policy(
                action="scan",
                target_identities=["org-test"],
            )
        assert result["allowed"] is True

    @pytest.mark.asyncio
    async def test_policy_check_write_action_fails_closed(
        self, toolkit: IdentityGraphToolkit
    ) -> None:
        """Write actions are denied when policy engine is unavailable."""
        with patch(
            "shieldops.agents.identity_graph.tools.policy_evaluate",
            side_effect=Exception("OPA unavailable"),
        ):
            result = await toolkit.check_policy(
                action="remediate",
                target_identities=["svc-admin"],
            )
        assert result["allowed"] is False


# ---------------------------------------------------------------------------
# Graph Compilation
# ---------------------------------------------------------------------------


class TestGraphCompilation:
    """Tests that the LangGraph workflow compiles correctly."""

    def test_graph_compiles(self) -> None:
        """Identity graph StateGraph compiles without errors."""
        from shieldops.agents.identity_graph.graph import create_identity_graph

        sg = create_identity_graph()
        app = sg.compile()
        assert app is not None

    def test_state_defaults(self) -> None:
        """IdentityGraphState initializes with expected defaults."""
        state = IdentityGraphState()
        assert state.error == ""
        assert state.current_step == "init"
        assert state.scan_target == ""
        assert len(state.identities_discovered) == 0
        assert len(state.risk_assessments) == 0


# ---------------------------------------------------------------------------
# Trust Principal Extraction
# ---------------------------------------------------------------------------


class TestTrustPrincipalExtraction:
    """Tests for trust policy principal parsing."""

    def test_extract_string_principal(self) -> None:
        toolkit = IdentityGraphToolkit()
        doc = {"Statement": [{"Principal": "arn:aws:iam::123:root", "Effect": "Allow"}]}
        principals = toolkit._extract_trust_principals(doc)
        assert "arn:aws:iam::123:root" in principals

    def test_extract_dict_principal(self) -> None:
        toolkit = IdentityGraphToolkit()
        doc = {
            "Statement": [
                {
                    "Principal": {"AWS": "arn:aws:iam::123:root"},
                    "Effect": "Allow",
                }
            ]
        }
        principals = toolkit._extract_trust_principals(doc)
        assert "arn:aws:iam::123:root" in principals

    def test_extract_list_principals(self) -> None:
        toolkit = IdentityGraphToolkit()
        doc = {
            "Statement": [
                {
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::111:root",
                            "arn:aws:iam::222:root",
                        ]
                    },
                    "Effect": "Allow",
                }
            ]
        }
        principals = toolkit._extract_trust_principals(doc)
        assert len(principals) == 2

    def test_empty_trust_policy(self) -> None:
        toolkit = IdentityGraphToolkit()
        principals = toolkit._extract_trust_principals({})
        assert principals == []


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class TestPersistence:
    """Tests for scan result persistence."""

    @pytest.mark.asyncio
    async def test_persist_handles_failure_gracefully(self, toolkit: IdentityGraphToolkit) -> None:
        """Persistence failure does not raise, returns None."""
        with patch(
            "shieldops.agents.identity_graph.tools.persist_agent_run",
            side_effect=Exception("DB down"),
        ):
            result = await toolkit.persist_scan_result(
                scan_target="org-test",
                result={"identities": 10},
            )
        assert result is None
