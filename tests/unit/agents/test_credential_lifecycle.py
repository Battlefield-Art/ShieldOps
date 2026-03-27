"""Tests for shieldops.agents.credential_lifecycle."""

from __future__ import annotations

from shieldops.agents.credential_lifecycle.models import (
    CredentialLifecycleState,
    CredentialType,
    LifecycleStage,
    PostureRating,
)


class TestEnums:
    def test_lifecyclestage_discover(self):
        assert LifecycleStage.DISCOVER == "discover"

    def test_lifecyclestage_assess_posture(self):
        assert LifecycleStage.ASSESS_POSTURE == "assess_posture"

    def test_lifecyclestage_issue_jit(self):
        assert LifecycleStage.ISSUE_JIT == "issue_jit"

    def test_lifecyclestage_enforce_rotation(self):
        assert LifecycleStage.ENFORCE_ROTATION == "enforce_rotation"

    def test_credentialtype_api_key(self):
        assert CredentialType.API_KEY == "api_key"

    def test_credentialtype_oauth_token(self):
        assert CredentialType.OAUTH_TOKEN == "oauth_token"  # noqa: S105

    def test_credentialtype_service_account(self):
        assert CredentialType.SERVICE_ACCOUNT == "service_account"

    def test_credentialtype_jwt_token(self):
        assert CredentialType.JWT_TOKEN == "jwt_token"  # noqa: S105

    def test_posturerating_excellent(self):
        assert PostureRating.EXCELLENT == "excellent"

    def test_posturerating_good(self):
        assert PostureRating.GOOD == "good"

    def test_posturerating_fair(self):
        assert PostureRating.FAIR == "fair"

    def test_posturerating_poor(self):
        assert PostureRating.POOR == "poor"


class TestModels:
    def test_state_defaults(self):
        s = CredentialLifecycleState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.credential_lifecycle.graph import (
            create_credential_lifecycle_graph,
        )

        sg = create_credential_lifecycle_graph()
        assert sg.compile() is not None
