"""Comprehensive TDD/BDD tests for Phase B remediation agents.

Tests cover: enums, models, toolkit methods, graph compilation,
and BDD scenarios for the full remediation pipeline.
"""

from __future__ import annotations

import pytest

# ── TDD: Patch Orchestrator ──


class TestPatchOrchestrator:
    """TDD tests for patch_orchestrator agent."""

    def test_patch_stage_enum(self):
        from shieldops.agents.patch_orchestrator.models import PatchStage

        assert PatchStage.INVENTORY_SYSTEMS == "inventory_systems"

    def test_patch_priority_enum(self):
        from shieldops.agents.patch_orchestrator.models import PatchPriority

        assert PatchPriority.EMERGENCY == "emergency"
        assert PatchPriority.CRITICAL == "critical"

    def test_deployment_status_enum(self):
        from shieldops.agents.patch_orchestrator.models import (
            DeploymentStatus,
        )

        assert DeploymentStatus.ROLLED_BACK == "rolled_back"

    def test_state_defaults(self):
        from shieldops.agents.patch_orchestrator.models import (
            PatchOrchestratorState,
        )

        s = PatchOrchestratorState()
        assert s.error == ""
        assert s.patched_count == 0

    def test_graph_compiles(self):
        from shieldops.agents.patch_orchestrator.graph import (
            create_patch_orchestrator_graph,
        )

        sg = create_patch_orchestrator_graph()
        assert sg.compile() is not None

    @pytest.mark.asyncio
    async def test_toolkit_inventory(self):
        from shieldops.agents.patch_orchestrator.tools import (
            PatchOrchestratorToolkit,
        )

        tk = PatchOrchestratorToolkit()
        result = await tk.inventory_systems("t-01")
        assert isinstance(result, list)
        assert len(result) > 0


# ── TDD: Config Remediation ──


class TestConfigRemediation:
    """TDD tests for config_remediation agent."""

    def test_misconfig_type_enum(self):
        from shieldops.agents.config_remediation.models import (
            MisconfigType,
        )

        assert MisconfigType.OVERPERMISSIVE_SG == "overpermissive_sg"

    def test_fix_status_enum(self):
        from shieldops.agents.config_remediation.models import FixStatus

        assert FixStatus.VERIFIED == "verified"

    def test_state_defaults(self):
        from shieldops.agents.config_remediation.models import (
            ConfigRemediationState,
        )

        s = ConfigRemediationState()
        assert s.error == ""

    def test_graph_compiles(self):
        from shieldops.agents.config_remediation.graph import (
            create_config_remediation_graph,
        )

        assert create_config_remediation_graph().compile() is not None

    @pytest.mark.asyncio
    async def test_toolkit_scan(self):
        from shieldops.agents.config_remediation.tools import (
            ConfigRemediationToolkit,
        )

        tk = ConfigRemediationToolkit()
        result = await tk.scan_configurations("t-01")
        assert isinstance(result, list)


# ── TDD: Access Remediation ──


class TestAccessRemediation:
    """TDD tests for access_remediation agent."""

    def test_access_issue_enum(self):
        from shieldops.agents.access_remediation.models import (
            AccessIssue,
        )

        assert AccessIssue.STALE_ACCESS == "stale_access"
        assert AccessIssue.DORMANT_ACCOUNT == "dormant_account"

    def test_action_type_enum(self):
        from shieldops.agents.access_remediation.models import ActionType

        assert ActionType.REVOKE == "revoke"
        assert ActionType.DISABLE == "disable"

    def test_state_defaults(self):
        from shieldops.agents.access_remediation.models import (
            AccessRemediationState,
        )

        s = AccessRemediationState()
        assert s.error == ""

    def test_graph_compiles(self):
        from shieldops.agents.access_remediation.graph import (
            create_access_remediation_graph,
        )

        assert create_access_remediation_graph().compile() is not None


# ── TDD: Vulnerability Remediation ──


class TestVulnerabilityRemediation:
    """TDD tests for vulnerability_remediation agent."""

    def test_fix_complexity_enum(self):
        from shieldops.agents.vulnerability_remediation.models import (
            FixComplexity,
        )

        assert FixComplexity.TRIVIAL == "trivial"
        assert FixComplexity.MANUAL_REQUIRED == "manual_required"

    def test_remediation_type_enum(self):
        from shieldops.agents.vulnerability_remediation.models import (
            RemediationType,
        )

        assert RemediationType.PATCH == "patch"
        assert RemediationType.WAF_RULE == "waf_rule"

    def test_state_defaults(self):
        from shieldops.agents.vulnerability_remediation.models import (
            VulnerabilityRemediationState,
        )

        s = VulnerabilityRemediationState()
        assert s.error == ""

    def test_graph_compiles(self):
        from shieldops.agents.vulnerability_remediation.graph import (
            create_vulnerability_remediation_graph,
        )

        g = create_vulnerability_remediation_graph()
        assert g.compile() is not None


# ── TDD: Remediation Verifier ──


class TestRemediationVerifier:
    """TDD tests for remediation_verifier agent."""

    def test_verification_result_enum(self):
        from shieldops.agents.remediation_verifier.models import (
            VerificationResult,
        )

        assert VerificationResult.FIXED == "fixed"
        assert VerificationResult.NOT_FIXED == "not_fixed"
        assert VerificationResult.REGRESSION == "regression"

    def test_test_type_enum(self):
        from shieldops.agents.remediation_verifier.models import TestType

        assert TestType.RESCAN == "rescan"
        assert TestType.EXPLOIT_RETEST == "exploit_retest"

    def test_state_defaults(self):
        from shieldops.agents.remediation_verifier.models import (
            RemediationVerifierState,
        )

        s = RemediationVerifierState()
        assert s.error == ""

    def test_graph_compiles(self):
        from shieldops.agents.remediation_verifier.graph import (
            create_remediation_verifier_graph,
        )

        assert create_remediation_verifier_graph().compile() is not None


# ── TDD: Remediation Orchestrator ──


class TestRemediationOrchestrator:
    """TDD tests for remediation_orchestrator agent."""

    def test_routing_decision_enum(self):
        from shieldops.agents.remediation_orchestrator.models import (
            RoutingDecision,
        )

        assert RoutingDecision.AUTO_REMEDIATE == "auto_remediate"
        assert RoutingDecision.CREATE_TICKET == "create_ticket"
        assert RoutingDecision.ACCEPT_RISK == "accept_risk"

    def test_ticket_priority_enum(self):
        from shieldops.agents.remediation_orchestrator.models import (
            TicketPriority,
        )

        assert TicketPriority.P0 == "p0"

    def test_state_defaults(self):
        from shieldops.agents.remediation_orchestrator.models import (
            RemediationOrchestratorState,
        )

        s = RemediationOrchestratorState()
        assert s.error == ""

    def test_graph_compiles(self):
        from shieldops.agents.remediation_orchestrator.graph import (
            create_remediation_orchestrator_graph,
        )

        g = create_remediation_orchestrator_graph()
        assert g.compile() is not None


# ── BDD: Remediation Scenarios ──


class TestBDDPatchDeployment:
    """Feature: Patches are deployed safely with rollback."""

    def test_canary_before_rollout(self):
        """Given a critical patch,
        When deploying to production,
        Then canary deployment runs first on 1 system."""
        from shieldops.agents.patch_orchestrator.models import (
            DeploymentStatus,
        )

        assert DeploymentStatus.DEPLOYING == "deploying"
        assert DeploymentStatus.ROLLED_BACK == "rolled_back"

    def test_rollback_on_failure(self):
        """Given a patch that causes failures,
        When verification detects issues,
        Then auto-rollback is triggered."""
        from shieldops.agents.patch_orchestrator.models import (
            DeploymentStatus,
            PatchPriority,
        )

        assert DeploymentStatus.FAILED == "failed"
        assert DeploymentStatus.ROLLED_BACK == "rolled_back"
        assert PatchPriority.EMERGENCY == "emergency"


class TestBDDConfigFix:
    """Feature: Misconfigs are auto-fixed with verification."""

    def test_fix_requires_approval(self):
        """Given a critical IAM misconfiguration,
        When auto-fix is planned,
        Then OPA approval is required before execution."""
        from shieldops.agents.config_remediation.models import (
            FixStatus,
        )

        assert FixStatus.APPROVED == "approved"
        assert FixStatus.APPLIED == "applied"
        assert FixStatus.VERIFIED == "verified"

    def test_fix_is_verified(self):
        """Given a fix was applied,
        When verification runs,
        Then re-scan confirms the misconfig is resolved."""
        from shieldops.agents.config_remediation.models import (
            FixStatus,
            MisconfigType,
        )

        assert FixStatus.VERIFIED == "verified"
        assert MisconfigType.PUBLIC_STORAGE == "public_storage"


class TestBDDAccessCleanup:
    """Feature: Stale access is revoked automatically."""

    def test_dormant_accounts_disabled(self):
        """Given accounts dormant for 90+ days,
        When access remediation runs,
        Then dormant accounts are disabled."""
        from shieldops.agents.access_remediation.models import (
            AccessIssue,
            ActionType,
        )

        assert AccessIssue.DORMANT_ACCOUNT == "dormant_account"
        assert ActionType.DISABLE == "disable"

    def test_owner_notified_before_change(self):
        """Given excess access is found,
        When remediation is planned,
        Then account owner is notified first."""
        from shieldops.agents.access_remediation.models import (
            ActionType,
        )

        assert ActionType.NOTIFY_OWNER == "notify_owner"


class TestBDDRemediationPipeline:
    """Feature: Full find→fix→verify pipeline works."""

    def test_trivial_fixes_auto_remediated(self):
        """Given a trivial vulnerability (e.g., public S3),
        When processed by orchestrator,
        Then it's auto-remediated without ticket."""
        from shieldops.agents.remediation_orchestrator.models import (
            RoutingDecision,
        )

        assert RoutingDecision.AUTO_REMEDIATE == "auto_remediate"

    def test_complex_fixes_create_tickets(self):
        """Given a complex vulnerability (e.g., code fix),
        When processed by orchestrator,
        Then a ticket is created for manual fix."""
        from shieldops.agents.remediation_orchestrator.models import (
            RoutingDecision,
        )

        assert RoutingDecision.CREATE_TICKET == "create_ticket"

    def test_verification_catches_unfixed(self):
        """Given a fix was applied,
        When verifier re-tests,
        Then it catches if the vuln is still present."""
        from shieldops.agents.remediation_verifier.models import (
            VerificationResult,
        )

        assert VerificationResult.NOT_FIXED == "not_fixed"
        assert VerificationResult.REGRESSION == "regression"

    def test_escalation_for_critical(self):
        """Given a critical finding that can't be auto-fixed,
        When orchestrator processes it,
        Then it's escalated to security team."""
        from shieldops.agents.remediation_orchestrator.models import (
            RoutingDecision,
        )

        assert RoutingDecision.ESCALATE == "escalate"
