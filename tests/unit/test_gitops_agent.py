"""Tests for the GitOps Agent module.

Covers:
- GitOpsState model creation, defaults, and field types
- DriftItem model construction and severity defaults
- ReconciliationPlan model construction and defaults
- ApplyResult model construction and defaults
- ReconciliationStage, DriftType, ReconciliationAction enum values
- GitOpsToolkit methods (detect_drift, generate_reconciliation_plan,
  apply_changes, verify_deployment, get_change_history)
- Node functions (detect_drift, plan_reconciliation, apply_reconciliation,
  verify_and_report)
- GitOpsRunner.run() with mocked graph
- GitOpsRunner.get_reconciliation(), list_reconciliations()
- Graph conditional routing (needs_approval)
- Edge cases: empty drift, dry_run, approval required, error handling
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.agents.gitops.graph import needs_approval
from shieldops.agents.gitops.models import (
    ApplyResult,
    DriftItem,
    DriftType,
    GitOpsState,
    ReconciliationAction,
    ReconciliationPlan,
    ReconciliationStage,
)
from shieldops.agents.gitops.nodes import (
    _get_toolkit,
    apply_reconciliation,
    detect_drift,
    plan_reconciliation,
    set_toolkit,
    verify_and_report,
)
from shieldops.agents.gitops.runner import GitOpsRunner
from shieldops.agents.gitops.tools import GitOpsToolkit

# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_toolkit():
    """Reset the module-level toolkit singleton between tests."""
    import shieldops.agents.gitops.nodes as nodes_mod

    original = nodes_mod._toolkit
    nodes_mod._toolkit = None
    yield
    nodes_mod._toolkit = original


@pytest.fixture
def sample_drift_item() -> DriftItem:
    return DriftItem(
        resource_id="default/nginx-deployment",
        resource_type="Deployment",
        drift_type=DriftType.CONFIG_DRIFT,
        expected_value='{"replicas": 3}',
        actual_value='{"replicas": 2}',
        severity="medium",
        namespace="default",
    )


@pytest.fixture
def sample_drift_item_critical() -> DriftItem:
    return DriftItem(
        resource_id="kube-system/coredns",
        resource_type="Deployment",
        drift_type=DriftType.POLICY_DRIFT,
        expected_value='{"securityContext": {"runAsNonRoot": true}}',
        actual_value='{"securityContext": {"runAsNonRoot": false}}',
        severity="critical",
        namespace="kube-system",
    )


@pytest.fixture
def sample_plan(sample_drift_item: DriftItem) -> ReconciliationPlan:
    return ReconciliationPlan(
        items=[sample_drift_item],
        actions=[ReconciliationAction.UPDATE],
        estimated_risk=0.3,
        requires_approval=False,
    )


@pytest.fixture
def sample_apply_result() -> ApplyResult:
    return ApplyResult(
        resource_id="default/nginx-deployment",
        action=ReconciliationAction.UPDATE,
        success=True,
        duration_seconds=1.5,
        rollback_available=True,
    )


@pytest.fixture
def base_state() -> GitOpsState:
    return GitOpsState(
        request_id="gitops-test123",
        repo_url="https://github.com/org/infra",
        branch="main",
        namespace="default",
        dry_run=True,
    )


# ── Enum tests ───────────────────────────────────────────────────


class TestEnums:
    def test_reconciliation_stage_values(self):
        assert ReconciliationStage.DETECT_DRIFT == "detect_drift"
        assert ReconciliationStage.PLAN == "plan"
        assert ReconciliationStage.APPLY == "apply"
        assert ReconciliationStage.VERIFY == "verify"
        assert ReconciliationStage.REPORT == "report"

    def test_drift_type_values(self):
        assert DriftType.CONFIG_DRIFT == "config_drift"
        assert DriftType.RESOURCE_DRIFT == "resource_drift"
        assert DriftType.POLICY_DRIFT == "policy_drift"
        assert DriftType.SECRET_DRIFT == "secret_drift"
        assert DriftType.VERSION_DRIFT == "version_drift"

    def test_reconciliation_action_values(self):
        assert ReconciliationAction.CREATE == "create"
        assert ReconciliationAction.UPDATE == "update"
        assert ReconciliationAction.DELETE == "delete"
        assert ReconciliationAction.ROLLBACK == "rollback"
        assert ReconciliationAction.NO_OP == "no_op"


# ── Model tests ──────────────────────────────────────────────────


class TestDriftItem:
    def test_construction(self, sample_drift_item: DriftItem):
        assert sample_drift_item.resource_id == "default/nginx-deployment"
        assert sample_drift_item.resource_type == "Deployment"
        assert sample_drift_item.drift_type == DriftType.CONFIG_DRIFT
        assert sample_drift_item.severity == "medium"
        assert sample_drift_item.namespace == "default"

    def test_defaults(self):
        item = DriftItem(
            resource_id="test/pod",
            resource_type="Pod",
            drift_type=DriftType.RESOURCE_DRIFT,
            expected_value="desired",
            actual_value="actual",
        )
        assert item.severity == "medium"
        assert item.namespace == ""


class TestReconciliationPlan:
    def test_construction(self, sample_plan: ReconciliationPlan):
        assert len(sample_plan.items) == 1
        assert len(sample_plan.actions) == 1
        assert sample_plan.estimated_risk == 0.3
        assert sample_plan.requires_approval is False

    def test_defaults(self):
        plan = ReconciliationPlan()
        assert plan.items == []
        assert plan.actions == []
        assert plan.estimated_risk == 0.0
        assert plan.requires_approval is False


class TestApplyResult:
    def test_construction(self, sample_apply_result: ApplyResult):
        assert sample_apply_result.resource_id == "default/nginx-deployment"
        assert sample_apply_result.action == ReconciliationAction.UPDATE
        assert sample_apply_result.success is True
        assert sample_apply_result.duration_seconds == 1.5
        assert sample_apply_result.rollback_available is True
        assert sample_apply_result.error is None

    def test_failed_result(self):
        result = ApplyResult(
            resource_id="test/pod",
            action=ReconciliationAction.CREATE,
            success=False,
            error="Resource quota exceeded",
        )
        assert result.success is False
        assert result.error == "Resource quota exceeded"
        assert result.rollback_available is False


class TestGitOpsState:
    def test_defaults(self):
        state = GitOpsState()
        assert state.request_id == ""
        assert state.repo_url == ""
        assert state.branch == "main"
        assert state.namespace == ""
        assert state.dry_run is True
        assert state.stage == ReconciliationStage.DETECT_DRIFT
        assert state.drift_items == []
        assert state.plan is None
        assert state.apply_results == []
        assert state.verification_passed is None
        assert state.change_summary == ""
        assert state.confidence_score == 0.0
        assert state.reasoning_chain == []
        assert state.error is None
        assert state.current_step == "init"

    def test_construction(self, base_state: GitOpsState):
        assert base_state.request_id == "gitops-test123"
        assert base_state.repo_url == "https://github.com/org/infra"
        assert base_state.branch == "main"
        assert base_state.namespace == "default"
        assert base_state.dry_run is True


# ── Toolkit tests ────────────────────────────────────────────────


class TestGitOpsToolkit:
    def test_construction_no_args(self):
        toolkit = GitOpsToolkit()
        assert toolkit._router is None
        assert toolkit._repository is None

    @pytest.mark.asyncio
    async def test_detect_drift_no_router(self):
        toolkit = GitOpsToolkit()
        result = await toolkit.detect_drift("https://github.com/org/repo")
        assert result == []

    @pytest.mark.asyncio
    async def test_detect_drift_with_router(self):
        mock_connector = AsyncMock()
        mock_router = MagicMock()
        mock_router.get.return_value = mock_connector

        toolkit = GitOpsToolkit(connector_router=mock_router)
        # Patch internal methods to return test data
        toolkit._fetch_desired_state = AsyncMock(
            return_value={
                "nginx": {"kind": "Deployment", "replicas": 3},
            }
        )
        toolkit._fetch_actual_state = AsyncMock(
            return_value={
                "nginx": {"kind": "Deployment", "replicas": 2},
            }
        )

        result = await toolkit.detect_drift("https://github.com/org/repo", namespace="default")
        assert len(result) == 1
        assert result[0].resource_id == "nginx"
        assert result[0].drift_type == DriftType.CONFIG_DRIFT

    @pytest.mark.asyncio
    async def test_generate_plan_empty(self):
        toolkit = GitOpsToolkit()
        plan = await toolkit.generate_reconciliation_plan([])
        assert plan.items == []
        assert plan.actions == []
        assert plan.estimated_risk == 0.0
        assert plan.requires_approval is False

    @pytest.mark.asyncio
    async def test_generate_plan_with_items(self, sample_drift_item: DriftItem):
        toolkit = GitOpsToolkit()
        plan = await toolkit.generate_reconciliation_plan([sample_drift_item])
        assert len(plan.actions) == 1
        assert plan.actions[0] == ReconciliationAction.UPDATE
        assert plan.estimated_risk > 0.0

    @pytest.mark.asyncio
    async def test_generate_plan_requires_approval_for_delete(self):
        toolkit = GitOpsToolkit()
        item = DriftItem(
            resource_id="default/orphan-svc",
            resource_type="Service",
            drift_type=DriftType.RESOURCE_DRIFT,
            expected_value="<should_not_exist>",
            actual_value='{"kind": "Service"}',
            namespace="default",
        )
        plan = await toolkit.generate_reconciliation_plan([item])
        assert ReconciliationAction.DELETE in plan.actions
        assert plan.requires_approval is True

    @pytest.mark.asyncio
    async def test_generate_plan_requires_approval_for_secrets(self):
        toolkit = GitOpsToolkit()
        item = DriftItem(
            resource_id="default/db-secret",
            resource_type="Secret",
            drift_type=DriftType.SECRET_DRIFT,
            expected_value="new_value",
            actual_value="old_value",
            namespace="default",
        )
        plan = await toolkit.generate_reconciliation_plan([item])
        assert plan.requires_approval is True

    @pytest.mark.asyncio
    async def test_apply_changes_dry_run(self, sample_plan: ReconciliationPlan):
        toolkit = GitOpsToolkit()
        results = await toolkit.apply_changes(sample_plan, dry_run=True)
        assert len(results) == 1
        assert results[0].success is True
        assert results[0].rollback_available is True

    @pytest.mark.asyncio
    async def test_apply_changes_no_op(self):
        toolkit = GitOpsToolkit()
        item = DriftItem(
            resource_id="test/pod",
            resource_type="Pod",
            drift_type=DriftType.CONFIG_DRIFT,
            expected_value="same",
            actual_value="same",
        )
        plan = ReconciliationPlan(
            items=[item],
            actions=[ReconciliationAction.NO_OP],
        )
        results = await toolkit.apply_changes(plan, dry_run=False)
        assert len(results) == 1
        assert results[0].success is True
        assert results[0].action == ReconciliationAction.NO_OP

    @pytest.mark.asyncio
    async def test_verify_deployment_empty(self):
        toolkit = GitOpsToolkit()
        result = await toolkit.verify_deployment([])
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_deployment_all_success(self, sample_apply_result: ApplyResult):
        toolkit = GitOpsToolkit()
        result = await toolkit.verify_deployment([sample_apply_result])
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_deployment_with_failure(self):
        toolkit = GitOpsToolkit()
        failed = ApplyResult(
            resource_id="test/pod",
            action=ReconciliationAction.CREATE,
            success=False,
            error="failed",
        )
        result = await toolkit.verify_deployment([failed])
        assert result is False

    @pytest.mark.asyncio
    async def test_get_change_history_no_repo(self):
        toolkit = GitOpsToolkit()
        result = await toolkit.get_change_history("default")
        assert result == []

    @pytest.mark.asyncio
    async def test_get_change_history_with_repo(self):
        mock_repo = AsyncMock()
        mock_repo.get_change_history.return_value = [
            {"id": "chg-1", "namespace": "default"},
        ]
        toolkit = GitOpsToolkit(repository=mock_repo)
        result = await toolkit.get_change_history("default", limit=5)
        assert len(result) == 1
        mock_repo.get_change_history.assert_awaited_once_with(
            namespace="default",
            limit=5,
        )

    def test_determine_action_missing_resource(self):
        item = DriftItem(
            resource_id="test/pod",
            resource_type="Pod",
            drift_type=DriftType.RESOURCE_DRIFT,
            expected_value="desired",
            actual_value="<missing>",
        )
        assert GitOpsToolkit._determine_action(item) == ReconciliationAction.CREATE

    def test_determine_action_extra_resource(self):
        item = DriftItem(
            resource_id="test/pod",
            resource_type="Pod",
            drift_type=DriftType.RESOURCE_DRIFT,
            expected_value="<should_not_exist>",
            actual_value="actual",
        )
        assert GitOpsToolkit._determine_action(item) == ReconciliationAction.DELETE

    def test_determine_action_version_drift(self):
        item = DriftItem(
            resource_id="test/pod",
            resource_type="Pod",
            drift_type=DriftType.VERSION_DRIFT,
            expected_value="v1.2.0",
            actual_value="v1.1.0",
        )
        assert GitOpsToolkit._determine_action(item) == ReconciliationAction.ROLLBACK

    def test_determine_action_config_drift(self, sample_drift_item: DriftItem):
        assert GitOpsToolkit._determine_action(sample_drift_item) == ReconciliationAction.UPDATE

    def test_assess_item_risk_no_op(self, sample_drift_item: DriftItem):
        risk = GitOpsToolkit._assess_item_risk(sample_drift_item, ReconciliationAction.NO_OP)
        assert risk == 0.0

    def test_assess_item_risk_delete(self, sample_drift_item: DriftItem):
        risk = GitOpsToolkit._assess_item_risk(sample_drift_item, ReconciliationAction.DELETE)
        assert risk >= 0.8

    def test_assess_item_risk_secret_drift(self):
        item = DriftItem(
            resource_id="test/secret",
            resource_type="Secret",
            drift_type=DriftType.SECRET_DRIFT,
            expected_value="new",
            actual_value="old",
        )
        risk = GitOpsToolkit._assess_item_risk(item, ReconciliationAction.UPDATE)
        assert risk >= 0.6  # base 0.3 + secret 0.3

    def test_assess_item_risk_critical_severity(self, sample_drift_item_critical: DriftItem):
        risk = GitOpsToolkit._assess_item_risk(
            sample_drift_item_critical,
            ReconciliationAction.UPDATE,
        )
        assert risk >= 0.5  # base 0.3 + policy 0.2 + critical 0.2 = 0.7


# ── Node tests ───────────────────────────────────────────────────


class TestNodes:
    def test_get_toolkit_returns_default(self):
        toolkit = _get_toolkit()
        assert isinstance(toolkit, GitOpsToolkit)

    def test_set_toolkit(self):
        custom = GitOpsToolkit()
        set_toolkit(custom)
        assert _get_toolkit() is custom

    @pytest.mark.asyncio
    async def test_detect_drift_node(self, base_state: GitOpsState):
        mock_toolkit = MagicMock(spec=GitOpsToolkit)
        mock_toolkit.detect_drift = AsyncMock(return_value=[])
        set_toolkit(mock_toolkit)

        result = await detect_drift(base_state)
        assert result["drift_items"] == []
        assert result["stage"] == ReconciliationStage.PLAN
        assert result["current_step"] == "detect_drift"
        assert len(result["reasoning_chain"]) == 1

    @pytest.mark.asyncio
    async def test_detect_drift_node_with_items(
        self,
        base_state: GitOpsState,
        sample_drift_item: DriftItem,
    ):
        mock_toolkit = MagicMock(spec=GitOpsToolkit)
        mock_toolkit.detect_drift = AsyncMock(return_value=[sample_drift_item])
        set_toolkit(mock_toolkit)

        result = await detect_drift(base_state)
        assert len(result["drift_items"]) == 1
        assert result["started_at"] is not None

    @pytest.mark.asyncio
    async def test_plan_reconciliation_node(
        self,
        base_state: GitOpsState,
        sample_drift_item: DriftItem,
    ):
        base_state.drift_items = [sample_drift_item]

        mock_toolkit = MagicMock(spec=GitOpsToolkit)
        mock_plan = ReconciliationPlan(
            items=[sample_drift_item],
            actions=[ReconciliationAction.UPDATE],
            estimated_risk=0.3,
            requires_approval=False,
        )
        mock_toolkit.generate_reconciliation_plan = AsyncMock(return_value=mock_plan)
        set_toolkit(mock_toolkit)

        result = await plan_reconciliation(base_state)
        assert result["plan"] is not None
        assert result["plan"].estimated_risk == 0.3
        assert result["stage"] == ReconciliationStage.APPLY
        assert result["confidence_score"] == pytest.approx(0.7)

    @pytest.mark.asyncio
    async def test_apply_reconciliation_node(
        self,
        base_state: GitOpsState,
        sample_plan: ReconciliationPlan,
    ):
        base_state.plan = sample_plan

        mock_toolkit = MagicMock(spec=GitOpsToolkit)
        mock_result = ApplyResult(
            resource_id="default/nginx-deployment",
            action=ReconciliationAction.UPDATE,
            success=True,
            duration_seconds=1.0,
            rollback_available=True,
        )
        mock_toolkit.apply_changes = AsyncMock(return_value=[mock_result])
        set_toolkit(mock_toolkit)

        result = await apply_reconciliation(base_state)
        assert len(result["apply_results"]) == 1
        assert result["apply_results"][0].success is True
        assert result["stage"] == ReconciliationStage.VERIFY

    @pytest.mark.asyncio
    async def test_apply_reconciliation_no_plan(self, base_state: GitOpsState):
        base_state.plan = None
        result = await apply_reconciliation(base_state)
        assert result["error"] == "No reconciliation plan available"

    @pytest.mark.asyncio
    async def test_verify_and_report_node(
        self,
        base_state: GitOpsState,
        sample_apply_result: ApplyResult,
    ):
        base_state.apply_results = [sample_apply_result]
        base_state.started_at = datetime.now(UTC)

        mock_toolkit = MagicMock(spec=GitOpsToolkit)
        mock_toolkit.verify_deployment = AsyncMock(return_value=True)
        set_toolkit(mock_toolkit)

        result = await verify_and_report(base_state)
        assert result["verification_passed"] is True
        assert "Completed" in result["change_summary"]
        assert result["stage"] == ReconciliationStage.REPORT
        assert result["current_step"] == "complete"

    @pytest.mark.asyncio
    async def test_verify_and_report_failed(
        self,
        base_state: GitOpsState,
        sample_apply_result: ApplyResult,
    ):
        base_state.apply_results = [sample_apply_result]
        base_state.started_at = datetime.now(UTC)

        mock_toolkit = MagicMock(spec=GitOpsToolkit)
        mock_toolkit.verify_deployment = AsyncMock(return_value=False)
        set_toolkit(mock_toolkit)

        result = await verify_and_report(base_state)
        assert result["verification_passed"] is False
        assert "Failed" in result["change_summary"]


# ── Graph routing tests ──────────────────────────────────────────


class TestGraphRouting:
    def test_needs_approval_no_drift(self, base_state: GitOpsState):
        base_state.drift_items = []
        assert needs_approval(base_state) == "__end__"

    def test_needs_approval_true(
        self,
        base_state: GitOpsState,
        sample_drift_item: DriftItem,
    ):
        base_state.drift_items = [sample_drift_item]
        base_state.plan = ReconciliationPlan(
            items=[sample_drift_item],
            actions=[ReconciliationAction.UPDATE],
            estimated_risk=0.8,
            requires_approval=True,
        )
        assert needs_approval(base_state) == "__end__"

    def test_needs_approval_false(
        self,
        base_state: GitOpsState,
        sample_drift_item: DriftItem,
    ):
        base_state.drift_items = [sample_drift_item]
        base_state.plan = ReconciliationPlan(
            items=[sample_drift_item],
            actions=[ReconciliationAction.UPDATE],
            estimated_risk=0.2,
            requires_approval=False,
        )
        assert needs_approval(base_state) == "apply_reconciliation"


# ── Runner tests ─────────────────────────────────────────────────


class TestGitOpsRunner:
    @pytest.mark.asyncio
    async def test_run_basic(self):
        with patch("shieldops.agents.gitops.runner.create_gitops_graph") as mock_graph_fn:
            mock_compiled = AsyncMock()
            mock_compiled.ainvoke.return_value = GitOpsState(
                request_id="gitops-test",
                repo_url="https://github.com/org/infra",
                branch="main",
                namespace="default",
                dry_run=True,
                current_step="complete",
                started_at=datetime.now(UTC),
            ).model_dump()

            mock_graph = MagicMock()
            mock_graph.compile.return_value = mock_compiled
            mock_graph_fn.return_value = mock_graph

            runner = GitOpsRunner()
            result = await runner.run(
                repo_url="https://github.com/org/infra",
                branch="main",
                namespace="default",
                dry_run=True,
            )

            assert result.current_step == "complete"
            assert result.repo_url == "https://github.com/org/infra"

    @pytest.mark.asyncio
    async def test_run_error_handling(self):
        with patch("shieldops.agents.gitops.runner.create_gitops_graph") as mock_graph_fn:
            mock_compiled = AsyncMock()
            mock_compiled.ainvoke.side_effect = RuntimeError("Connection failed")

            mock_graph = MagicMock()
            mock_graph.compile.return_value = mock_compiled
            mock_graph_fn.return_value = mock_graph

            runner = GitOpsRunner()
            result = await runner.run(
                repo_url="https://github.com/org/infra",
            )

            assert result.current_step == "failed"
            assert result.error == "Connection failed"

    def test_get_reconciliation(self):
        with patch("shieldops.agents.gitops.runner.create_gitops_graph") as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = MagicMock()
            mock_graph_fn.return_value = mock_graph

            runner = GitOpsRunner()
            assert runner.get_reconciliation("nonexistent") is None

            state = GitOpsState(request_id="test-123")
            runner._reconciliations["test-123"] = state
            assert runner.get_reconciliation("test-123") is state

    def test_list_reconciliations(self):
        with patch("shieldops.agents.gitops.runner.create_gitops_graph") as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = MagicMock()
            mock_graph_fn.return_value = mock_graph

            runner = GitOpsRunner()
            assert runner.list_reconciliations() == []

            runner._reconciliations["req-1"] = GitOpsState(
                request_id="req-1",
                repo_url="https://github.com/org/infra",
                namespace="prod",
                current_step="complete",
            )

            listing = runner.list_reconciliations()
            assert len(listing) == 1
            assert listing[0]["request_id"] == "req-1"
            assert listing[0]["repo_url"] == "https://github.com/org/infra"
            assert listing[0]["namespace"] == "prod"
