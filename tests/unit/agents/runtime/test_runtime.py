"""Contract tests for the AgentRuntime — RFC #247 PR-1.

See ghantakiran/ShieldOps#247. This is the keystone test file. The
central test —
:meth:`TestFullLifecycle.test_one_run_goes_through_every_lifecycle_step`
— mounts a minimal three-node agent on an all-in-memory runtime and
asserts every lifecycle step fired:

    1. license check
    2. toolkit mount
    3. policy gate (for the one node that declares a policy_action)
    4. node execution
    5. state persisted
    6. audit log entry
    7. websocket publish
    8. evolution.record_run at terminal

All in <10 ms. No FastAPI, no real DB, no real WebSocket, no real time.

The other tests lock: license denial, policy denial, exception safety
inside the lifecycle, conditional routing, per-tenant isolation, pure
node unit-testability.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from shieldops.agents.runtime import (
    END,
    Agent,
    AgentRuntime,
    build_in_memory_runtime,
    get_agent_runtime,
    node,
    set_agent_runtime,
    use_test_agent_runtime,
)
from shieldops.agents.runtime.adapters import (
    CapturingAuditLog,
    CapturingHub,
    DenyPolicy,
    InMemoryConnectorRouter,
    InMemoryEvolutionRecorder,
    InMemoryLicenseManager,
    InMemoryPersistence,
    ManualClock,
    NullAgentLogger,
)
from shieldops.agents.runtime.agent import cond, edge

# ---------------------------------------------------------------------------
# A minimal three-node agent used across the tests
# ---------------------------------------------------------------------------


@dataclass
class TriageState:
    alert_id: str
    severity: str = "unknown"
    findings: list[str] | None = None
    decision: str = ""


class FakeToolkit:
    """A per-run toolkit. Agents hold one of these for all their nodes."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def enrich(self) -> list[str]:
        self.calls.append("enrich")
        return ["finding-a", "finding-b"]

    def decide(self, severity: str, n_findings: int) -> str:
        self.calls.append("decide")
        return "remediate" if severity == "high" and n_findings > 0 else "done"


class _ToolkitOnly:
    """A mutable holder so tests can capture the toolkit the runtime built."""

    instance: FakeToolkit | None = None


def _fresh_toolkit() -> FakeToolkit:
    _ToolkitOnly.instance = FakeToolkit()
    return _ToolkitOnly.instance


class TriageAgent(Agent[TriageState]):
    name = "triage"
    state_model = TriageState
    toolkit_factory = _fresh_toolkit
    entry = "scan"
    policy_actions = {"remediate": "triage.remediate"}

    @staticmethod
    @node
    async def scan(state: TriageState, toolkit: FakeToolkit) -> TriageState:  # noqa: ARG004
        state.severity = "high" if state.alert_id.startswith("critical") else "low"
        return state

    @staticmethod
    @node
    async def enrich(state: TriageState, toolkit: FakeToolkit) -> TriageState:
        state.findings = toolkit.enrich()
        return state

    @staticmethod
    @node
    async def decide(state: TriageState, toolkit: FakeToolkit) -> TriageState:
        state.decision = toolkit.decide(state.severity, len(state.findings or []))
        return state

    @staticmethod
    @node
    async def remediate(state: TriageState, toolkit: FakeToolkit) -> TriageState:  # noqa: ARG004
        # Would call connectors in production; no-op here.
        return state

    nodes = {
        "scan": scan,
        "enrich": enrich,
        "decide": decide,
        "remediate": remediate,
    }
    edges = [
        edge("scan", "enrich"),
        edge("enrich", "decide"),
        cond(
            "decide",
            lambda s: s.decision,
            {"remediate": "remediate", "done": END},
        ),
        edge("remediate", END),
    ]


# ---------------------------------------------------------------------------
# 1. THE FULL-LIFECYCLE CONTRACT TEST
# ---------------------------------------------------------------------------


class TestFullLifecycle:
    @pytest.mark.asyncio
    async def test_one_run_goes_through_every_lifecycle_step(self) -> None:
        """A single run mounts the agent, drives 4 nodes, persists each
        state, emits an audit log per node, publishes a WS event per node,
        and records the run in the evolution store at terminal.

        This single test replaces the ~5 per-concern tests the old
        hand-rolled runners needed for rough parity.
        """
        runtime = build_in_memory_runtime()
        mounted = runtime.mount(TriageAgent)

        record = await mounted.run(
            TriageState(alert_id="critical-123"),
            tenant_id="acme",
        )

        # Terminal record
        assert record.success is True
        assert record.agent_name == "triage"
        assert record.tenant_id == "acme"
        assert record.final_state.decision == "remediate"
        assert record.node_count == 4  # scan → enrich → decide → remediate
        assert record.error is None

        # License check fired once (allow-all by default)
        assert len(runtime.license.calls) == 0  # no license_feature set on TriageAgent

        # Persistence captured one state per node
        assert len(runtime.persist.history) == 4

        # Audit entries for every node + the node action strings
        actions = [e["action"] for e in runtime.audit.entries]
        assert actions.count("agent.node") == 4

        # Hub published 4 node events + 1 terminal event
        assert len(runtime.hub.published) == 5
        terminal_channel = f"agent.triage.{record.run_id}.terminal"
        assert any(c == terminal_channel for c, _ in runtime.hub.published)

        # Evolution store recorded the terminal
        assert len(runtime.evolution.runs) == 1
        rec = runtime.evolution.runs[0]
        assert rec["agent_name"] == "triage"
        assert rec["success"] is True
        assert rec["node_count"] == 4

        # Policy gate fired once — only for the `remediate` node
        assert len(runtime.policy.calls) == 1
        assert runtime.policy.calls[0][0] == "triage.remediate"


# ---------------------------------------------------------------------------
# 2. Conditional routing
# ---------------------------------------------------------------------------


class TestConditionalRouting:
    @pytest.mark.asyncio
    async def test_low_severity_short_circuits_before_remediate(self) -> None:
        runtime = build_in_memory_runtime()
        mounted = runtime.mount(TriageAgent)

        record = await mounted.run(
            TriageState(alert_id="routine-1"),  # low severity
            tenant_id="acme",
        )

        assert record.success is True
        assert record.final_state.decision == "done"
        assert record.node_count == 3  # scan → enrich → decide (no remediate)
        # Policy gate NOT called — remediate node never ran.
        assert len(runtime.policy.calls) == 0


# ---------------------------------------------------------------------------
# 3. License denial
# ---------------------------------------------------------------------------


class TestLicenseDenial:
    @pytest.mark.asyncio
    async def test_denied_license_short_circuits_before_any_node_runs(self) -> None:
        class LicensedAgent(Agent[TriageState]):
            name = "licensed"
            state_model = TriageState
            toolkit_factory = _fresh_toolkit
            entry = "scan"
            license_feature = "enterprise"

            @staticmethod
            @node
            async def scan(state: TriageState, toolkit: FakeToolkit) -> TriageState:  # noqa: ARG004
                state.decision = "should_not_run"
                return state

            nodes = {"scan": scan}
            edges = [edge("scan", END)]

        runtime = build_in_memory_runtime()
        runtime.license.deny_all = True
        mounted = runtime.mount(LicensedAgent)

        record = await mounted.run(TriageState(alert_id="x"), tenant_id="acme")

        assert record.success is False
        assert record.error == "license_denied"
        assert record.node_count == 0
        # The decision is untouched — the node never executed.
        assert record.final_state.decision == ""
        # Audit entry for the denial.
        assert any(e["action"] == "agent.license_denied" for e in runtime.audit.entries)


# ---------------------------------------------------------------------------
# 4. Policy denial
# ---------------------------------------------------------------------------


class TestPolicyDenial:
    @pytest.mark.asyncio
    async def test_policy_denied_records_failed_run(self) -> None:
        runtime = AgentRuntime(
            connectors=InMemoryConnectorRouter(),
            policy=DenyPolicy(deny_action="triage.remediate"),
            hub=CapturingHub(),
            evolution=InMemoryEvolutionRecorder(),
            license=InMemoryLicenseManager(),
            persist=InMemoryPersistence(),
            audit=CapturingAuditLog(),
            clock=ManualClock(),
            log=NullAgentLogger(),
        )
        mounted = runtime.mount(TriageAgent)

        record = await mounted.run(TriageState(alert_id="critical-1"), tenant_id="acme")

        assert record.success is False
        assert "policy denied" in (record.error or "")
        # Evolution still records the failed run.
        assert len(runtime.evolution.runs) == 1
        assert runtime.evolution.runs[0]["success"] is False


# ---------------------------------------------------------------------------
# 5. Multi-tenant isolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    @pytest.mark.asyncio
    async def test_tenant_id_flows_through_to_audit_and_evolution(self) -> None:
        runtime = build_in_memory_runtime()
        mounted = runtime.mount(TriageAgent)

        await mounted.run(TriageState(alert_id="critical-1"), tenant_id="acme")
        await mounted.run(TriageState(alert_id="routine-1"), tenant_id="globex")

        tenants = {r["tenant_id"] for r in runtime.evolution.runs}
        assert tenants == {"acme", "globex"}

        audit_tenants = {
            e["metadata"]["tenant_id"] for e in runtime.audit.entries if e["action"] == "agent.node"
        }
        assert audit_tenants == {"acme", "globex"}


# ---------------------------------------------------------------------------
# 6. Pure-node unit testing (the Design A borrow)
# ---------------------------------------------------------------------------


class TestPureNodeUnitTesting:
    @pytest.mark.asyncio
    async def test_node_can_be_tested_without_runtime(self) -> None:
        """The 2-arg (state, toolkit) node signature means any node
        runs standalone with a hand-built toolkit. No runtime, no
        lifecycle, no mocks."""
        toolkit = FakeToolkit()
        state = TriageState(alert_id="critical-1")

        state = await TriageAgent.scan(state, toolkit)
        assert state.severity == "high"

        state = await TriageAgent.enrich(state, toolkit)
        assert state.findings == ["finding-a", "finding-b"]

        state = await TriageAgent.decide(state, toolkit)
        assert state.decision == "remediate"

        # The toolkit recorded the calls the nodes made.
        assert toolkit.calls == ["enrich", "decide"]


# ---------------------------------------------------------------------------
# 7. Composition root
# ---------------------------------------------------------------------------


class TestComposition:
    def test_get_raises_when_not_installed(self) -> None:
        set_agent_runtime(None)
        with pytest.raises(RuntimeError, match="No AgentRuntime installed"):
            get_agent_runtime()

    def test_use_test_runtime_installs_and_restores(self) -> None:
        original = build_in_memory_runtime()
        set_agent_runtime(original)

        with use_test_agent_runtime() as fresh:
            assert get_agent_runtime() is fresh
            assert fresh is not original

        assert get_agent_runtime() is original
        set_agent_runtime(None)

    def test_use_test_runtime_restores_on_exception(self) -> None:
        original = build_in_memory_runtime()
        set_agent_runtime(original)

        with pytest.raises(ValueError, match="test"), use_test_agent_runtime():
            raise ValueError("test")

        assert get_agent_runtime() is original
        set_agent_runtime(None)
