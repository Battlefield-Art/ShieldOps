"""Tests for the agent framework — define_agent() factory."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Test fixtures — mock state and toolkit
# ---------------------------------------------------------------------------


class MockState(BaseModel):
    request_id: str = ""
    tenant_id: str = ""
    error: str = ""
    current_step: str = ""
    findings: list[str] = Field(default_factory=list)
    reasoning_chain: list[str] = Field(default_factory=list)
    report: str = ""


class MockToolkit:
    def __init__(self, connector: Any = None) -> None:
        self.connector = connector
        self.call_log: list[str] = []

    async def collect(self, state: dict[str, Any]) -> dict[str, Any]:
        self.call_log.append("collect")
        return {"findings": ["finding1", "finding2"]}

    async def analyze(self, state: dict[str, Any]) -> dict[str, Any]:
        self.call_log.append("analyze")
        findings = state.get("findings", [])
        return {"findings": findings + ["analysis_result"]}

    async def report(self, state: dict[str, Any]) -> dict[str, Any]:
        self.call_log.append("report")
        return {"report": f"Report with {len(state.get('findings', []))} findings"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDefineAgent:
    def test_returns_a_class(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="test_agent",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect", "analyze", "report"],
        )
        assert isinstance(Runner, type)

    def test_class_has_agent_name(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="test_agent",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect"],
        )
        assert Runner.agent_name == "test_agent"

    def test_class_has_state_and_toolkit_refs(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="test_agent",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect"],
        )
        assert Runner.state_class is MockState
        assert Runner.toolkit_class is MockToolkit

    def test_empty_nodes_raises(self) -> None:
        from shieldops.agents.framework import define_agent

        with pytest.raises(ValueError, match="At least one node"):
            define_agent(
                name="test_agent",
                state_type=MockState,
                toolkit_type=MockToolkit,
                nodes=[],
            )


class TestRunnerInstantiation:
    def test_can_instantiate(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="test_agent",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect", "analyze", "report"],
        )
        runner = Runner()
        assert runner is not None

    def test_toolkit_kwargs_forwarded(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="test_agent",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect"],
        )
        runner = Runner(connector="my_connector")
        assert runner._toolkit.connector == "my_connector"


class TestLinearExecution:
    @pytest.mark.asyncio
    async def test_executes_all_nodes_in_order(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="test_agent",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect", "analyze", "report"],
        )
        runner = Runner()
        await runner.run(tenant_id="t-1")

        # All nodes should have been called
        assert runner._toolkit.call_log == ["collect", "analyze", "report"]

    @pytest.mark.asyncio
    async def test_final_state_has_report(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="test_agent",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect", "analyze", "report"],
        )
        runner = Runner()
        result = await runner.run(tenant_id="t-1")
        assert result.report != ""

    @pytest.mark.asyncio
    async def test_reasoning_chain_built(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="test_agent",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect", "analyze", "report"],
        )
        runner = Runner()
        result = await runner.run()
        assert len(result.reasoning_chain) == 3
        assert "collect" in result.reasoning_chain[0]
        assert "analyze" in result.reasoning_chain[1]
        assert "report" in result.reasoning_chain[2]

    @pytest.mark.asyncio
    async def test_current_step_set_to_last_node(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="test_agent",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect", "analyze", "report"],
        )
        runner = Runner()
        result = await runner.run()
        assert result.current_step == "report"


class TestCustomNodes:
    @pytest.mark.asyncio
    async def test_custom_node_function_called(self) -> None:
        from shieldops.agents.framework import define_agent

        custom_called = []

        async def custom_step(state: Any) -> dict[str, Any]:
            custom_called.append(True)
            return {"findings": ["custom_finding"]}

        Runner = define_agent(
            name="test_agent",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect", ("custom", custom_step), "report"],
        )
        runner = Runner()
        await runner.run()
        assert len(custom_called) == 1


class TestConditionalEdges:
    @pytest.mark.asyncio
    async def test_edge_routes_correctly(self) -> None:
        from shieldops.agents.framework import Edge, define_agent

        class BranchState(BaseModel):
            request_id: str = ""
            error: str = ""
            current_step: str = ""
            reasoning_chain: list[str] = Field(default_factory=list)
            findings: list[str] = Field(default_factory=list)
            should_remediate: bool = False
            remediated: bool = False
            report: str = ""

        class BranchToolkit:
            async def detect(self, state: dict[str, Any]) -> dict[str, Any]:
                return {"should_remediate": True}

            async def remediate(self, state: dict[str, Any]) -> dict[str, Any]:
                return {"remediated": True}

            async def report(self, state: dict[str, Any]) -> dict[str, Any]:
                return {"report": "done"}

        Runner = define_agent(
            name="branch_test",
            state_type=BranchState,
            toolkit_type=BranchToolkit,
            nodes=["detect", "remediate", "report"],
            edges=[
                Edge(
                    after="detect",
                    condition=lambda s: "remediate" if s.get("should_remediate") else "report",
                    routes={"remediate": "remediate", "report": "report"},
                ),
            ],
        )
        runner = Runner()
        result = await runner.run()
        assert result.remediated is True


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_exception_sets_error(self) -> None:
        from shieldops.agents.framework import define_agent

        class FailToolkit:
            async def fail_step(self, state: dict[str, Any]) -> dict[str, Any]:
                raise RuntimeError("boom")

        Runner = define_agent(
            name="fail_agent",
            state_type=MockState,
            toolkit_type=FailToolkit,
            nodes=["fail_step"],
        )
        runner = Runner()
        result = await runner.run()
        assert "boom" in result.error
        assert result.current_step == "failed"


class TestResultCaching:
    @pytest.mark.asyncio
    async def test_get_result_after_run(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="cache_test",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect"],
        )
        runner = Runner()
        await runner.run()

        # Find the session ID
        results = runner.list_results()
        assert len(results) == 1
        sid = results[0]["session_id"]

        cached = runner.get_result(sid)
        assert cached is not None

    @pytest.mark.asyncio
    async def test_get_result_missing(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="cache_test",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect"],
        )
        runner = Runner()
        assert runner.get_result("nonexistent") is None

    @pytest.mark.asyncio
    async def test_list_results_multiple(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="cache_test",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect"],
        )
        runner = Runner()
        await runner.run()
        await runner.run()
        assert len(runner.list_results()) == 2


class TestStateValidation:
    @pytest.mark.asyncio
    async def test_request_id_auto_generated(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="id_test",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect"],
        )
        runner = Runner()
        result = await runner.run()
        assert result.request_id.startswith("id_test-")

    @pytest.mark.asyncio
    async def test_custom_kwargs_passed_to_state(self) -> None:
        from shieldops.agents.framework import define_agent

        Runner = define_agent(
            name="kwargs_test",
            state_type=MockState,
            toolkit_type=MockToolkit,
            nodes=["collect"],
        )
        runner = Runner()
        result = await runner.run(tenant_id="org-42")
        assert result.tenant_id == "org-42"
