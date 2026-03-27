"""LangGraph workflow for the Web App Scanner Agent."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.web_app_scanner.models import (
    WebAppScannerState,
)
from shieldops.agents.web_app_scanner.nodes import (
    crawl_application,
    discover_endpoints,
    generate_report,
    test_access_control,
    test_authentication,
    test_injection,
)
from shieldops.agents.web_app_scanner.tools import (
    WebAppScannerToolkit,
)

_AGENT = "web_app_scanner"


def _has_injection_findings(
    state: WebAppScannerState,
) -> str:
    """Route based on injection findings."""
    if state.error:
        return "generate_report"
    if state.injection_findings:
        return "test_authentication"
    return "test_access_control"


def build_graph(
    toolkit: WebAppScannerToolkit,
) -> StateGraph:
    """Build the web app scanner LangGraph workflow.

    Workflow:
        discover_endpoints -> crawl_application
            -> test_injection
            -> [findings? -> test_authentication]
            -> test_access_control
            -> generate_report -> END
    """
    graph = StateGraph(WebAppScannerState)

    async def _discover(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await discover_endpoints(state, toolkit)

    async def _crawl(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await crawl_application(state, toolkit)

    async def _injection(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await test_injection(state, toolkit)

    async def _auth(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await test_authentication(state, toolkit)

    async def _acl(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await test_access_control(state, toolkit)

    async def _report(
        state: dict[str, Any],
    ) -> dict[str, Any]:
        return await generate_report(state, toolkit)

    graph.add_node(
        "discover_endpoints",
        traced_node(f"{_AGENT}.discover_endpoints", _AGENT)(_discover),
    )
    graph.add_node(
        "crawl_application",
        traced_node(f"{_AGENT}.crawl_application", _AGENT)(_crawl),
    )
    graph.add_node(
        "test_injection",
        traced_node(f"{_AGENT}.test_injection", _AGENT)(_injection),
    )
    graph.add_node(
        "test_authentication",
        traced_node(f"{_AGENT}.test_authentication", _AGENT)(_auth),
    )
    graph.add_node(
        "test_access_control",
        traced_node(f"{_AGENT}.test_access_control", _AGENT)(_acl),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(_report),
    )

    graph.set_entry_point("discover_endpoints")
    graph.add_edge("discover_endpoints", "crawl_application")
    graph.add_edge("crawl_application", "test_injection")
    graph.add_conditional_edges(
        "test_injection",
        _has_injection_findings,
        {
            "test_authentication": "test_authentication",
            "test_access_control": "test_access_control",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("test_authentication", "test_access_control")
    graph.add_edge("test_access_control", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_web_app_scanner_graph(
    **clients: Any,
) -> StateGraph:
    """Factory to create a web app scanner graph."""
    toolkit = WebAppScannerToolkit(
        http_client=clients.get("http_client"),
        policy_engine=clients.get("policy_engine"),
        repository=clients.get("repository"),
    )
    return build_graph(toolkit)
