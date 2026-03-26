"""LangGraph workflow for the Agent Memory Store agent."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.agent_memory_store.models import (
    AgentMemoryStoreState,
)
from shieldops.agents.agent_memory_store.nodes import (
    classify_memory,
    index_for_retrieval,
    prune_stale,
    receive_memory,
    report,
    store_memory,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()

_AGENT = "agent_memory_store"


def route_operation(
    state: AgentMemoryStoreState,
) -> str:
    """Route based on the requested operation."""
    if state.error:
        return "report"
    if state.operation == "prune":
        return "prune_stale"
    if state.operation == "retrieve":
        return "report"
    # Default: store operation
    return "classify_memory"


def should_prune_after_store(
    state: AgentMemoryStoreState,
) -> str:
    """Decide whether to prune after storing."""
    if state.storage_utilization > 0.8:
        return "prune_stale"
    return "report"


def create_agent_memory_store_graph() -> StateGraph[AgentMemoryStoreState]:
    """Build the Agent Memory Store LangGraph workflow.

    Store workflow:
        receive_memory -> classify_memory
            -> store_memory -> index_for_retrieval
            -> [conditional: prune_stale OR report]

    Prune workflow:
        receive_memory -> prune_stale -> report

    Retrieve workflow:
        receive_memory -> report
    """
    graph = StateGraph(AgentMemoryStoreState)

    # Add nodes with OTEL tracing
    graph.add_node(
        "receive_memory",
        traced_node("memory_store.receive_memory", _AGENT)(receive_memory),
    )
    graph.add_node(
        "classify_memory",
        traced_node("memory_store.classify_memory", _AGENT)(classify_memory),
    )
    graph.add_node(
        "store_memory",
        traced_node("memory_store.store_memory", _AGENT)(store_memory),
    )
    graph.add_node(
        "index_for_retrieval",
        traced_node(
            "memory_store.index_for_retrieval",
            _AGENT,
        )(index_for_retrieval),
    )
    graph.add_node(
        "prune_stale",
        traced_node("memory_store.prune_stale", _AGENT)(prune_stale),
    )
    graph.add_node(
        "report",
        traced_node("memory_store.report", _AGENT)(report),
    )

    # Define edges
    graph.set_entry_point("receive_memory")
    graph.add_conditional_edges(
        "receive_memory",
        route_operation,
        {
            "classify_memory": "classify_memory",
            "prune_stale": "prune_stale",
            "report": "report",
        },
    )
    graph.add_edge("classify_memory", "store_memory")
    graph.add_edge("store_memory", "index_for_retrieval")
    graph.add_conditional_edges(
        "index_for_retrieval",
        should_prune_after_store,
        {
            "prune_stale": "prune_stale",
            "report": "report",
        },
    )
    graph.add_edge("prune_stale", "report")
    graph.add_edge("report", END)

    return graph
