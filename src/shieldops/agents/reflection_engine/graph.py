"""LangGraph workflow definition for the Reflection Engine Agent."""

from langgraph.graph import END, StateGraph

from shieldops.agents.reflection_engine.models import (
    ReflectionEngineState,
)
from shieldops.agents.reflection_engine.nodes import (
    apply_learnings,
    collect_agent_actions,
    evaluate_outcomes,
    generate_improvements,
    generate_report,
    identify_mistakes,
)
from shieldops.agents.tracing import traced_node


def has_actions(state: ReflectionEngineState) -> str:
    """Route based on whether actions were collected."""
    if state.error:
        return END
    if not state.actions_reviewed:
        return "generate_report"
    return "evaluate_outcomes"


def has_mistakes(state: ReflectionEngineState) -> str:
    """Route based on whether mistakes were found."""
    if state.error:
        return END
    if not state.mistakes_found:
        return "generate_report"
    return "generate_improvements"


def has_improvements(
    state: ReflectionEngineState,
) -> str:
    """Route based on whether improvements exist."""
    if state.error:
        return END
    if not state.improvements_recommended:
        return "generate_report"
    return "apply_learnings"


def create_reflection_engine_graph() -> StateGraph:
    """Build the Reflection Engine Agent LangGraph workflow.

    Workflow:
        collect_agent_actions
            → [no actions? → generate_report → END]
            → evaluate_outcomes → identify_mistakes
            → [no mistakes? → generate_report → END]
            → generate_improvements
            → [no improvements? → generate_report → END]
            → apply_learnings → generate_report → END
    """
    graph = StateGraph(ReflectionEngineState)

    _agent = "reflection_engine"
    graph.add_node(
        "collect_agent_actions",
        traced_node(
            "reflection_engine.collect_agent_actions",
            _agent,
        )(collect_agent_actions),
    )
    graph.add_node(
        "evaluate_outcomes",
        traced_node(
            "reflection_engine.evaluate_outcomes",
            _agent,
        )(evaluate_outcomes),
    )
    graph.add_node(
        "identify_mistakes",
        traced_node(
            "reflection_engine.identify_mistakes",
            _agent,
        )(identify_mistakes),
    )
    graph.add_node(
        "generate_improvements",
        traced_node(
            "reflection_engine.generate_improvements",
            _agent,
        )(generate_improvements),
    )
    graph.add_node(
        "apply_learnings",
        traced_node(
            "reflection_engine.apply_learnings",
            _agent,
        )(apply_learnings),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            "reflection_engine.generate_report",
            _agent,
        )(generate_report),
    )

    # Define edges
    graph.set_entry_point("collect_agent_actions")
    graph.add_conditional_edges(
        "collect_agent_actions",
        has_actions,
        {
            "evaluate_outcomes": "evaluate_outcomes",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("evaluate_outcomes", "identify_mistakes")
    graph.add_conditional_edges(
        "identify_mistakes",
        has_mistakes,
        {
            "generate_improvements": ("generate_improvements"),
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_conditional_edges(
        "generate_improvements",
        has_improvements,
        {
            "apply_learnings": "apply_learnings",
            "generate_report": "generate_report",
            END: END,
        },
    )
    graph.add_edge("apply_learnings", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
