"""Agent framework — eliminates boilerplate from LangGraph agent definitions.

Usage::

    from shieldops.agents.framework import define_agent, Edge

    # Simple linear agent (5 lines):
    MyRunner = define_agent(
        name="my_agent",
        state_type=MyState,
        toolkit_type=MyToolkit,
        nodes=["collect", "analyze", "report"],
    )

    # Agent with conditional routing:
    MyRunner = define_agent(
        name="my_agent",
        state_type=MyState,
        toolkit_type=MyToolkit,
        nodes=["collect", "analyze", ("custom_step", my_custom_fn), "report"],
        edges=[Edge(after="analyze",
             condition=lambda s: "report" if s.get("done") else "custom_step",
             routes={"report": "report", "custom_step": "custom_step"})],
    )
"""

from __future__ import annotations

import contextlib
import functools
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import structlog
from pydantic import BaseModel

logger = structlog.get_logger()


@dataclass(frozen=True)
class Edge:
    """Conditional routing edge in the agent graph."""

    after: str
    condition: Callable[[Any], str]
    routes: dict[str, str]


def build_linear_graph(
    state_type: type[BaseModel],
    nodes: list[tuple[str, Callable[..., Any]]],
    toolkit: Any | None = None,
) -> Any:
    """Build a linear (sequential) LangGraph StateGraph from a list of node functions.

    This is a lightweight helper for the common case: a graph with N nodes
    executed in order, no conditional routing. It replaces the boilerplate
    `graph.add_node`/`graph.add_edge` sequence found in most linear agents.

    Args:
        state_type: Pydantic BaseModel subclass for the graph state.
        nodes: Ordered list of ``(node_name, node_fn)`` tuples. Each ``node_fn``
            may be either a unary ``async (state) -> dict`` coroutine or a
            binary ``async (state, toolkit) -> dict`` coroutine. If binary and
            ``toolkit`` is provided, it is bound automatically.
        toolkit: Optional toolkit instance to bind to binary ``(state, toolkit)``
            node functions.

    Returns:
        An uncompiled ``StateGraph`` ready for ``.compile()``.
    """
    import inspect

    from langgraph.graph import END, StateGraph

    if not nodes:
        raise ValueError("At least one node is required.")

    graph: Any = StateGraph(state_type)

    def _to_dict(state: Any) -> dict[str, Any]:
        if isinstance(state, BaseModel):
            return state.model_dump()
        if isinstance(state, dict):
            return state
        return dict(state)

    def _wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(fn)
        n_params = len(sig.parameters)
        if n_params >= 2 and toolkit is not None:

            async def _binary(state: Any) -> dict[str, Any]:
                return await fn(_to_dict(state), toolkit)  # type: ignore[no-any-return]

            _binary.__name__ = getattr(fn, "__name__", "node")
            return _binary

        async def _unary(state: Any) -> dict[str, Any]:
            return await fn(_to_dict(state))  # type: ignore[no-any-return]

        _unary.__name__ = getattr(fn, "__name__", "node")
        return _unary

    for node_name, node_fn in nodes:
        graph.add_node(node_name, _wrap(node_fn))

    graph.set_entry_point(nodes[0][0])
    for i in range(len(nodes) - 1):
        graph.add_edge(nodes[i][0], nodes[i + 1][0])
    graph.add_edge(nodes[-1][0], END)

    return graph


def define_agent(
    name: str,
    *,
    state_type: type[BaseModel],
    toolkit_type: type,
    nodes: list[str | tuple[str, Callable[..., Any]]],
    edges: list[Edge] | None = None,
    license_enforced: bool = True,
) -> type:
    """Define a complete LangGraph agent from its essential parts.

    Args:
        name: Agent identifier (e.g. "threat_hunter").
        state_type: Pydantic BaseModel subclass for the graph state.
        toolkit_type: The Toolkit class. Instantiated in Runner.__init__.
        nodes: Ordered list of node definitions. String entries auto-generate
               nodes that call the corresponding toolkit method. Tuple entries
               (name, callable) use the provided function directly.
        edges: Optional conditional routing edges. If None, nodes execute
               in linear order with the last node connecting to END.
        license_enforced: If True (the default), the generated runner's
            ``run()`` method is automatically wrapped with the RFC #244
            ``@enforced(name)`` decorator so license limits are checked
            before every run. This is PR-2 of RFC #244 — the single
            framework patch that propagates license enforcement to all
            114 ``define_agent``-built runners. Set to False to opt out
            during migration; a warning is logged if no LicenseManager
            is installed (enforcement becomes a no-op in that case).

    Returns:
        A Runner class with __init__, run, get_result, list_results.
    """

    # Parse node specs
    node_specs: list[tuple[str, Callable[..., Any] | None]] = []
    for entry in nodes:
        if isinstance(entry, str):
            node_specs.append((entry, None))  # auto-generate from toolkit
        elif isinstance(entry, tuple) and len(entry) == 2:
            node_specs.append((entry[0], entry[1]))
        else:
            raise ValueError(f"Invalid node spec: {entry!r}. Use str or (str, callable).")

    if not node_specs:
        raise ValueError("At least one node is required.")

    # Build set of nodes that have explicit edge routing
    routed_sources: set[str] = set()
    if edges:
        for edge in edges:
            routed_sources.add(edge.after)

    # Try to import tracing
    _traced_node: Any = None
    with contextlib.suppress(ImportError):
        from shieldops.agents.tracing import traced_node as _traced_node

    class AgentRunner:
        """Auto-generated runner for the {name} agent."""

        agent_name: str = name
        state_class: type[BaseModel] = state_type
        toolkit_class: type = toolkit_type

        def __init__(self, **toolkit_kwargs: Any) -> None:
            self._toolkit = toolkit_type(**toolkit_kwargs)
            self._results: dict[str, Any] = {}
            self._app = self._build_graph()
            logger.info(f"{name}_runner.initialized")

        def _build_graph(self) -> Any:
            from langgraph.graph import END, StateGraph

            graph = StateGraph(state_type)

            # Generate node functions
            for node_name, custom_fn in node_specs:
                node_fn = custom_fn if custom_fn is not None else self._make_auto_node(node_name)

                # Wrap with tracing
                if _traced_node is not None:
                    wrapped = _traced_node(f"{name}.{node_name}", name)(node_fn)
                else:
                    wrapped = node_fn

                graph.add_node(node_name, wrapped)

            # Set entry point
            graph.set_entry_point(node_specs[0][0])

            # Wire edges
            for i, (node_name, _) in enumerate(node_specs):
                if node_name in routed_sources:
                    # Find the Edge for this source
                    for edge in edges or []:
                        if edge.after == node_name:
                            # Wrap condition to handle both dict and Pydantic state
                            raw_cond = edge.condition

                            def _safe_condition(
                                state: Any,
                                _cond: Any = raw_cond,
                            ) -> str:
                                if isinstance(state, BaseModel):
                                    return _cond(state.model_dump())
                                return _cond(state)

                            graph.add_conditional_edges(
                                node_name,
                                _safe_condition,
                                edge.routes,  # type: ignore[arg-type]
                            )
                            break
                elif i < len(node_specs) - 1:
                    # Linear edge to next node
                    next_node = node_specs[i + 1][0]
                    graph.add_edge(node_name, next_node)
                else:
                    # Last node -> END
                    graph.add_edge(node_name, END)

            return graph.compile()

        def _make_auto_node(self, node_name: str) -> Callable[..., Any]:
            """Generate a node function that calls toolkit.{node_name}."""
            toolkit = self._toolkit

            @functools.wraps(getattr(toolkit, node_name, lambda s: {}))
            async def auto_node(state: Any) -> dict[str, Any]:
                # Convert state to dict if needed
                if isinstance(state, BaseModel):
                    state_dict = state.model_dump()
                elif isinstance(state, dict):
                    state_dict = state
                else:
                    state_dict = dict(state)

                start = time.monotonic()
                method = getattr(toolkit, node_name)
                result = await method(state_dict)
                duration_ms = (time.monotonic() - start) * 1000

                if not isinstance(result, dict):
                    result = {}

                # Update step tracking
                result["current_step"] = node_name

                # Append to reasoning chain
                chain = list(state_dict.get("reasoning_chain", []))
                chain.append(f"{node_name} completed in {duration_ms:.0f}ms")
                result["reasoning_chain"] = chain

                return result

            auto_node.__name__ = node_name
            auto_node.__qualname__ = f"{name}.{node_name}"
            return auto_node

        async def run(self, **initial_state_kwargs: Any) -> Any:
            """Execute the agent workflow."""
            session_id = f"{name}-{uuid4().hex[:12]}"

            # Set defaults
            initial_state_kwargs.setdefault("request_id", session_id)

            logger.info(f"{name}_runner.starting", session_id=session_id)

            try:
                initial = state_type(**initial_state_kwargs)
                result_dict = await self._app.ainvoke(
                    initial.model_dump(),
                    config={"metadata": {"session_id": session_id, "agent": name}},
                )
                final = state_type.model_validate(result_dict)
                self._results[session_id] = final
                logger.info(f"{name}_runner.completed", session_id=session_id)
                return final
            except Exception as e:
                logger.error(f"{name}_runner.failed", session_id=session_id, error=str(e))
                error_state = state_type(
                    **{
                        **initial_state_kwargs,
                        "error": str(e),
                        "current_step": "failed",
                    },
                )
                self._results[session_id] = error_state
                return error_state

        def get_result(self, session_id: str) -> Any | None:
            """Retrieve a cached result by session ID."""
            return self._results.get(session_id)

        def list_results(self) -> list[dict[str, Any]]:
            """List all cached results."""
            results = []
            for sid, state in self._results.items():
                entry: dict[str, Any] = {"session_id": sid}
                if hasattr(state, "model_dump"):
                    dumped = state.model_dump()
                    entry["current_step"] = dumped.get("current_step", "")
                    entry["error"] = dumped.get("error", "")
                else:
                    entry["state"] = state
                results.append(entry)
            return results

    # Set class metadata
    AgentRunner.__name__ = f"{name.title().replace('_', '')}Runner"
    AgentRunner.__qualname__ = AgentRunner.__name__
    AgentRunner.__doc__ = f"Auto-generated runner for the {name} agent."

    # ------------------------------------------------------------------
    # RFC #244 PR-2: auto-apply @enforced to the generated run method so
    # license limits are checked on every invocation. The decorator is
    # idempotent (via the _shieldops_enforced marker) so re-applying it
    # to an already-decorated class is safe. When license_enforced=False
    # is passed explicitly, this step is skipped (opt-out for migration).
    #
    # When no LicenseManager is installed at call time, the decorator
    # logs a warning once and passes through — this keeps existing test
    # suites green while production deployments opt in by calling
    # set_license_manager() during app.py lifespan.
    # ------------------------------------------------------------------
    if license_enforced:
        from shieldops.licensing.enforce import enforced as _enforced

        AgentRunner.run = _enforced(name)(AgentRunner.run)  # type: ignore[method-assign]

    return AgentRunner
