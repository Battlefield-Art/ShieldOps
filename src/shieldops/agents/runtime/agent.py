"""Agent base class + declarative node/edge spec.

See RFC #247. Agents are class declarations whose attributes are the
graph spec. The ``@node`` decorator marks bound-method nodes, and the
class-level ``edges`` attribute lists the transitions. The runtime
compiles the spec into a sequence at mount time and drives it through
the lifecycle.

Node functions have the pure ``(state, toolkit) → state`` signature
(borrowed from Design A of RFC #247) — no ``ctx`` argument, no module
globals, no ``set_toolkit()``. Tests unit-test a node by calling
``await MyAgent.scan(state, FakeToolkit())`` with no runtime needed.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, ClassVar

NodeFn = Callable[[Any, Any], Awaitable[Any]]


def node(fn: NodeFn) -> NodeFn:
    """Mark a method as an agent node.

    The decorator is a no-op at runtime (it just tags the function) but
    makes the agent's declaration form readable::

        class MyAgent(Agent):
            @node
            async def scan(state, toolkit):
                ...
    """
    fn._shieldops_node = True
    return fn


@dataclass(frozen=True)
class Edge:
    """A static transition from one node to another."""

    source: str
    target: str


@dataclass(frozen=True)
class ConditionalEdge:
    """A conditional transition: ``predicate(state)`` returns the name
    of the next node (or :data:`END`)."""

    source: str
    predicate: Callable[[Any], str]
    routes: dict[str, str]


def edge(source: str, target: str) -> Edge:
    """Convenience constructor for a static edge."""
    return Edge(source=source, target=target)


def cond(
    source: str,
    predicate: Callable[[Any], str],
    routes: dict[str, str],
) -> ConditionalEdge:
    """Convenience constructor for a conditional edge."""
    return ConditionalEdge(source=source, predicate=predicate, routes=routes)


class Agent[StateT]:
    """Base class — agents subclass this and declare the spec via class attrs.

    The runtime discovers ``nodes`` (a dict of name → NodeFn) and
    ``edges`` (a list of :class:`Edge` or :class:`ConditionalEdge`)
    at mount time and compiles them into a sequence.

    Cross-cutting concerns absorbed by the runtime (not the author):
    - license check before any node runs
    - policy evaluation per node (if declared in ``policy_actions``)
    - persistence of state after each node
    - audit log entries for the run
    - websocket publish of lifecycle events
    - evolution store record_run at terminal
    """

    name: ClassVar[str]
    state_model: ClassVar[type]
    toolkit_factory: ClassVar[Callable[[], Any]]
    nodes: ClassVar[dict[str, NodeFn]]
    edges: ClassVar[list[Edge | ConditionalEdge]]
    entry: ClassVar[str]

    # Optional opt-in class attributes — absent = "don't enforce"
    policy_actions: ClassVar[dict[str, str]] = {}
    """Map of node_name → policy action string. Only listed nodes are
    gated by the PolicyPort."""

    license_feature: ClassVar[str | None] = None
    """Optional license feature gate. When set, the runtime calls
    LicenseManagerPort.check(license_feature, tenant_id) before mounting."""
