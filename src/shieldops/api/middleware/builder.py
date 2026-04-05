"""Middleware composition builder with validated ordering.

Replaces implicit LIFO middleware stacking with a declarative builder
that validates ordering constraints, detects cycles, and resolves a
deterministic topological order via Kahn's algorithm.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import structlog

logger = structlog.get_logger()


class Position(StrEnum):
    """Fixed positions in the middleware stack."""

    OUTERMOST = "outermost"
    INNERMOST = "innermost"


@dataclass(frozen=True)
class MiddlewareSpec:
    """Declarative specification for a single middleware layer."""

    cls: type
    name: str
    kwargs: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    optional: bool = False
    position: Position | None = None
    must_run_before: frozenset[str] = frozenset()
    must_run_after: frozenset[str] = frozenset()
    tags: frozenset[str] = frozenset()


class MiddlewareOrderingError(Exception):
    """Raised when middleware ordering constraints cannot be satisfied."""


class MiddlewareStackBuilder:
    """Build a validated, topologically-sorted middleware stack.

    Usage::

        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=MetricsMiddleware, name="metrics",
                                   position=Position.OUTERMOST))
        builder.add(MiddlewareSpec(cls=ErrorHandlerMiddleware, name="error_handler",
                                   position=Position.INNERMOST))
        names = builder.build(app)
    """

    def __init__(self) -> None:
        self._specs: list[MiddlewareSpec] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, spec: MiddlewareSpec) -> MiddlewareStackBuilder:
        """Append a middleware spec to the builder (fluent API)."""
        self._specs.append(spec)
        return self

    def validate(self) -> list[str]:
        """Validate ordering constraints. Returns a list of warnings.

        Raises :class:`MiddlewareOrderingError` on hard errors such as
        duplicate names, position conflicts, or dependency cycles.
        """
        warnings: list[str] = []
        enabled = [s for s in self._specs if s.enabled]
        names = [s.name for s in enabled]
        name_set = set(names)

        # --- Duplicate names ---
        seen: set[str] = set()
        for n in names:
            if n in seen:
                raise MiddlewareOrderingError(f"Duplicate middleware name: '{n}'")
            seen.add(n)

        # --- Position conflicts ---
        outermost = [s.name for s in enabled if s.position == Position.OUTERMOST]
        if len(outermost) > 1:
            raise MiddlewareOrderingError(
                f"Multiple middleware claim OUTERMOST position: {outermost}"
            )
        innermost = [s.name for s in enabled if s.position == Position.INNERMOST]
        if len(innermost) > 1:
            raise MiddlewareOrderingError(
                f"Multiple middleware claim INNERMOST position: {innermost}"
            )

        # --- Dangling references ---
        for spec in enabled:
            for ref in spec.must_run_before:
                if ref not in name_set:
                    warnings.append(
                        f"'{spec.name}' declares must_run_before='{ref}' which is not in the stack"
                    )
            for ref in spec.must_run_after:
                if ref not in name_set:
                    warnings.append(
                        f"'{spec.name}' declares must_run_after='{ref}' which is not in the stack"
                    )

        # --- Tag-based redundancy ---
        tag_to_names: dict[str, list[str]] = defaultdict(list)
        for spec in enabled:
            for tag in spec.tags:
                tag_to_names[tag].append(spec.name)
        for tag, tag_names in tag_to_names.items():
            if len(tag_names) > 1:
                warnings.append(
                    f"Tag '{tag}' shared by multiple middleware: {tag_names} -- possible redundancy"
                )

        # --- Cycle detection (via topological sort attempt) ---
        self._resolve_order(enabled)  # raises on cycle

        return warnings

    def build(self, app: Any) -> list[str]:
        """Validate, resolve order, and apply middleware to *app*.

        Returns the resolved middleware names in outermost-first order.

        Starlette processes ``add_middleware`` in LIFO order, so we add
        middleware in **reverse** (innermost first) so the outermost
        middleware wraps everything.
        """
        enabled = [s for s in self._specs if s.enabled]
        ordered = self._resolve_order(enabled)  # outermost-first

        # LIFO inversion: add in reverse so outermost is added last
        for spec in reversed(ordered):
            try:
                app.add_middleware(spec.cls, **spec.kwargs)
            except Exception:
                if not spec.optional:
                    raise
                logger.warning("middleware_init_skipped", name=spec.name)

        names = [s.name for s in ordered]
        logger.info("middleware_stack_resolved", order=names, count=len(names))
        return names

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _resolve_order(self, specs: list[MiddlewareSpec]) -> list[MiddlewareSpec]:
        """Topological sort using Kahn's algorithm.

        Returns specs in **outermost-first** order.  Position constraints
        (``OUTERMOST`` / ``INNERMOST``) are translated into edges so
        they participate naturally in the sort.
        """
        by_name: dict[str, MiddlewareSpec] = {s.name: s for s in specs}
        names = list(by_name.keys())

        # Build adjacency: edge A -> B means "A must run before B"
        # (A is outer, B is inner).
        graph: dict[str, set[str]] = {n: set() for n in names}
        in_degree: dict[str, int] = {n: 0 for n in names}

        def _add_edge(before: str, after: str) -> None:
            if after not in graph[before]:
                graph[before].add(after)
                in_degree[after] += 1

        # Position constraints
        outermost_name: str | None = None
        innermost_name: str | None = None
        for spec in specs:
            if spec.position == Position.OUTERMOST:
                outermost_name = spec.name
            elif spec.position == Position.INNERMOST:
                innermost_name = spec.name

        if outermost_name:
            for n in names:
                if n != outermost_name:
                    _add_edge(outermost_name, n)

        if innermost_name:
            for n in names:
                if n != innermost_name:
                    _add_edge(n, innermost_name)

        # Explicit ordering constraints
        for spec in specs:
            for before_name in spec.must_run_before:
                if before_name in by_name:
                    _add_edge(spec.name, before_name)
            for after_name in spec.must_run_after:
                if after_name in by_name:
                    _add_edge(after_name, spec.name)

        # Kahn's algorithm
        queue: deque[str] = deque()
        for n in names:
            if in_degree[n] == 0:
                queue.append(n)

        result: list[str] = []
        while queue:
            # Sort for deterministic output when multiple nodes have
            # in-degree 0 (stable tie-breaking by insertion order).
            queue = deque(sorted(queue, key=lambda x: names.index(x)))
            node = queue.popleft()
            result.append(node)
            for neighbour in sorted(graph[node], key=lambda x: names.index(x)):
                in_degree[neighbour] -= 1
                if in_degree[neighbour] == 0:
                    queue.append(neighbour)

        if len(result) != len(names):
            remaining = set(names) - set(result)
            raise MiddlewareOrderingError(
                f"Cycle detected in middleware ordering involving: {sorted(remaining)}"
            )

        return [by_name[n] for n in result]
