"""Tests for the middleware composition builder."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from shieldops.api.middleware.builder import (
    MiddlewareOrderingError,
    MiddlewareSpec,
    MiddlewareStackBuilder,
    Position,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeMiddleware:
    """Minimal middleware stand-in for testing."""

    def __init__(self, app: Any, **kwargs: Any) -> None:
        self.app = app
        self.kwargs = kwargs


class _FakeMiddlewareA(_FakeMiddleware):
    pass


class _FakeMiddlewareB(_FakeMiddleware):
    pass


class _FakeMiddlewareC(_FakeMiddleware):
    pass


class _FakeMiddlewareD(_FakeMiddleware):
    pass


class _BrokenMiddleware:
    """Raises on init to test optional handling."""

    def __init__(self, app: Any, **kwargs: Any) -> None:
        raise RuntimeError("init failed")


def _make_app() -> MagicMock:
    """Return a mock app with an ``add_middleware`` recorder."""
    app = MagicMock()
    app._added: list[tuple[type, dict[str, Any]]] = []  # type: ignore[misc]

    def _record(cls: type, **kwargs: Any) -> None:
        app._added.append((cls, kwargs))

    app.add_middleware.side_effect = _record
    return app


# ---------------------------------------------------------------------------
# Tests: topological sort
# ---------------------------------------------------------------------------


class TestTopologicalSort:
    def test_linear_chain(self) -> None:
        """A -> B -> C produces outermost-first [A, B, C]."""
        builder = MiddlewareStackBuilder()
        builder.add(
            MiddlewareSpec(cls=_FakeMiddlewareA, name="A", must_run_before=frozenset({"B"}))
        )
        builder.add(
            MiddlewareSpec(cls=_FakeMiddlewareB, name="B", must_run_before=frozenset({"C"}))
        )
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareC, name="C"))

        app = _make_app()
        names = builder.build(app)

        assert names == ["A", "B", "C"]

    def test_must_run_after(self) -> None:
        """``must_run_after`` is the inverse of ``must_run_before``."""
        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareA, name="A"))
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareB, name="B", must_run_after=frozenset({"A"})))

        app = _make_app()
        names = builder.build(app)

        assert names == ["A", "B"]

    def test_position_outermost(self) -> None:
        """OUTERMOST spec is always first."""
        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareA, name="inner"))
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareB, name="outer", position=Position.OUTERMOST))

        app = _make_app()
        names = builder.build(app)

        assert names[0] == "outer"

    def test_position_innermost(self) -> None:
        """INNERMOST spec is always last."""
        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareA, name="inner", position=Position.INNERMOST))
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareB, name="outer"))

        app = _make_app()
        names = builder.build(app)

        assert names[-1] == "inner"

    def test_deterministic_with_no_constraints(self) -> None:
        """Without constraints, insertion order is preserved."""
        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareA, name="X"))
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareB, name="Y"))
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareC, name="Z"))

        app = _make_app()
        names = builder.build(app)

        assert names == ["X", "Y", "Z"]


# ---------------------------------------------------------------------------
# Tests: cycle detection
# ---------------------------------------------------------------------------


class TestCycleDetection:
    def test_direct_cycle(self) -> None:
        """A -> B -> A raises MiddlewareOrderingError."""
        builder = MiddlewareStackBuilder()
        builder.add(
            MiddlewareSpec(cls=_FakeMiddlewareA, name="A", must_run_before=frozenset({"B"}))
        )
        builder.add(
            MiddlewareSpec(cls=_FakeMiddlewareB, name="B", must_run_before=frozenset({"A"}))
        )

        with pytest.raises(MiddlewareOrderingError, match="Cycle detected"):
            builder.validate()

    def test_indirect_cycle(self) -> None:
        """A -> B -> C -> A raises MiddlewareOrderingError."""
        builder = MiddlewareStackBuilder()
        builder.add(
            MiddlewareSpec(cls=_FakeMiddlewareA, name="A", must_run_before=frozenset({"B"}))
        )
        builder.add(
            MiddlewareSpec(cls=_FakeMiddlewareB, name="B", must_run_before=frozenset({"C"}))
        )
        builder.add(
            MiddlewareSpec(cls=_FakeMiddlewareC, name="C", must_run_before=frozenset({"A"}))
        )

        with pytest.raises(MiddlewareOrderingError, match="Cycle detected"):
            builder.build(_make_app())


# ---------------------------------------------------------------------------
# Tests: position conflicts
# ---------------------------------------------------------------------------


class TestPositionConflicts:
    def test_two_outermost(self) -> None:
        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareA, name="A", position=Position.OUTERMOST))
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareB, name="B", position=Position.OUTERMOST))

        with pytest.raises(MiddlewareOrderingError, match="OUTERMOST"):
            builder.validate()

    def test_two_innermost(self) -> None:
        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareA, name="A", position=Position.INNERMOST))
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareB, name="B", position=Position.INNERMOST))

        with pytest.raises(MiddlewareOrderingError, match="INNERMOST"):
            builder.validate()


# ---------------------------------------------------------------------------
# Tests: duplicate names
# ---------------------------------------------------------------------------


class TestDuplicateNames:
    def test_duplicate_raises(self) -> None:
        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareA, name="same"))
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareB, name="same"))

        with pytest.raises(MiddlewareOrderingError, match="Duplicate"):
            builder.validate()


# ---------------------------------------------------------------------------
# Tests: disabled middleware
# ---------------------------------------------------------------------------


class TestDisabledMiddleware:
    def test_disabled_excluded(self) -> None:
        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareA, name="on"))
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareB, name="off", enabled=False))

        app = _make_app()
        names = builder.build(app)

        assert names == ["on"]
        assert app.add_middleware.call_count == 1

    def test_disabled_not_validated(self) -> None:
        """Disabled specs with duplicate names should not raise."""
        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareA, name="X"))
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareB, name="X", enabled=False))

        warnings = builder.validate()
        assert isinstance(warnings, list)


# ---------------------------------------------------------------------------
# Tests: optional middleware failure
# ---------------------------------------------------------------------------


class TestOptionalMiddleware:
    def test_optional_failure_swallowed(self) -> None:
        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareA, name="ok"))
        builder.add(MiddlewareSpec(cls=_BrokenMiddleware, name="broken", optional=True))

        app = _make_app()
        # Make the second add_middleware call raise
        call_count = 0

        def _side_effect(cls: type, **kwargs: Any) -> None:
            nonlocal call_count
            call_count += 1
            if cls is _BrokenMiddleware:
                raise RuntimeError("init failed")

        app.add_middleware.side_effect = _side_effect
        names = builder.build(app)  # should not raise

        assert "ok" in names

    def test_non_optional_failure_raises(self) -> None:
        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=_BrokenMiddleware, name="broken", optional=False))

        app = _make_app()
        app.add_middleware.side_effect = RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            builder.build(app)


# ---------------------------------------------------------------------------
# Tests: tag redundancy warnings
# ---------------------------------------------------------------------------


class TestTagRedundancy:
    def test_shared_tag_warns(self) -> None:
        builder = MiddlewareStackBuilder()
        builder.add(
            MiddlewareSpec(cls=_FakeMiddlewareA, name="A", tags=frozenset({"rate_limiting"}))
        )
        builder.add(
            MiddlewareSpec(cls=_FakeMiddlewareB, name="B", tags=frozenset({"rate_limiting"}))
        )

        warnings = builder.validate()
        assert any("rate_limiting" in w for w in warnings)

    def test_dangling_reference_warns(self) -> None:
        builder = MiddlewareStackBuilder()
        builder.add(
            MiddlewareSpec(
                cls=_FakeMiddlewareA, name="A", must_run_before=frozenset({"nonexistent"})
            )
        )

        warnings = builder.validate()
        assert any("nonexistent" in w for w in warnings)


# ---------------------------------------------------------------------------
# Tests: LIFO inversion
# ---------------------------------------------------------------------------


class TestLIFOInversion:
    def test_outermost_added_last(self) -> None:
        """Outermost middleware must be the LAST ``add_middleware`` call
        so Starlette's LIFO ordering makes it execute first."""
        builder = MiddlewareStackBuilder()
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareA, name="outer", position=Position.OUTERMOST))
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareB, name="middle"))
        builder.add(MiddlewareSpec(cls=_FakeMiddlewareC, name="inner", position=Position.INNERMOST))

        app = _make_app()
        builder.build(app)

        added_classes = [call[0] for call in app._added]
        # reversed(outermost-first) means innermost added first, outermost last
        assert added_classes[0] == _FakeMiddlewareC  # inner added first
        assert added_classes[-1] == _FakeMiddlewareA  # outer added last


# ---------------------------------------------------------------------------
# Tests: empty builder
# ---------------------------------------------------------------------------


class TestEmptyBuilder:
    def test_empty_build(self) -> None:
        builder = MiddlewareStackBuilder()
        app = _make_app()
        names = builder.build(app)

        assert names == []
        assert app.add_middleware.call_count == 0

    def test_empty_validate(self) -> None:
        builder = MiddlewareStackBuilder()
        warnings = builder.validate()
        assert warnings == []


# ---------------------------------------------------------------------------
# Tests: fluent API
# ---------------------------------------------------------------------------


class TestFluentAPI:
    def test_chaining(self) -> None:
        builder = (
            MiddlewareStackBuilder()
            .add(MiddlewareSpec(cls=_FakeMiddlewareA, name="A"))
            .add(MiddlewareSpec(cls=_FakeMiddlewareB, name="B"))
        )
        assert len(builder._specs) == 2
