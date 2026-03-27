"""Tests for shieldops.agents.access_review."""

from __future__ import annotations

from shieldops.agents.access_review.models import (
    AccessReviewState,
)


class TestModels:
    def test_state_defaults(self):
        s = AccessReviewState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.access_review.graph import (
            create_access_review_graph,
        )

        sg = create_access_review_graph()
        assert sg.compile() is not None
