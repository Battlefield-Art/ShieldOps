"""Tests for shieldops.agents.knowledge — utility module."""

from __future__ import annotations


def test_knowledge_imports():
    from shieldops.agents.knowledge import embedder, rag_store

    assert embedder is not None
    assert rag_store is not None
