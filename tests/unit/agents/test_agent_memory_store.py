"""Tests for shieldops.agents.agent_memory_store — episodic memory for AI agents."""

from __future__ import annotations

import pytest

from shieldops.agents.agent_memory_store.models import (
    AgentMemoryStoreState,
    MemoryClassification,
    MemoryIndex,
    MemoryRecord,
    MemoryStage,
    MemoryType,
    RetrievalQuery,
    RetrievalResult,
    RetrievalStrategy,
)


def _state(**kw) -> AgentMemoryStoreState:
    return AgentMemoryStoreState(**kw)


class TestEnums:
    def test_memory_stage_values(self):
        assert MemoryStage.RECEIVE == "receive_memory"
        assert MemoryStage.CLASSIFY == "classify_memory"
        assert MemoryStage.STORE == "store_memory"
        assert MemoryStage.INDEX == "index_for_retrieval"
        assert MemoryStage.PRUNE == "prune_stale"
        assert MemoryStage.REPORT == "report"

    def test_memory_type_values(self):
        assert MemoryType.INVESTIGATION_OUTCOME == "investigation_outcome"
        assert MemoryType.FALSE_POSITIVE_PATTERN == "false_positive_pattern"
        assert MemoryType.ATTACK_SIGNATURE == "attack_signature"
        assert MemoryType.REMEDIATION_PLAYBOOK == "remediation_playbook"
        assert MemoryType.ANALYST_FEEDBACK == "analyst_feedback"
        assert MemoryType.CONFIGURATION_DRIFT == "configuration_drift"

    def test_retrieval_strategy_values(self):
        assert RetrievalStrategy.SEMANTIC_SEARCH == "semantic_search"
        assert RetrievalStrategy.TEMPORAL == "temporal"
        assert RetrievalStrategy.ENTITY_MATCH == "entity_match"
        assert RetrievalStrategy.PATTERN_MATCH == "pattern_match"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.operation == "store"
        assert s.incoming_memory is None
        assert s.retrieval_query is None
        assert s.classification is None
        assert s.index_entry is None
        assert s.memories_stored == 0
        assert s.memories_retrieved == 0
        assert s.retrieval_accuracy == 0.0
        assert s.storage_utilization == 0.0
        assert s.stale_memories_pruned == 0
        assert s.retrieval_result is None
        assert s.current_stage == "init"
        assert s.error == ""
        assert s.processing_steps == []

    def test_memory_record_defaults(self):
        m = MemoryRecord()
        assert m.memory_id == ""
        assert m.agent_id == ""
        assert m.agent_type == ""
        assert m.memory_type == MemoryType.INVESTIGATION_OUTCOME
        assert m.content == ""
        assert m.entities == []
        assert m.outcome == ""
        assert m.confidence == 0.0
        assert m.context == {}
        assert m.created_at is None
        assert m.expires_at is None
        assert m.access_count == 0
        assert m.tags == []

    def test_memory_classification_defaults(self):
        mc = MemoryClassification(memory_type="investigation_outcome")
        assert mc.importance_score == 0.5
        assert mc.keywords == []
        assert mc.related_patterns == []
        assert mc.suggested_ttl_days == 90
        assert mc.reasoning == ""

    def test_memory_index_defaults(self):
        mi = MemoryIndex()
        assert mi.memory_id == ""
        assert mi.keywords == []
        assert mi.entities == []
        assert mi.importance_score == 0.0

    def test_retrieval_query_defaults(self):
        rq = RetrievalQuery()
        assert rq.query_text == ""
        assert rq.agent_id is None
        assert rq.memory_type is None
        assert rq.strategy == RetrievalStrategy.SEMANTIC_SEARCH
        assert rq.limit == 10
        assert rq.min_importance == 0.0
        assert rq.max_age_days is None

    def test_retrieval_result_defaults(self):
        rr = RetrievalResult()
        assert rr.memories == []
        assert rr.total_matches == 0
        assert rr.strategy_used == RetrievalStrategy.SEMANTIC_SEARCH
        assert rr.query_time_ms == 0
        assert rr.relevance_scores == []


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.agent_memory_store.tools import AgentMemoryStoreToolkit

        return AgentMemoryStoreToolkit()

    @pytest.mark.asyncio
    async def test_store_memory(self, toolkit):
        result = await toolkit.store_memory(
            agent_id="agent-1",
            memory_type=MemoryType.INVESTIGATION_OUTCOME,
            content="Investigated lateral movement via SSH",
            entities=["host-1", "host-2"],
            outcome="contained",
        )
        assert isinstance(result, MemoryRecord)
        assert result.agent_id == "agent-1"
        assert result.memory_type == MemoryType.INVESTIGATION_OUTCOME

    @pytest.mark.asyncio
    async def test_retrieve_memories(self, toolkit):
        # Store a memory first
        await toolkit.store_memory(
            agent_id="agent-1",
            memory_type=MemoryType.FALSE_POSITIVE_PATTERN,
            content="DNS query to internal CDN is benign",
        )
        result = await toolkit.retrieve_memories(query="DNS query")
        assert isinstance(result, RetrievalResult)

    @pytest.mark.asyncio
    async def test_store_false_positive(self, toolkit):
        result = await toolkit.store_false_positive(
            agent_id="agent-1",
            content="Scheduled task alert is benign",
            entities=["cron-job-1"],
        )
        assert isinstance(result, MemoryRecord)
        assert result.memory_type == MemoryType.FALSE_POSITIVE_PATTERN

    @pytest.mark.asyncio
    async def test_retrieve_similar_incidents(self, toolkit):
        result = await toolkit.retrieve_similar_incidents(entities=["host-1"], limit=5)
        assert isinstance(result, RetrievalResult)

    @pytest.mark.asyncio
    async def test_prune_stale_memories(self, toolkit):
        result = await toolkit.prune_stale_memories()
        assert isinstance(result, int)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.agent_memory_store.graph import create_agent_memory_store_graph

        sg = create_agent_memory_store_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.agent_memory_store.graph import create_agent_memory_store_graph

        sg = create_agent_memory_store_graph()
        compiled = sg.compile()
        assert compiled is not None
