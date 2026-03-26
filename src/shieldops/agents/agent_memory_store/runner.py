"""Agent Memory Store runner — entry point for memory ops.

Provides store() and recall() methods that other agents
call to persist and retrieve episodic memories.
"""

from datetime import datetime
from typing import Any

import structlog

from shieldops.agents.agent_memory_store.graph import (
    create_agent_memory_store_graph,
)
from shieldops.agents.agent_memory_store.models import (
    AgentMemoryStoreState,
    MemoryRecord,
    MemoryType,
    RetrievalResult,
    RetrievalStrategy,
)
from shieldops.agents.agent_memory_store.nodes import (
    set_toolkit,
)
from shieldops.agents.agent_memory_store.tools import (
    AgentMemoryStoreToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class AgentMemoryStoreRunner:
    """Runs agent memory store operations.

    Usage:
        runner = AgentMemoryStoreRunner()
        await runner.store(
            agent_id="investigation-01",
            memory_type=MemoryType.INVESTIGATION_OUTCOME,
            content="Root cause was OOM in redis pod",
            entities=["redis-primary-0", "10.0.1.42"],
            outcome="resolved_by_memory_increase",
        )
        result = await runner.recall(
            query="redis OOM",
            limit=5,
        )
    """

    def __init__(
        self,
        max_records: int = 10_000,
        repository: Any = None,
    ) -> None:
        self._toolkit = AgentMemoryStoreToolkit(
            max_records=max_records,
            repository=repository,
        )
        set_toolkit(self._toolkit)

        graph = create_agent_memory_store_graph()
        self._app = graph.compile()
        self._repository = repository

    async def store(
        self,
        agent_id: str,
        memory_type: MemoryType,
        content: str,
        entities: list[str] | None = None,
        outcome: str = "",
        confidence: float = 0.5,
        context: dict[str, Any] | None = None,
        tags: list[str] | None = None,
    ) -> AgentMemoryStoreState:
        """Store an episodic memory via the LangGraph.

        Args:
            agent_id: Agent storing the memory.
            memory_type: Category of the memory.
            content: Memory content/description.
            entities: Related entities.
            outcome: Episode outcome.
            confidence: Memory confidence.
            context: Additional metadata.
            tags: Tags for categorization.

        Returns:
            Final AgentMemoryStoreState.
        """
        logger.info(
            "memory_store_started",
            agent_id=agent_id,
            memory_type=memory_type.value,
            content_preview=content[:80],
        )

        incoming = MemoryRecord(
            agent_id=agent_id,
            memory_type=memory_type,
            content=content,
            entities=entities or [],
            outcome=outcome,
            confidence=confidence,
            context=context or {},
            tags=tags or [],
        )

        initial_state = AgentMemoryStoreState(
            operation="store",
            incoming_memory=incoming,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("agent_memory_store.store") as span:
                span.set_attribute("memory.agent_id", agent_id)
                span.set_attribute(
                    "memory.type",
                    memory_type.value,
                )

                result_dict = await self._app.ainvoke(
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "operation": "store",
                            "agent_id": agent_id,
                        },
                    },
                )

                final = AgentMemoryStoreState.model_validate(result_dict)

                span.set_attribute(
                    "memory.stored_count",
                    final.memories_stored,
                )

            logger.info(
                "memory_store_completed",
                agent_id=agent_id,
                memories_stored=final.memories_stored,
                utilization=(final.storage_utilization),
            )
            return final

        except Exception as e:
            logger.error(
                "memory_store_failed",
                agent_id=agent_id,
                error=str(e),
            )
            return AgentMemoryStoreState(
                operation="store",
                error=str(e),
                current_stage="failed",
            )

    async def recall(
        self,
        query: str = "",
        agent_id: str | None = None,
        memory_type: MemoryType | None = None,
        entities: list[str] | None = None,
        strategy: RetrievalStrategy = (RetrievalStrategy.SEMANTIC_SEARCH),
        limit: int = 10,
    ) -> RetrievalResult:
        """Recall memories matching a query.

        This bypasses the full LangGraph for speed and
        calls the toolkit directly.

        Args:
            query: Search query text.
            agent_id: Filter by agent.
            memory_type: Filter by type.
            entities: Filter by entities.
            strategy: Retrieval strategy.
            limit: Max results.

        Returns:
            RetrievalResult with matching memories.
        """
        logger.info(
            "memory_recall_started",
            query=query[:80] if query else "",
            strategy=strategy.value,
            limit=limit,
        )

        result = await self._toolkit.retrieve_memories(
            query=query,
            agent_id=agent_id,
            memory_type=memory_type,
            entities=entities,
            strategy=strategy,
            limit=limit,
        )

        logger.info(
            "memory_recall_completed",
            total_matches=result.total_matches,
            returned=len(result.memories),
            query_time_ms=result.query_time_ms,
        )

        return result

    async def store_false_positive(
        self,
        alert_hash: str,
        reason: str,
        confidence: float = 0.8,
        agent_id: str = "system",
    ) -> MemoryRecord:
        """Store a false positive learning.

        Args:
            alert_hash: Hash of the alert signature.
            reason: Why this is a false positive.
            confidence: Confidence in the FP judgment.
            agent_id: Agent that identified the FP.

        Returns:
            The stored MemoryRecord.
        """
        return await self._toolkit.store_false_positive(
            alert_hash=alert_hash,
            reason=reason,
            confidence=confidence,
            agent_id=agent_id,
        )

    async def find_similar_incidents(
        self,
        indicators: list[str],
        limit: int = 10,
    ) -> RetrievalResult:
        """Find past incidents with similar indicators.

        Args:
            indicators: IOCs, IPs, hostnames, hashes.
            limit: Max results.

        Returns:
            RetrievalResult with similar incidents.
        """
        return await self._toolkit.retrieve_similar_incidents(
            indicators=indicators,
            limit=limit,
        )

    async def prune(self, max_age_days: int = 90) -> AgentMemoryStoreState:
        """Run the prune workflow via LangGraph.

        Args:
            max_age_days: Max age before pruning.

        Returns:
            Final AgentMemoryStoreState.
        """
        initial_state = AgentMemoryStoreState(
            operation="prune",
        )

        try:
            result_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "operation": "prune",
                    },
                },
            )
            return AgentMemoryStoreState.model_validate(result_dict)
        except Exception as e:
            logger.error(
                "memory_prune_failed",
                error=str(e),
            )
            return AgentMemoryStoreState(
                operation="prune",
                error=str(e),
                current_stage="failed",
            )

    def get_stats(self) -> dict[str, Any]:
        """Get memory store statistics."""
        return self._toolkit.get_stats()

    def list_recent_memories(self, limit: int = 20) -> list[dict[str, Any]]:
        """List recent memories with summary info."""
        sorted_mems = sorted(
            self._toolkit._memories.values(),
            key=lambda m: m.created_at or datetime.min,
            reverse=True,
        )
        return [
            {
                "memory_id": m.memory_id,
                "agent_id": m.agent_id,
                "memory_type": m.memory_type.value,
                "content_preview": m.content[:100],
                "confidence": m.confidence,
                "entities_count": len(m.entities),
                "access_count": m.access_count,
                "created_at": (m.created_at.isoformat() if m.created_at else None),
            }
            for m in sorted_mems[:limit]
        ]
