"""Tool functions for the Agent Memory Store agent.

Provides persistent episodic memory storage and
retrieval for all ShieldOps agents. Uses an in-memory
ring buffer with optional database persistence.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.agent_memory_store.models import (
    MemoryIndex,
    MemoryRecord,
    MemoryType,
    RetrievalResult,
    RetrievalStrategy,
)

logger = structlog.get_logger()

# Default max memories before eviction
DEFAULT_MAX_RECORDS = 10_000


class AgentMemoryStoreToolkit:
    """Toolkit for storing and retrieving agent memories.

    Provides episodic memory that any agent can write to
    and read from, enabling cross-agent learning.
    """

    def __init__(
        self,
        max_records: int = DEFAULT_MAX_RECORDS,
        repository: Any = None,
    ) -> None:
        self._max_records = max_records
        self._repository = repository
        # Ring-buffer storage keyed by memory_id
        self._memories: dict[str, MemoryRecord] = {}
        # Index for fast lookup
        self._indices: dict[str, MemoryIndex] = {}
        # Entity-to-memory mapping
        self._entity_map: dict[str, list[str]] = {}
        # Type-to-memory mapping
        self._type_map: dict[str, list[str]] = {}
        # FP hash cache for deduplication
        self._fp_hashes: dict[str, str] = {}

    async def store_memory(
        self,
        agent_id: str,
        memory_type: MemoryType,
        content: str,
        entities: list[str] | None = None,
        outcome: str = "",
        confidence: float = 0.5,
        context: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        ttl_days: int | None = None,
    ) -> MemoryRecord:
        """Store an episodic memory from an agent.

        Args:
            agent_id: ID of the agent storing memory.
            memory_type: Category of the memory.
            content: The memory content/description.
            entities: Related entities (IPs, hosts, etc).
            outcome: Outcome or result of the episode.
            confidence: Confidence in the memory.
            context: Additional context metadata.
            tags: Tags for categorization.
            ttl_days: Days until memory expires.

        Returns:
            The stored MemoryRecord.
        """
        now = datetime.now(UTC)
        memory_id = f"mem-{uuid4().hex[:12]}"

        expires_at = None
        if ttl_days is not None:
            expires_at = now + timedelta(days=ttl_days)

        record = MemoryRecord(
            memory_id=memory_id,
            agent_id=agent_id,
            memory_type=memory_type,
            content=content,
            entities=entities or [],
            outcome=outcome,
            confidence=confidence,
            context=context or {},
            created_at=now,
            expires_at=expires_at,
            tags=tags or [],
        )

        # Evict oldest if at capacity
        self._evict_if_needed()

        self._memories[memory_id] = record

        # Update type index
        type_key = memory_type.value
        self._type_map.setdefault(type_key, []).append(memory_id)

        # Update entity index
        for entity in record.entities:
            normalized = entity.lower().strip()
            self._entity_map.setdefault(normalized, []).append(memory_id)

        logger.info(
            "memory_stored",
            memory_id=memory_id,
            agent_id=agent_id,
            memory_type=type_key,
            entities_count=len(record.entities),
        )

        return record

    async def retrieve_memories(
        self,
        query: str = "",
        agent_id: str | None = None,
        memory_type: MemoryType | None = None,
        entities: list[str] | None = None,
        strategy: RetrievalStrategy = (RetrievalStrategy.SEMANTIC_SEARCH),
        limit: int = 10,
        min_importance: float = 0.0,
    ) -> RetrievalResult:
        """Retrieve memories matching a query.

        Args:
            query: Search query text.
            agent_id: Filter by agent ID.
            memory_type: Filter by memory type.
            entities: Filter by related entities.
            strategy: Retrieval strategy to use.
            limit: Maximum results to return.
            min_importance: Minimum importance threshold.

        Returns:
            RetrievalResult with matching memories.
        """
        start = datetime.now(UTC)
        candidates: list[MemoryRecord] = []

        if strategy == RetrievalStrategy.ENTITY_MATCH:
            candidates = self._retrieve_by_entity(entities or [])
        elif strategy == RetrievalStrategy.TEMPORAL:
            candidates = self._retrieve_temporal(limit)
        elif strategy == RetrievalStrategy.PATTERN_MATCH:
            candidates = self._retrieve_by_pattern(query)
        else:
            # Semantic search: keyword matching fallback
            candidates = self._retrieve_semantic(query)

        # Apply filters
        if agent_id:
            candidates = [m for m in candidates if m.agent_id == agent_id]
        if memory_type:
            candidates = [m for m in candidates if m.memory_type == memory_type]

        # Filter expired
        now = datetime.now(UTC)
        candidates = [m for m in candidates if m.expires_at is None or m.expires_at > now]

        # Sort by confidence descending, limit
        candidates.sort(key=lambda m: m.confidence, reverse=True)
        results = candidates[:limit]

        # Update access counts
        for mem in results:
            mem.access_count += 1
            mem.last_accessed = now

        elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)

        logger.info(
            "memories_retrieved",
            query=query[:80] if query else "",
            strategy=strategy.value,
            total_matches=len(candidates),
            returned=len(results),
            query_time_ms=elapsed,
        )

        return RetrievalResult(
            memories=results,
            total_matches=len(candidates),
            strategy_used=strategy,
            query_time_ms=elapsed,
            relevance_scores=[m.confidence for m in results],
        )

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
        # Check for duplicate FP hash
        if alert_hash in self._fp_hashes:
            existing_id = self._fp_hashes[alert_hash]
            existing = self._memories.get(existing_id)
            if existing:
                existing.access_count += 1
                existing.confidence = max(existing.confidence, confidence)
                return existing

        record = await self.store_memory(
            agent_id=agent_id,
            memory_type=MemoryType.FALSE_POSITIVE_PATTERN,
            content=(f"False positive: {reason}. Alert hash: {alert_hash}"),
            entities=[alert_hash],
            outcome="false_positive",
            confidence=confidence,
            context={"alert_hash": alert_hash},
            tags=["false_positive", "noise_reduction"],
            ttl_days=180,
        )

        self._fp_hashes[alert_hash] = record.memory_id
        return record

    async def retrieve_similar_incidents(
        self,
        indicators: list[str],
        limit: int = 10,
    ) -> RetrievalResult:
        """Find past incidents similar to given indicators.

        Args:
            indicators: IOCs, IPs, hostnames, hashes.
            limit: Max results to return.

        Returns:
            RetrievalResult with similar incidents.
        """
        # Combine entity-based and pattern-based retrieval
        entity_results = self._retrieve_by_entity(indicators)
        pattern_results = self._retrieve_by_pattern(" ".join(indicators))

        # Merge and deduplicate
        seen: set[str] = set()
        merged: list[MemoryRecord] = []
        for mem in entity_results + pattern_results:
            if mem.memory_id not in seen:
                seen.add(mem.memory_id)
                merged.append(mem)

        # Filter to investigation/attack types
        relevant_types = {
            MemoryType.INVESTIGATION_OUTCOME,
            MemoryType.ATTACK_SIGNATURE,
        }
        merged = [m for m in merged if m.memory_type in relevant_types]

        merged.sort(key=lambda m: m.confidence, reverse=True)
        results = merged[:limit]

        return RetrievalResult(
            memories=results,
            total_matches=len(merged),
            strategy_used=RetrievalStrategy.ENTITY_MATCH,
            query_time_ms=0,
            relevance_scores=[m.confidence for m in results],
        )

    async def prune_stale_memories(
        self,
        max_age_days: int = 90,
    ) -> int:
        """Remove memories older than max_age_days.

        Args:
            max_age_days: Max age in days before pruning.

        Returns:
            Number of memories pruned.
        """
        cutoff = datetime.now(UTC) - timedelta(days=max_age_days)
        pruned_ids: list[str] = []

        for mid, mem in list(self._memories.items()):
            should_prune = False

            # Prune if explicitly expired
            if (
                mem.expires_at
                and mem.expires_at < cutoff
                or (mem.created_at and mem.created_at < cutoff and mem.access_count < 3)
            ):
                should_prune = True

            if should_prune:
                pruned_ids.append(mid)

        for mid in pruned_ids:
            self._remove_memory(mid)

        logger.info(
            "memories_pruned",
            pruned_count=len(pruned_ids),
            max_age_days=max_age_days,
            remaining=len(self._memories),
        )

        return len(pruned_ids)

    def get_stats(self) -> dict[str, Any]:
        """Get memory store statistics."""
        type_counts: dict[str, int] = {}
        for mem in self._memories.values():
            key = mem.memory_type.value
            type_counts[key] = type_counts.get(key, 0) + 1

        return {
            "total_memories": len(self._memories),
            "max_capacity": self._max_records,
            "utilization": (
                len(self._memories) / self._max_records if self._max_records > 0 else 0.0
            ),
            "type_distribution": type_counts,
            "total_entities_indexed": len(self._entity_map),
            "fp_patterns_stored": len(self._fp_hashes),
            "unique_agents": len({m.agent_id for m in self._memories.values()}),
        }

    # --- Private helpers ---

    def _evict_if_needed(self) -> None:
        """Evict oldest low-access memories if at cap."""
        if len(self._memories) < self._max_records:
            return

        # Sort by (access_count, created_at) ascending
        sorted_mems = sorted(
            self._memories.items(),
            key=lambda kv: (
                kv[1].access_count,
                kv[1].created_at or datetime.min,
            ),
        )

        # Evict bottom 10%
        evict_count = max(1, self._max_records // 10)
        for mid, _ in sorted_mems[:evict_count]:
            self._remove_memory(mid)

    def _remove_memory(self, memory_id: str) -> None:
        """Remove a memory and clean up indices."""
        mem = self._memories.pop(memory_id, None)
        if mem is None:
            return

        self._indices.pop(memory_id, None)

        # Clean entity index
        for entity in mem.entities:
            normalized = entity.lower().strip()
            ids = self._entity_map.get(normalized, [])
            if memory_id in ids:
                ids.remove(memory_id)
                if not ids:
                    self._entity_map.pop(normalized, None)

        # Clean type index
        type_key = mem.memory_type.value
        ids = self._type_map.get(type_key, [])
        if memory_id in ids:
            ids.remove(memory_id)

        # Clean FP hash
        for h, mid in list(self._fp_hashes.items()):
            if mid == memory_id:
                del self._fp_hashes[h]
                break

    def _retrieve_by_entity(self, entities: list[str]) -> list[MemoryRecord]:
        """Retrieve memories matching given entities."""
        memory_ids: set[str] = set()
        for entity in entities:
            normalized = entity.lower().strip()
            ids = self._entity_map.get(normalized, [])
            memory_ids.update(ids)

        return [self._memories[mid] for mid in memory_ids if mid in self._memories]

    def _retrieve_temporal(self, limit: int) -> list[MemoryRecord]:
        """Retrieve most recent memories."""
        sorted_mems = sorted(
            self._memories.values(),
            key=lambda m: m.created_at or datetime.min,
            reverse=True,
        )
        return sorted_mems[:limit]

    def _retrieve_by_pattern(self, query: str) -> list[MemoryRecord]:
        """Retrieve memories matching query patterns."""
        if not query:
            return []

        query_lower = query.lower()
        query_terms = set(query_lower.split())
        results: list[MemoryRecord] = []

        for mem in self._memories.values():
            content_lower = mem.content.lower()
            # Score based on term overlap
            matches = sum(1 for t in query_terms if t in content_lower)
            if matches > 0:
                results.append(mem)

        return results

    def _retrieve_semantic(self, query: str) -> list[MemoryRecord]:
        """Semantic retrieval with keyword fallback.

        In production this would use vector embeddings.
        Falls back to keyword matching.
        """
        if not query:
            return list(self._memories.values())

        # Check index keywords first
        query_lower = query.lower()
        query_terms = set(query_lower.split())
        scored: list[tuple[float, MemoryRecord]] = []

        for mid, mem in self._memories.items():
            score = 0.0
            idx = self._indices.get(mid)

            # Score from index keywords
            if idx and idx.keywords:
                kw_set = {k.lower() for k in idx.keywords}
                overlap = len(query_terms & kw_set)
                if overlap > 0:
                    score += overlap * 0.3

            # Score from content match
            content_lower = mem.content.lower()
            content_matches = sum(1 for t in query_terms if t in content_lower)
            score += content_matches * 0.2

            # Score from entity match
            entity_set = {e.lower() for e in mem.entities}
            entity_overlap = len(query_terms & entity_set)
            score += entity_overlap * 0.4

            # Score from tag match
            tag_set = {t.lower() for t in mem.tags}
            tag_overlap = len(query_terms & tag_set)
            score += tag_overlap * 0.1

            if score > 0:
                scored.append((score, mem))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [mem for _, mem in scored]
