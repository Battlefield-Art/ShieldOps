"""Agent Episodic Memory — store and recall agent experiences."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MemoryScope(StrEnum):
    INVESTIGATION = "investigation"
    INCIDENT = "incident"
    REMEDIATION = "remediation"
    DETECTION = "detection"


class RetentionPolicy(StrEnum):
    PERMANENT = "permanent"
    YEARLY = "yearly"
    QUARTERLY = "quarterly"
    MONTHLY = "monthly"


class RecallAccuracy(StrEnum):
    EXACT = "exact"
    FUZZY = "fuzzy"
    PARTIAL = "partial"


# --- Models ---


class EpisodeRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    scope: MemoryScope = MemoryScope.INVESTIGATION
    retention: RetentionPolicy = RetentionPolicy.QUARTERLY
    summary: str = ""
    context_keys: list[str] = Field(default_factory=list)
    outcome: str = ""
    confidence: float = 0.0
    decay_factor: float = 1.0
    created_at: float = Field(default_factory=time.time)


class EpisodeAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    total_episodes: int = 0
    avg_confidence: float = 0.0
    avg_decay: float = 0.0
    scope_distribution: dict[str, int] = Field(default_factory=dict)
    recall_quality: RecallAccuracy = RecallAccuracy.EXACT
    analyzed_at: float = Field(default_factory=time.time)


class EpisodeReport(BaseModel):
    total_episodes: int = 0
    by_scope: dict[str, int] = Field(default_factory=dict)
    by_retention: dict[str, int] = Field(default_factory=dict)
    avg_confidence: float = 0.0
    avg_decay: float = 0.0
    decayed_count: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentEpisodicMemoryEngine:
    """Store and recall agent episodic experiences."""

    def __init__(
        self,
        max_records: int = 200000,
        decay_rate: float = 0.01,
    ) -> None:
        self._max_records = max_records
        self._decay_rate = decay_rate
        self._records: list[EpisodeRecord] = []
        logger.info(
            "agent_episodic_memory.initialized",
            max_records=max_records,
            decay_rate=decay_rate,
        )

    # -- record / query --

    def add_record(
        self,
        agent_id: str,
        scope: MemoryScope = MemoryScope.INVESTIGATION,
        retention: RetentionPolicy = RetentionPolicy.QUARTERLY,
        summary: str = "",
        context_keys: list[str] | None = None,
        outcome: str = "",
        confidence: float = 0.5,
    ) -> EpisodeRecord:
        record = EpisodeRecord(
            agent_id=agent_id,
            scope=scope,
            retention=retention,
            summary=summary,
            context_keys=context_keys or [],
            outcome=outcome,
            confidence=confidence,
            decay_factor=1.0,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_episodic_memory.record_added",
            record_id=record.id,
            agent_id=agent_id,
            scope=scope.value,
        )
        return record

    def process(self, agent_id: str) -> EpisodeAnalysis:
        episodes = [r for r in self._records if r.agent_id == agent_id]
        if not episodes:
            return EpisodeAnalysis(agent_id=agent_id)
        avg_conf = round(
            sum(e.confidence for e in episodes) / len(episodes),
            4,
        )
        avg_decay = round(
            sum(e.decay_factor for e in episodes) / len(episodes),
            4,
        )
        scope_dist: dict[str, int] = {}
        for e in episodes:
            key = e.scope.value
            scope_dist[key] = scope_dist.get(key, 0) + 1
        if avg_decay > 0.8:
            quality = RecallAccuracy.EXACT
        elif avg_decay > 0.5:
            quality = RecallAccuracy.FUZZY
        else:
            quality = RecallAccuracy.PARTIAL
        return EpisodeAnalysis(
            agent_id=agent_id,
            total_episodes=len(episodes),
            avg_confidence=avg_conf,
            avg_decay=avg_decay,
            scope_distribution=scope_dist,
            recall_quality=quality,
        )

    def generate_report(self) -> EpisodeReport:
        by_scope: dict[str, int] = {}
        by_retention: dict[str, int] = {}
        for r in self._records:
            by_scope[r.scope.value] = by_scope.get(r.scope.value, 0) + 1
            by_retention[r.retention.value] = by_retention.get(r.retention.value, 0) + 1
        total = len(self._records)
        avg_conf = (
            round(
                sum(r.confidence for r in self._records) / total,
                4,
            )
            if total
            else 0.0
        )
        avg_decay = (
            round(
                sum(r.decay_factor for r in self._records) / total,
                4,
            )
            if total
            else 0.0
        )
        decayed = sum(1 for r in self._records if r.decay_factor < 0.5)
        recs: list[str] = []
        if decayed > 0:
            recs.append(f"{decayed} episode(s) significantly decayed")
        if avg_conf < 0.5:
            recs.append("Low average confidence — review episode quality")
        if not recs:
            recs.append("Episodic memory health is good")
        return EpisodeReport(
            total_episodes=total,
            by_scope=by_scope,
            by_retention=by_retention,
            avg_confidence=avg_conf,
            avg_decay=avg_decay,
            decayed_count=decayed,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        scope_dist: dict[str, int] = {}
        for r in self._records:
            key = r.scope.value
            scope_dist[key] = scope_dist.get(key, 0) + 1
        return {
            "total_episodes": len(self._records),
            "max_records": self._max_records,
            "decay_rate": self._decay_rate,
            "scope_distribution": scope_dist,
            "unique_agents": len({r.agent_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("agent_episodic_memory.cleared")
        return {"status": "cleared"}

    # -- domain operations --

    def store_episode(
        self,
        agent_id: str,
        scope: MemoryScope,
        summary: str,
        context_keys: list[str] | None = None,
        outcome: str = "",
        confidence: float = 0.5,
    ) -> dict[str, Any]:
        """Store a new episode in agent memory."""
        record = self.add_record(
            agent_id=agent_id,
            scope=scope,
            summary=summary,
            context_keys=context_keys,
            outcome=outcome,
            confidence=confidence,
        )
        logger.info(
            "agent_episodic_memory.episode_stored",
            record_id=record.id,
            agent_id=agent_id,
        )
        return {
            "record_id": record.id,
            "agent_id": agent_id,
            "scope": scope.value,
            "summary": summary,
            "stored": True,
        }

    def recall_similar(
        self,
        agent_id: str,
        context_keys: list[str],
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Recall episodes matching context keys."""
        candidates = [r for r in self._records if r.agent_id == agent_id]
        scored: list[tuple[float, EpisodeRecord]] = []
        for ep in candidates:
            overlap = len(set(ep.context_keys) & set(context_keys))
            if overlap > 0:
                score = overlap * ep.decay_factor * ep.confidence
                scored.append((score, ep))
        scored.sort(key=lambda x: x[0], reverse=True)
        results: list[dict[str, Any]] = []
        for score, ep in scored[:limit]:
            accuracy = RecallAccuracy.EXACT
            if ep.decay_factor < 0.5:
                accuracy = RecallAccuracy.PARTIAL
            elif ep.decay_factor < 0.8:
                accuracy = RecallAccuracy.FUZZY
            results.append(
                {
                    "record_id": ep.id,
                    "summary": ep.summary,
                    "outcome": ep.outcome,
                    "relevance_score": round(score, 4),
                    "accuracy": accuracy.value,
                    "decay_factor": ep.decay_factor,
                }
            )
        logger.info(
            "agent_episodic_memory.recall_similar",
            agent_id=agent_id,
            matches=len(results),
        )
        return results

    def calculate_decay(
        self,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        """Apply time-based decay to episode memories."""
        now = time.time()
        targets = self._records
        if agent_id:
            targets = [r for r in self._records if r.agent_id == agent_id]
        updated = 0
        for ep in targets:
            age_days = (now - ep.created_at) / 86400
            new_decay = max(
                0.0,
                1.0 - (self._decay_rate * age_days),
            )
            if new_decay != ep.decay_factor:
                ep.decay_factor = round(new_decay, 4)
                updated += 1
        decayed_count = sum(1 for r in targets if r.decay_factor < 0.5)
        logger.info(
            "agent_episodic_memory.decay_calculated",
            updated=updated,
            decayed_count=decayed_count,
        )
        return {
            "total_processed": len(targets),
            "updated": updated,
            "decayed_below_threshold": decayed_count,
            "decay_rate": self._decay_rate,
        }
