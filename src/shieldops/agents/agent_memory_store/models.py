"""State models for the Agent Memory Store agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MemoryStage(StrEnum):
    """Stages in the memory store workflow."""

    RECEIVE = "receive_memory"
    CLASSIFY = "classify_memory"
    STORE = "store_memory"
    INDEX = "index_for_retrieval"
    PRUNE = "prune_stale"
    REPORT = "report"


class MemoryType(StrEnum):
    """Categories of episodic memories agents can store."""

    INVESTIGATION_OUTCOME = "investigation_outcome"
    FALSE_POSITIVE_PATTERN = "false_positive_pattern"
    ATTACK_SIGNATURE = "attack_signature"
    REMEDIATION_PLAYBOOK = "remediation_playbook"
    ANALYST_FEEDBACK = "analyst_feedback"
    CONFIGURATION_DRIFT = "configuration_drift"


class RetrievalStrategy(StrEnum):
    """Strategies for retrieving stored memories."""

    SEMANTIC_SEARCH = "semantic_search"
    TEMPORAL = "temporal"
    ENTITY_MATCH = "entity_match"
    PATTERN_MATCH = "pattern_match"


# --- Domain models ---


class MemoryRecord(BaseModel):
    """A single episodic memory stored by an agent."""

    memory_id: str = ""
    agent_id: str = ""
    agent_type: str = ""
    memory_type: MemoryType = MemoryType.INVESTIGATION_OUTCOME
    content: str = ""
    entities: list[str] = Field(default_factory=list)
    outcome: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    context: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
    expires_at: datetime | None = None
    access_count: int = 0
    last_accessed: datetime | None = None
    tags: list[str] = Field(default_factory=list)


class MemoryClassification(BaseModel):
    """LLM-generated classification of a memory."""

    memory_type: str = Field(description="Classified memory type")
    importance_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="How important this memory is",
    )
    keywords: list[str] = Field(
        default_factory=list,
        description="Keywords for indexing",
    )
    related_patterns: list[str] = Field(
        default_factory=list,
        description="Patterns this memory relates to",
    )
    suggested_ttl_days: int = Field(
        default=90,
        description="Suggested time-to-live in days",
    )
    reasoning: str = Field(
        default="",
        description="Why this classification was chosen",
    )


class MemoryIndex(BaseModel):
    """Index entry for fast retrieval of a memory."""

    memory_id: str = ""
    keywords: list[str] = Field(default_factory=list)
    entities: list[str] = Field(default_factory=list)
    memory_type: str = ""
    importance_score: float = 0.0
    embedding_hash: str = ""
    created_at: datetime | None = None


class RetrievalQuery(BaseModel):
    """Query to retrieve memories from the store."""

    query_text: str = ""
    agent_id: str | None = None
    memory_type: MemoryType | None = None
    entities: list[str] = Field(default_factory=list)
    strategy: RetrievalStrategy = RetrievalStrategy.SEMANTIC_SEARCH
    limit: int = Field(default=10, ge=1, le=100)
    min_importance: float = Field(default=0.0, ge=0.0, le=1.0)
    max_age_days: int | None = None


class RetrievalResult(BaseModel):
    """Result of a memory retrieval operation."""

    memories: list[MemoryRecord] = Field(default_factory=list)
    total_matches: int = 0
    strategy_used: RetrievalStrategy = RetrievalStrategy.SEMANTIC_SEARCH
    query_time_ms: int = 0
    relevance_scores: list[float] = Field(default_factory=list)


# --- Agent state ---


class AgentMemoryStoreState(BaseModel):
    """Full state of the agent memory store workflow."""

    # Input
    operation: str = "store"  # store | retrieve | prune
    incoming_memory: MemoryRecord | None = None
    retrieval_query: RetrievalQuery | None = None

    # Processing
    classification: MemoryClassification | None = None
    index_entry: MemoryIndex | None = None

    # Outputs
    memories_stored: int = 0
    memories_retrieved: int = 0
    retrieval_accuracy: float = 0.0
    storage_utilization: float = 0.0
    stale_memories_pruned: int = 0
    retrieval_result: RetrievalResult | None = None

    # Metadata
    current_stage: str = "init"
    error: str = ""
    processing_steps: list[dict[str, Any]] = Field(default_factory=list)
