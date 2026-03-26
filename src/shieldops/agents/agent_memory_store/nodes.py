"""Node implementations for the Agent Memory Store workflow.

Each node is an async function that processes memory
operations: receiving, classifying, storing, indexing,
pruning, and reporting.
"""

import contextlib
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import structlog

from shieldops.agents.agent_memory_store.models import (
    AgentMemoryStoreState,
    MemoryClassification,
    MemoryIndex,
    MemoryType,
)
from shieldops.agents.agent_memory_store.prompts import (
    SYSTEM_CLASSIFY_MEMORY,
    SYSTEM_INDEX_MEMORY,
    ClassificationOutput,
    IndexingOutput,
)
from shieldops.agents.agent_memory_store.tools import (
    AgentMemoryStoreToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by the runner.
_toolkit: AgentMemoryStoreToolkit | None = None


def set_toolkit(
    toolkit: AgentMemoryStoreToolkit,
) -> None:
    """Configure the toolkit for all nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> AgentMemoryStoreToolkit:
    if _toolkit is None:
        return AgentMemoryStoreToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


def _step(
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
) -> dict[str, Any]:
    return {
        "action": action,
        "input_summary": input_summary,
        "output_summary": output_summary,
        "duration_ms": duration_ms,
    }


async def receive_memory(
    state: AgentMemoryStoreState,
) -> dict[str, Any]:
    """Validate and prepare incoming memory for storage."""
    start = datetime.now(UTC)

    logger.info(
        "memory_receive_started",
        operation=state.operation,
        has_memory=state.incoming_memory is not None,
        has_query=(state.retrieval_query is not None),
    )

    output = "No incoming memory to process"
    if state.incoming_memory:
        mem = state.incoming_memory
        if not mem.memory_id:
            mem.memory_id = f"mem-{uuid4().hex[:12]}"
        if not mem.created_at:
            mem.created_at = datetime.now(UTC)
        output = f"Received memory {mem.memory_id} from agent {mem.agent_id}: {mem.content[:80]}"

    step = _step(
        "receive_memory",
        f"Operation: {state.operation}",
        output,
        _elapsed_ms(start),
    )

    return {
        "current_stage": "receive_memory",
        "processing_steps": [
            *state.processing_steps,
            step,
        ],
    }


async def classify_memory(
    state: AgentMemoryStoreState,
) -> dict[str, Any]:
    """Classify memory type and importance using LLM."""
    start = datetime.now(UTC)

    if state.incoming_memory is None:
        step = _step(
            "classify_memory",
            "No memory to classify",
            "Skipped — no incoming memory",
            _elapsed_ms(start),
        )
        return {
            "current_stage": "classify_memory",
            "processing_steps": [
                *state.processing_steps,
                step,
            ],
        }

    mem = state.incoming_memory
    classification: MemoryClassification | None = None
    output = "Classification pending"

    # Build context for LLM
    context_lines = [
        "## Memory to Classify",
        f"Agent: {mem.agent_id} ({mem.agent_type})",
        f"Content: {mem.content}",
        f"Outcome: {mem.outcome}",
        f"Entities: {', '.join(mem.entities[:20])}",
        f"Tags: {', '.join(mem.tags[:10])}",
        f"Confidence: {mem.confidence}",
    ]
    user_prompt = "\n".join(context_lines)

    try:
        result = cast(
            ClassificationOutput,
            await llm_structured(
                system_prompt=SYSTEM_CLASSIFY_MEMORY,
                user_prompt=user_prompt,
                schema=ClassificationOutput,
            ),
        )

        classification = MemoryClassification(
            memory_type=result.memory_type,
            importance_score=result.importance_score,
            keywords=result.keywords,
            related_patterns=result.related_patterns,
            suggested_ttl_days=result.suggested_ttl_days,
            reasoning=result.reasoning,
        )

        output = (
            f"Classified as {result.memory_type} "
            f"(importance: {result.importance_score:.2f}"
            f", TTL: {result.suggested_ttl_days}d)"
        )
    except Exception as e:
        logger.error(
            "llm_classify_memory_failed",
            error=str(e),
        )
        # Fallback: use provided type
        classification = MemoryClassification(
            memory_type=mem.memory_type.value,
            importance_score=mem.confidence,
            keywords=mem.tags,
            related_patterns=[],
            suggested_ttl_days=90,
            reasoning=f"Fallback classification: {e}",
        )
        output = f"Fallback classification: {mem.memory_type.value}"

    step = _step(
        "classify_memory",
        f"Classifying memory {mem.memory_id}",
        output,
        _elapsed_ms(start),
    )

    return {
        "classification": classification,
        "current_stage": "classify_memory",
        "processing_steps": [
            *state.processing_steps,
            step,
        ],
    }


async def store_memory(
    state: AgentMemoryStoreState,
) -> dict[str, Any]:
    """Persist memory to the store via toolkit."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if state.incoming_memory is None:
        step = _step(
            "store_memory",
            "No memory to store",
            "Skipped — no incoming memory",
            _elapsed_ms(start),
        )
        return {
            "current_stage": "store_memory",
            "processing_steps": [
                *state.processing_steps,
                step,
            ],
        }

    mem = state.incoming_memory
    ttl = None
    if state.classification:
        ttl = state.classification.suggested_ttl_days

    # Determine memory type from classification
    memory_type = mem.memory_type
    if state.classification:
        with contextlib.suppress(ValueError):
            memory_type = MemoryType(state.classification.memory_type)

    record = await toolkit.store_memory(
        agent_id=mem.agent_id,
        memory_type=memory_type,
        content=mem.content,
        entities=mem.entities,
        outcome=mem.outcome,
        confidence=mem.confidence,
        context=mem.context,
        tags=mem.tags,
        ttl_days=ttl,
    )

    stats = toolkit.get_stats()
    output = (
        f"Stored {record.memory_id} (type: {memory_type.value}, total: {stats['total_memories']})"
    )

    step = _step(
        "store_memory",
        f"Storing memory from {mem.agent_id}",
        output,
        _elapsed_ms(start),
    )

    return {
        "memories_stored": state.memories_stored + 1,
        "storage_utilization": stats["utilization"],
        "current_stage": "store_memory",
        "processing_steps": [
            *state.processing_steps,
            step,
        ],
    }


async def index_for_retrieval(
    state: AgentMemoryStoreState,
) -> dict[str, Any]:
    """Generate search index using LLM."""
    start = datetime.now(UTC)

    if state.incoming_memory is None:
        step = _step(
            "index_for_retrieval",
            "No memory to index",
            "Skipped — no incoming memory",
            _elapsed_ms(start),
        )
        return {
            "current_stage": "index_for_retrieval",
            "processing_steps": [
                *state.processing_steps,
                step,
            ],
        }

    mem = state.incoming_memory
    index_entry: MemoryIndex | None = None
    output = "Indexing pending"

    context_lines = [
        "## Memory to Index",
        f"Content: {mem.content}",
        f"Outcome: {mem.outcome}",
        f"Entities: {', '.join(mem.entities[:20])}",
        f"Type: {mem.memory_type.value}",
    ]
    if state.classification:
        context_lines.extend(
            [
                "",
                "## Classification",
                f"Keywords: {', '.join(state.classification.keywords)}",
                f"Patterns: {', '.join(state.classification.related_patterns)}",
            ]
        )

    user_prompt = "\n".join(context_lines)

    try:
        result = cast(
            IndexingOutput,
            await llm_structured(
                system_prompt=SYSTEM_INDEX_MEMORY,
                user_prompt=user_prompt,
                schema=IndexingOutput,
            ),
        )

        index_entry = MemoryIndex(
            memory_id=mem.memory_id,
            keywords=result.keywords,
            entities=(mem.entities + result.entity_aliases),
            memory_type=mem.memory_type.value,
            importance_score=(
                state.classification.importance_score if state.classification else mem.confidence
            ),
            embedding_hash=str(hash(result.embedding_text)),
            created_at=mem.created_at,
        )

        # Store index in toolkit
        toolkit = _get_toolkit()
        toolkit._indices[mem.memory_id] = index_entry

        # Add alias entities to entity map
        for alias in result.entity_aliases:
            normalized = alias.lower().strip()
            toolkit._entity_map.setdefault(normalized, []).append(mem.memory_id)

        output = (
            f"Indexed {mem.memory_id} with "
            f"{len(result.keywords)} keywords, "
            f"{len(result.entity_aliases)} aliases"
        )
    except Exception as e:
        logger.error(
            "llm_index_memory_failed",
            error=str(e),
        )
        # Fallback: use raw entities and tags
        index_entry = MemoryIndex(
            memory_id=mem.memory_id,
            keywords=mem.tags,
            entities=mem.entities,
            memory_type=mem.memory_type.value,
            importance_score=mem.confidence,
            created_at=mem.created_at,
        )
        toolkit = _get_toolkit()
        toolkit._indices[mem.memory_id] = index_entry
        output = f"Fallback index for {mem.memory_id}"

    step = _step(
        "index_for_retrieval",
        f"Indexing memory {mem.memory_id}",
        output,
        _elapsed_ms(start),
    )

    return {
        "index_entry": index_entry,
        "current_stage": "index_for_retrieval",
        "processing_steps": [
            *state.processing_steps,
            step,
        ],
    }


async def prune_stale(
    state: AgentMemoryStoreState,
) -> dict[str, Any]:
    """Prune expired and low-value memories."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    pruned = await toolkit.prune_stale_memories(max_age_days=90)
    stats = toolkit.get_stats()

    output = f"Pruned {pruned} stale memories. Remaining: {stats['total_memories']}"

    step = _step(
        "prune_stale",
        "Pruning expired/low-value memories",
        output,
        _elapsed_ms(start),
    )

    return {
        "stale_memories_pruned": (state.stale_memories_pruned + pruned),
        "storage_utilization": stats["utilization"],
        "current_stage": "prune_stale",
        "processing_steps": [
            *state.processing_steps,
            step,
        ],
    }


async def report(
    state: AgentMemoryStoreState,
) -> dict[str, Any]:
    """Generate final report on memory operations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()
    stats = toolkit.get_stats()

    output = (
        f"Stored: {state.memories_stored}, "
        f"Retrieved: {state.memories_retrieved}, "
        f"Pruned: {state.stale_memories_pruned}, "
        f"Total: {stats['total_memories']}, "
        f"Utilization: {stats['utilization']:.1%}"
    )

    step = _step(
        "report",
        "Generating memory store report",
        output,
        _elapsed_ms(start),
    )

    return {
        "storage_utilization": stats["utilization"],
        "current_stage": "report",
        "processing_steps": [
            *state.processing_steps,
            step,
        ],
    }
