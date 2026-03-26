"""LLM prompt templates and response schemas for the Agent Memory Store."""

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class ClassificationOutput(BaseModel):
    """Structured output from LLM memory classification."""

    memory_type: str = Field(
        description=(
            "Type: investigation_outcome, "
            "false_positive_pattern, attack_signature, "
            "remediation_playbook, analyst_feedback, "
            "configuration_drift"
        )
    )
    importance_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Importance from 0.0 to 1.0",
    )
    keywords: list[str] = Field(description="Keywords for retrieval indexing")
    related_patterns: list[str] = Field(description="Related patterns or signatures")
    suggested_ttl_days: int = Field(description="Suggested retention in days")
    reasoning: str = Field(description="Why this classification was chosen")


class IndexingOutput(BaseModel):
    """Structured output from LLM memory indexing."""

    keywords: list[str] = Field(description="Semantic keywords for search")
    entity_aliases: list[str] = Field(
        description=("Normalized entity names (e.g., IP aliases, hostnames)")
    )
    summary: str = Field(description="One-line summary for fast scanning")
    embedding_text: str = Field(description=("Optimized text for embedding generation"))


class RelevanceOutput(BaseModel):
    """Structured output from LLM relevance scoring."""

    relevance_scores: list[float] = Field(description="Relevance score per candidate memory")
    reasoning: list[str] = Field(description="Why each memory is/isn't relevant")
    recommended_order: list[int] = Field(description="Indices sorted by relevance")


# --- Prompt templates ---

SYSTEM_CLASSIFY_MEMORY = """\
You are a memory classification engine for an AI \
security operations platform.

Your task is to classify an episodic memory stored \
by a security agent. Determine:
1. The memory type (investigation_outcome, \
false_positive_pattern, attack_signature, \
remediation_playbook, analyst_feedback, \
configuration_drift)
2. Its importance score (0.0-1.0)
3. Keywords for retrieval indexing
4. Related patterns this memory connects to
5. How long it should be retained (TTL in days)

GUIDELINES:
- Attack signatures and false positive patterns are \
high importance (>0.7)
- Analyst feedback is always high importance (>0.8)
- Remediation playbooks should have long TTL (180+ days)
- Investigation outcomes vary by severity
- Configuration drift memories expire faster (30-60 days)"""

SYSTEM_INDEX_MEMORY = """\
You are a memory indexing engine for an AI security \
operations platform.

Your task is to generate optimal search metadata for \
a classified memory so it can be retrieved later by \
any agent. Produce:
1. Semantic keywords (include synonyms and related \
terms for broad retrieval)
2. Normalized entity names (expand IPs, hostnames, \
service names into searchable aliases)
3. A one-line summary for fast scanning
4. Optimized text for embedding generation (combine \
the key facts into a dense retrieval-friendly passage)

Focus on recall: it is better to over-index than to \
miss a relevant memory during retrieval."""

SYSTEM_SCORE_RELEVANCE = """\
You are a relevance scoring engine for an AI security \
operations platform.

Given a retrieval query and a list of candidate \
memories, score each memory for relevance to the \
query. Consider:
1. Semantic similarity to the query
2. Entity overlap (IPs, hosts, users mentioned)
3. Temporal relevance (recent memories score higher)
4. Pattern similarity (similar attack types, \
alert signatures)

Score each memory from 0.0 (irrelevant) to 1.0 \
(exact match). Be discriminating — only score \
above 0.7 if there is strong evidence of relevance."""
