"""LLM provider configuration."""

from pydantic import BaseModel


class LlmConfig(BaseModel):
    """LLM provider and routing settings."""

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    llm_routing_enabled: bool = False
    llm_simple_model: str = "claude-haiku-4-5-20251001"
    llm_moderate_model: str = "claude-sonnet-4-20250514"
    llm_complex_model: str = "claude-opus-4-20250514"
    rag_enabled: bool = False
    rag_embedding_model: str = "text-embedding-3-small"
