"""Multi-cloud LLM provider abstraction.

Supports: Anthropic (direct), AWS Bedrock (via Strands), Google Vertex AI, Azure OpenAI.
All providers expose the same interface so agents work identically across clouds.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import structlog
from pydantic import BaseModel

logger = structlog.get_logger()


class LLMProvider(ABC):
    """Abstract base for all LLM providers.

    Every provider must implement ``analyze()`` for free-form text completions
    and ``structured()`` for Pydantic-validated structured output.
    """

    provider_name: str = ""

    @abstractmethod
    async def analyze(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        """Run a text completion and return ``{"content": str}``."""

    @abstractmethod
    async def structured(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: type[BaseModel],
    ) -> BaseModel | dict[str, Any]:
        """Run a structured output completion validated against *schema*."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_to_schema(raw_text: str, schema: type[BaseModel]) -> BaseModel | dict[str, Any]:
    """Best-effort parse of LLM text into a Pydantic model.

    Tries JSON extraction first, then falls back to returning the raw dict.
    """
    # Strip markdown code fences if present
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # Remove first and last fence lines
        lines = [ln for ln in lines if not ln.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        data = json.loads(text)
        return schema.model_validate(data)
    except (json.JSONDecodeError, Exception) as exc:
        logger.warning(
            "llm_providers.parse_fallback",
            error=str(exc),
            raw_length=len(raw_text),
        )
        return {"content": raw_text}


# ---------------------------------------------------------------------------
# Anthropic — current default, delegates to existing llm.py
# ---------------------------------------------------------------------------


class AnthropicProvider(LLMProvider):
    """Direct Anthropic API via langchain-anthropic (current default).

    Delegates to the existing ``get_llm()`` singleton so behaviour is
    identical to the original ``llm_analyze`` / ``llm_structured`` helpers.
    """

    provider_name = "anthropic"

    def __init__(
        self,
        model: str = "",
        api_key: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ) -> None:
        self._model = model
        self._api_key = api_key
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._llm: Any = None

    def _ensure_llm(self) -> Any:
        if self._llm is not None:
            return self._llm
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError as exc:
            raise RuntimeError(
                "langchain-anthropic not installed. Run: pip install langchain-anthropic"
            ) from exc

        if self._model and self._api_key:
            self._llm = ChatAnthropic(  # type: ignore[call-arg]
                model=self._model,
                api_key=self._api_key,  # type: ignore[arg-type]
                max_tokens=self._max_tokens,
                temperature=self._temperature,
            )
        else:
            # Fall back to the shared singleton
            from shieldops.utils.llm import get_llm

            self._llm = get_llm()
        return self._llm

    async def analyze(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        from langchain_core.messages import HumanMessage, SystemMessage

        llm = self._ensure_llm()
        messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
        response = await llm.ainvoke(messages)
        return {"content": response.content}

    async def structured(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: type[BaseModel],
    ) -> BaseModel | dict[str, Any]:
        from langchain_core.messages import HumanMessage, SystemMessage

        llm = self._ensure_llm()
        structured_llm = llm.with_structured_output(schema)
        messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
        return await structured_llm.ainvoke(messages)


# ---------------------------------------------------------------------------
# AWS Bedrock via Strands Agents SDK
# ---------------------------------------------------------------------------


class BedrockStrandsProvider(LLMProvider):
    """AWS Bedrock via Strands Agents SDK.

    Uses ``strands-agents`` package for Bedrock model access.
    Supports Claude on Bedrock, Amazon Nova, and other Bedrock models.

    Install: ``pip install strands-agents strands-agents-bedrock``
    """

    provider_name = "bedrock"

    def __init__(
        self,
        model_id: str = "anthropic.claude-sonnet-4-20250514-v1:0",
        region: str = "us-east-1",
        temperature: float = 0.1,
    ) -> None:
        self._model_id = model_id
        self._region = region
        self._temperature = temperature
        self._model: Any = None

    def _ensure_model(self) -> Any:
        if self._model is not None:
            return self._model
        try:
            from strands.models import BedrockModel
        except ImportError as exc:
            raise RuntimeError(
                "strands-agents not installed. "
                "Run: pip install strands-agents strands-agents-bedrock"
            ) from exc
        self._model = BedrockModel(
            model_id=self._model_id,
            region_name=self._region,
            temperature=self._temperature,
        )
        return self._model

    async def analyze(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        import asyncio

        model = self._ensure_model()

        try:
            from strands import Agent
        except ImportError as exc:
            raise RuntimeError(
                "strands-agents not installed. Run: pip install strands-agents"
            ) from exc

        agent = Agent(model=model, system_prompt=system_prompt)

        # Strands Agent __call__ is synchronous — run in executor
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, agent, user_prompt)
        content = str(result)
        logger.debug("bedrock_strands.analyze", content_length=len(content))
        return {"content": content}

    async def structured(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: type[BaseModel],
    ) -> BaseModel | dict[str, Any]:
        schema_json = json.dumps(schema.model_json_schema(), indent=2)
        augmented_system = (
            f"{system_prompt}\n\n"
            f"You MUST respond with valid JSON matching this schema:\n{schema_json}\n"
            f"Return ONLY the JSON object, no other text."
        )
        result = await self.analyze(augmented_system, user_prompt)
        return _parse_to_schema(result["content"], schema)


# ---------------------------------------------------------------------------
# Google Vertex AI
# ---------------------------------------------------------------------------


class VertexAIProvider(LLMProvider):
    """Google Vertex AI via langchain-google-vertexai.

    Uses Gemini models on Vertex AI.

    Install: ``pip install langchain-google-vertexai``
    """

    provider_name = "vertex_ai"

    def __init__(
        self,
        model_id: str = "gemini-2.0-flash",
        project: str = "",
        location: str = "us-central1",
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> None:
        self._model_id = model_id
        self._project = project or ""
        self._location = location
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._llm: Any = None

    def _ensure_llm(self) -> Any:
        if self._llm is not None:
            return self._llm
        try:
            from langchain_google_vertexai import ChatVertexAI
        except ImportError as exc:
            raise RuntimeError(
                "langchain-google-vertexai not installed. "
                "Run: pip install langchain-google-vertexai"
            ) from exc

        kwargs: dict[str, Any] = {
            "model_name": self._model_id,
            "temperature": self._temperature,
            "max_output_tokens": self._max_tokens,
        }
        if self._project:
            kwargs["project"] = self._project
        if self._location:
            kwargs["location"] = self._location

        self._llm = ChatVertexAI(**kwargs)
        return self._llm

    async def analyze(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        from langchain_core.messages import HumanMessage, SystemMessage

        llm = self._ensure_llm()
        messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
        response = await llm.ainvoke(messages)
        return {"content": response.content}

    async def structured(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: type[BaseModel],
    ) -> BaseModel | dict[str, Any]:
        from langchain_core.messages import HumanMessage, SystemMessage

        llm = self._ensure_llm()
        try:
            structured_llm = llm.with_structured_output(schema)
            messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
            return await structured_llm.ainvoke(messages)
        except Exception:
            logger.warning("vertex_ai.structured_fallback", model=self._model_id)
            # Fallback: request JSON in prompt and parse manually
            schema_json = json.dumps(schema.model_json_schema(), indent=2)
            augmented_system = (
                f"{system_prompt}\n\nRespond with valid JSON matching this schema:\n{schema_json}"
            )
            result = await self.analyze(augmented_system, user_prompt)
            return _parse_to_schema(result["content"], schema)


# ---------------------------------------------------------------------------
# Azure OpenAI
# ---------------------------------------------------------------------------


class AzureOpenAIProvider(LLMProvider):
    """Azure OpenAI Service via langchain-openai.

    Uses Azure-hosted OpenAI models (GPT-4o, GPT-4, etc.).

    Install: ``pip install langchain-openai``
    """

    provider_name = "azure_openai"

    def __init__(
        self,
        deployment_name: str = "",
        endpoint: str = "",
        api_key: str = "",
        api_version: str = "2024-02-01",
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> None:
        self._deployment = deployment_name
        self._endpoint = endpoint
        self._api_key = api_key
        self._api_version = api_version
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._llm: Any = None

    def _ensure_llm(self) -> Any:
        if self._llm is not None:
            return self._llm
        try:
            from langchain_openai import AzureChatOpenAI
        except ImportError as exc:
            raise RuntimeError(
                "langchain-openai not installed. Run: pip install langchain-openai"
            ) from exc

        if not self._deployment or not self._endpoint or not self._api_key:
            raise RuntimeError(
                "Azure OpenAI requires deployment_name, endpoint, and api_key. "
                "Set AZURE_OPENAI_DEPLOYMENT, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY."
            )

        self._llm = AzureChatOpenAI(
            azure_deployment=self._deployment,
            azure_endpoint=self._endpoint,
            api_key=self._api_key,  # type: ignore[arg-type]
            api_version=self._api_version,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )
        return self._llm

    async def analyze(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        from langchain_core.messages import HumanMessage, SystemMessage

        llm = self._ensure_llm()
        messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
        response = await llm.ainvoke(messages)
        return {"content": response.content}

    async def structured(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: type[BaseModel],
    ) -> BaseModel | dict[str, Any]:
        from langchain_core.messages import HumanMessage, SystemMessage

        llm = self._ensure_llm()
        try:
            structured_llm = llm.with_structured_output(schema)
            messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
            return await structured_llm.ainvoke(messages)
        except Exception:
            logger.warning("azure_openai.structured_fallback", deployment=self._deployment)
            schema_json = json.dumps(schema.model_json_schema(), indent=2)
            augmented_system = (
                f"{system_prompt}\n\nRespond with valid JSON matching this schema:\n{schema_json}"
            )
            result = await self.analyze(augmented_system, user_prompt)
            return _parse_to_schema(result["content"], schema)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PROVIDER_REGISTRY: dict[str, type[LLMProvider]] = {
    "anthropic": AnthropicProvider,
    "bedrock": BedrockStrandsProvider,
    "vertex_ai": VertexAIProvider,
    "azure_openai": AzureOpenAIProvider,
}


def create_provider(provider_name: str, **kwargs: Any) -> LLMProvider:
    """Factory function to create the right provider.

    Args:
        provider_name: One of ``anthropic``, ``bedrock``, ``vertex_ai``, ``azure_openai``.
        **kwargs: Provider-specific configuration passed to the constructor.

    Returns:
        An initialized :class:`LLMProvider` instance.

    Raises:
        ValueError: If *provider_name* is not registered.
    """
    cls = _PROVIDER_REGISTRY.get(provider_name)
    if cls is None:
        raise ValueError(
            f"Unknown provider: {provider_name}. Available: {sorted(_PROVIDER_REGISTRY.keys())}"
        )
    return cls(**kwargs)


def list_providers() -> list[str]:
    """Return the names of all registered providers."""
    return sorted(_PROVIDER_REGISTRY.keys())
