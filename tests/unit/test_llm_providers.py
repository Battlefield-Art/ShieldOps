"""Tests for multi-cloud LLM provider abstraction and Strands tool wrappers.

Covers: provider initialization, factory function, error handling for missing SDKs,
structured output parsing, strands tool availability, and tool callability.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel

from shieldops.utils.llm_providers import (
    AnthropicProvider,
    AzureOpenAIProvider,
    BedrockStrandsProvider,
    LLMProvider,
    VertexAIProvider,
    _parse_to_schema,
    create_provider,
    list_providers,
)

# ── Test schema ────────────────────────────────────────────────────


class SampleOutput(BaseModel):
    """A simple Pydantic model for structured output tests."""

    summary: str = ""
    confidence: float = 0.0
    tags: list[str] = []


# ── Provider Initialization ────────────────────────────────────────


class TestAnthropicProvider:
    def test_init_defaults(self) -> None:
        provider = AnthropicProvider()
        assert provider.provider_name == "anthropic"
        assert provider._model == ""
        assert provider._temperature == 0.1

    def test_init_custom_params(self) -> None:
        provider = AnthropicProvider(
            model="claude-opus-4-20250514",
            api_key="test-key",
            max_tokens=8192,
            temperature=0.5,
        )
        assert provider._model == "claude-opus-4-20250514"
        assert provider._api_key == "test-key"
        assert provider._max_tokens == 8192
        assert provider._temperature == 0.5

    def test_is_llm_provider(self) -> None:
        provider = AnthropicProvider()
        assert isinstance(provider, LLMProvider)


class TestBedrockStrandsProvider:
    def test_init_defaults(self) -> None:
        provider = BedrockStrandsProvider()
        assert provider.provider_name == "bedrock"
        assert provider._model_id == "anthropic.claude-sonnet-4-20250514-v1:0"
        assert provider._region == "us-east-1"
        assert provider._temperature == 0.1

    def test_init_custom_params(self) -> None:
        provider = BedrockStrandsProvider(
            model_id="amazon.nova-pro-v1:0",
            region="eu-west-1",
            temperature=0.3,
        )
        assert provider._model_id == "amazon.nova-pro-v1:0"
        assert provider._region == "eu-west-1"
        assert provider._temperature == 0.3

    def test_is_llm_provider(self) -> None:
        provider = BedrockStrandsProvider()
        assert isinstance(provider, LLMProvider)

    def test_ensure_model_missing_sdk(self) -> None:
        provider = BedrockStrandsProvider()
        with (
            patch.dict("sys.modules", {"strands": None, "strands.models": None}),
            pytest.raises(RuntimeError, match="strands-agents not installed"),
        ):
            provider._ensure_model()


class TestVertexAIProvider:
    def test_init_defaults(self) -> None:
        provider = VertexAIProvider()
        assert provider.provider_name == "vertex_ai"
        assert provider._model_id == "gemini-2.0-flash"
        assert provider._location == "us-central1"

    def test_init_custom_params(self) -> None:
        provider = VertexAIProvider(
            model_id="gemini-1.5-pro",
            project="my-gcp-project",
            location="europe-west4",
        )
        assert provider._model_id == "gemini-1.5-pro"
        assert provider._project == "my-gcp-project"
        assert provider._location == "europe-west4"

    def test_is_llm_provider(self) -> None:
        provider = VertexAIProvider()
        assert isinstance(provider, LLMProvider)

    def test_ensure_llm_missing_sdk(self) -> None:
        provider = VertexAIProvider()
        with (
            patch.dict("sys.modules", {"langchain_google_vertexai": None}),
            pytest.raises(RuntimeError, match="langchain-google-vertexai not installed"),
        ):
            provider._ensure_llm()


class TestAzureOpenAIProvider:
    def test_init_defaults(self) -> None:
        provider = AzureOpenAIProvider()
        assert provider.provider_name == "azure_openai"
        assert provider._deployment == ""
        assert provider._api_version == "2024-02-01"

    def test_init_custom_params(self) -> None:
        provider = AzureOpenAIProvider(
            deployment_name="gpt-4o-deploy",
            endpoint="https://my-resource.openai.azure.com/",
            api_key="azure-key-123",
            api_version="2024-06-01",
        )
        assert provider._deployment == "gpt-4o-deploy"
        assert provider._endpoint == "https://my-resource.openai.azure.com/"
        assert provider._api_key == "azure-key-123"

    def test_is_llm_provider(self) -> None:
        provider = AzureOpenAIProvider()
        assert isinstance(provider, LLMProvider)

    def test_ensure_llm_missing_credentials(self) -> None:
        """Azure provider raises when credentials are missing."""
        provider = AzureOpenAIProvider()
        # Even if langchain_openai is available, missing creds should error
        mock_module = MagicMock()
        with (
            patch.dict("sys.modules", {"langchain_openai": mock_module}),
            pytest.raises(RuntimeError, match="Azure OpenAI requires"),
        ):
            provider._ensure_llm()

    def test_ensure_llm_missing_sdk(self) -> None:
        provider = AzureOpenAIProvider(
            deployment_name="test", endpoint="https://test", api_key="key"
        )
        with (
            patch.dict("sys.modules", {"langchain_openai": None}),
            pytest.raises(RuntimeError, match="langchain-openai not installed"),
        ):
            provider._ensure_llm()


# ── Factory ────────────────────────────────────────────────────────


class TestCreateProvider:
    def test_create_anthropic(self) -> None:
        p = create_provider("anthropic")
        assert isinstance(p, AnthropicProvider)

    def test_create_bedrock(self) -> None:
        p = create_provider("bedrock", model_id="amazon.nova-lite-v1:0")
        assert isinstance(p, BedrockStrandsProvider)
        assert p._model_id == "amazon.nova-lite-v1:0"

    def test_create_vertex_ai(self) -> None:
        p = create_provider("vertex_ai", project="test-project")
        assert isinstance(p, VertexAIProvider)
        assert p._project == "test-project"

    def test_create_azure_openai(self) -> None:
        p = create_provider("azure_openai", deployment_name="gpt4")
        assert isinstance(p, AzureOpenAIProvider)

    def test_unknown_provider_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown provider: fake_provider"):
            create_provider("fake_provider")

    def test_list_providers(self) -> None:
        providers = list_providers()
        assert "anthropic" in providers
        assert "bedrock" in providers
        assert "vertex_ai" in providers
        assert "azure_openai" in providers
        assert len(providers) == 4


# ── Structured Output Parsing ──────────────────────────────────────


class TestParseToSchema:
    def test_valid_json(self) -> None:
        raw = json.dumps({"summary": "ok", "confidence": 0.95, "tags": ["test"]})
        result = _parse_to_schema(raw, SampleOutput)
        assert isinstance(result, SampleOutput)
        assert result.summary == "ok"
        assert result.confidence == 0.95

    def test_json_with_code_fences(self) -> None:
        raw = '```json\n{"summary": "fenced", "confidence": 0.8, "tags": []}\n```'
        result = _parse_to_schema(raw, SampleOutput)
        assert isinstance(result, SampleOutput)
        assert result.summary == "fenced"

    def test_invalid_json_returns_dict(self) -> None:
        raw = "This is not JSON at all."
        result = _parse_to_schema(raw, SampleOutput)
        assert isinstance(result, dict)
        assert "content" in result


# ── Strands Tools ──────────────────────────────────────────────────


class TestStrandsTools:
    def test_strands_available_flag_is_bool(self) -> None:
        from shieldops.utils.strands_tools import STRANDS_AVAILABLE

        assert isinstance(STRANDS_AVAILABLE, bool)

    def test_all_tools_list(self) -> None:
        from shieldops.utils.strands_tools import ALL_TOOLS

        assert len(ALL_TOOLS) == 5

    def test_tools_are_callable(self) -> None:
        from shieldops.utils.strands_tools import (
            assess_threat_model,
            check_compliance,
            investigate_incident,
            optimize_telemetry,
            run_security_scan,
        )

        for tool_fn in [
            investigate_incident,
            run_security_scan,
            check_compliance,
            optimize_telemetry,
            assess_threat_model,
        ]:
            assert callable(tool_fn)


# ── Strands Agent ──────────────────────────────────────────────────


class TestStrandsAgent:
    def test_create_agent_raises_without_strands(self) -> None:
        with patch.dict("sys.modules", {"strands": None, "strands.models": None}):
            from shieldops.utils.strands_agent import create_shieldops_strands_agent

            with pytest.raises(RuntimeError, match="strands-agents is not installed"):
                create_shieldops_strands_agent()

    def test_system_prompt_defined(self) -> None:
        from shieldops.utils.strands_agent import SHIELDOPS_SYSTEM_PROMPT

        assert "ShieldOps" in SHIELDOPS_SYSTEM_PROMPT
        assert "SRE" in SHIELDOPS_SYSTEM_PROMPT


# ── Async Provider Methods (mocked) ───────────────────────────────


class TestAnthropicProviderAnalyze:
    @pytest.mark.asyncio
    async def test_analyze_returns_content(self) -> None:
        provider = AnthropicProvider()
        mock_llm = AsyncMock()
        mock_response = MagicMock()
        mock_response.content = "Test analysis result"
        mock_llm.ainvoke = AsyncMock(return_value=mock_response)
        provider._llm = mock_llm

        result = await provider.analyze("system", "user prompt")
        assert result == {"content": "Test analysis result"}

    @pytest.mark.asyncio
    async def test_structured_returns_model(self) -> None:
        provider = AnthropicProvider()
        mock_llm = MagicMock()
        expected = SampleOutput(summary="structured", confidence=0.9, tags=["a"])
        mock_structured = AsyncMock(return_value=expected)
        mock_llm.with_structured_output = MagicMock(return_value=MagicMock(ainvoke=mock_structured))
        provider._llm = mock_llm

        result = await provider.structured("system", "user", SampleOutput)
        assert result == expected
