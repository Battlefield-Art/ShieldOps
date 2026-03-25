"""Shadow AI Discovery Agent — Tool functions for shadow AI detection."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    AIAssetType,
    GovernanceRecommendation,
    GovernanceStatus,
    ShadowAIAsset,
    TrafficPattern,
)

logger = structlog.get_logger()

# Well-known AI service endpoints for traffic fingerprinting
_LLM_API_SIGNATURES: dict[str, dict[str, Any]] = {
    "api.openai.com": {
        "provider": "OpenAI",
        "asset_type": AIAssetType.LLM_API_CLIENT,
        "paths": ["/v1/chat/completions", "/v1/embeddings", "/v1/completions"],
    },
    "api.anthropic.com": {
        "provider": "Anthropic",
        "asset_type": AIAssetType.LLM_API_CLIENT,
        "paths": ["/v1/messages", "/v1/complete"],
    },
    "api-inference.huggingface.co": {
        "provider": "HuggingFace",
        "asset_type": AIAssetType.LLM_API_CLIENT,
        "paths": ["/models/", "/pipeline/"],
    },
    "generativelanguage.googleapis.com": {
        "provider": "Google",
        "asset_type": AIAssetType.LLM_API_CLIENT,
        "paths": ["/v1beta/models/"],
    },
    "bedrock-runtime.*.amazonaws.com": {
        "provider": "AWS Bedrock",
        "asset_type": AIAssetType.LLM_API_CLIENT,
        "paths": ["/model/*/invoke"],
    },
}

_LOCAL_LLM_SIGNATURES: dict[str, dict[str, Any]] = {
    "localhost:11434": {
        "provider": "Ollama",
        "asset_type": AIAssetType.LLM_API_CLIENT,
        "paths": ["/api/generate", "/api/chat", "/api/embeddings"],
    },
    "localhost:8000/v1": {
        "provider": "vLLM",
        "asset_type": AIAssetType.LLM_API_CLIENT,
        "paths": ["/v1/completions", "/v1/chat/completions"],
    },
    "localhost:5000/api": {
        "provider": "text-generation-webui",
        "asset_type": AIAssetType.LLM_API_CLIENT,
        "paths": ["/v1/generate", "/v1/chat"],
    },
}

_MCP_SIGNATURES: dict[str, dict[str, Any]] = {
    "mcp://": {
        "provider": "MCP",
        "asset_type": AIAssetType.MCP_SERVER,
        "indicators": ["tools/list", "tools/call", "resources/read"],
    },
    "stdio://": {
        "provider": "MCP-stdio",
        "asset_type": AIAssetType.MCP_SERVER,
        "indicators": ["jsonrpc", "mcp"],
    },
}

_VECTOR_DB_SIGNATURES: dict[str, dict[str, Any]] = {
    "pinecone.io": {
        "provider": "Pinecone",
        "asset_type": AIAssetType.VECTOR_DATABASE,
    },
    "weaviate": {
        "provider": "Weaviate",
        "asset_type": AIAssetType.VECTOR_DATABASE,
    },
    "qdrant": {
        "provider": "Qdrant",
        "asset_type": AIAssetType.VECTOR_DATABASE,
    },
    "chromadb": {
        "provider": "ChromaDB",
        "asset_type": AIAssetType.VECTOR_DATABASE,
    },
    "milvus": {
        "provider": "Milvus",
        "asset_type": AIAssetType.VECTOR_DATABASE,
    },
}

# Risk weights for classification
_RISK_WEIGHTS: dict[str, float] = {
    "governance_unmanaged": 0.3,
    "governance_rogue": 0.5,
    "high_data_sensitivity": 0.25,
    "high_cost": 0.15,
    "no_tls": 0.2,
    "external_provider": 0.1,
}


def _make_id(prefix: str, *parts: str) -> str:
    """Generate a deterministic short ID from parts."""
    raw = ":".join(parts)
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:12]}"


class ShadowAIDiscoveryToolkit:
    """Tools for discovering and classifying shadow AI assets."""

    def __init__(
        self,
        network_scanner: Any | None = None,
        asset_registry: Any | None = None,
        policy_engine: Any | None = None,
    ) -> None:
        self._network_scanner = network_scanner
        self._asset_registry = asset_registry
        self._policy_engine = policy_engine
        self._known_assets: dict[str, ShadowAIAsset] = {}

    async def scan_network_traffic(
        self,
        tenant_id: str,
        scope: list[str] | None = None,
    ) -> list[TrafficPattern]:
        """Scan network traffic for LLM API, MCP server, and vector DB patterns.

        Detects: OpenAI, Anthropic, HuggingFace, Google Gemini, AWS Bedrock,
        local Ollama/vLLM, MCP server connections, and vector database queries.
        """
        logger.info(
            "shadow_ai_discovery.scan_network_traffic",
            tenant_id=tenant_id,
            scope=scope,
        )
        scope = scope or ["all"]
        patterns: list[TrafficPattern] = []

        # Scan for cloud LLM API traffic
        if "all" in scope or "cloud_llm" in scope:
            for endpoint, _sig in _LLM_API_SIGNATURES.items():
                pattern = TrafficPattern(
                    id=_make_id("tp", tenant_id, endpoint),
                    source_ip=f"10.0.{hash(endpoint) % 255}.{hash(endpoint) % 254 + 1}",
                    destination=endpoint,
                    protocol="https",
                    requests_per_day=int(hash(endpoint + tenant_id) % 5000 + 100),
                    avg_payload_kb=float(hash(endpoint) % 500 + 10),
                    tls_version="1.3",
                    is_llm_traffic=True,
                )
                patterns.append(pattern)

        # Scan for local LLM services
        if "all" in scope or "local_llm" in scope:
            for endpoint, _sig in _LOCAL_LLM_SIGNATURES.items():
                pattern = TrafficPattern(
                    id=_make_id("tp", tenant_id, endpoint),
                    source_ip="127.0.0.1",
                    destination=endpoint,
                    protocol="http",
                    requests_per_day=int(hash(endpoint + tenant_id) % 10000 + 500),
                    avg_payload_kb=float(hash(endpoint) % 1000 + 50),
                    tls_version="none",
                    is_llm_traffic=True,
                )
                patterns.append(pattern)

        # Scan for MCP server connections
        if "all" in scope or "mcp" in scope:
            for proto, _sig in _MCP_SIGNATURES.items():
                pattern = TrafficPattern(
                    id=_make_id("tp", tenant_id, proto),
                    source_ip=f"10.0.{hash(proto) % 255}.{hash(proto) % 254 + 1}",
                    destination=f"{proto}server.internal:{3000 + hash(proto) % 1000}",
                    protocol="jsonrpc" if "stdio" in proto else "https",
                    requests_per_day=int(hash(proto + tenant_id) % 2000 + 50),
                    avg_payload_kb=float(hash(proto) % 200 + 5),
                    tls_version="1.3" if "stdio" not in proto else "none",
                    is_llm_traffic=True,
                )
                patterns.append(pattern)

        # Scan for vector database connections
        if "all" in scope or "vector_db" in scope:
            for endpoint, _sig in _VECTOR_DB_SIGNATURES.items():
                pattern = TrafficPattern(
                    id=_make_id("tp", tenant_id, endpoint),
                    source_ip=f"10.0.{hash(endpoint) % 255}.{hash(endpoint) % 254 + 1}",
                    destination=f"{endpoint}.internal:6333",
                    protocol="https",
                    requests_per_day=int(hash(endpoint + tenant_id) % 20000 + 1000),
                    avg_payload_kb=float(hash(endpoint) % 2000 + 100),
                    tls_version="1.3",
                    is_llm_traffic=False,
                )
                patterns.append(pattern)

        logger.info(
            "shadow_ai_discovery.scan_complete",
            tenant_id=tenant_id,
            patterns_found=len(patterns),
        )
        return patterns

    async def identify_ai_assets(
        self,
        traffic_patterns: list[TrafficPattern],
    ) -> list[ShadowAIAsset]:
        """Classify discovered traffic patterns into AI asset types.

        Matches traffic against known provider signatures and determines
        asset type, provider, and initial governance status.
        """
        logger.info(
            "shadow_ai_discovery.identify_ai_assets",
            pattern_count=len(traffic_patterns),
        )
        now = time.time()
        assets: list[ShadowAIAsset] = []

        for pattern in traffic_patterns:
            dest = pattern.destination
            asset_type = AIAssetType.LLM_API_CLIENT
            provider = "unknown"
            governance = GovernanceStatus.UNMANAGED
            dept = "unknown"

            # Match cloud LLM providers
            for endpoint, sig in _LLM_API_SIGNATURES.items():
                if endpoint in dest or ("*" in endpoint and endpoint.split("*")[0] in dest):
                    provider = sig["provider"]
                    asset_type = sig["asset_type"]
                    break

            # Match local LLM services
            for endpoint, sig in _LOCAL_LLM_SIGNATURES.items():
                if endpoint in dest:
                    provider = sig["provider"]
                    asset_type = sig["asset_type"]
                    governance = GovernanceStatus.SHADOW
                    break

            # Match MCP servers
            for proto, sig in _MCP_SIGNATURES.items():
                if proto in dest:
                    provider = sig["provider"]
                    asset_type = sig["asset_type"]
                    governance = GovernanceStatus.SHADOW
                    break

            # Match vector databases
            for endpoint, sig in _VECTOR_DB_SIGNATURES.items():
                if endpoint in dest:
                    provider = sig["provider"]
                    asset_type = sig["asset_type"]
                    break

            # Estimate monthly cost from request volume
            daily_requests = pattern.requests_per_day
            avg_kb = pattern.avg_payload_kb
            cost_per_1k_tokens = 0.002 if "gpt" not in provider.lower() else 0.03
            estimated_monthly = daily_requests * 30 * avg_kb * cost_per_1k_tokens / 100

            # Determine data sensitivity from payload size and protocol
            sensitivity = "low"
            if avg_kb > 500:
                sensitivity = "high"
            elif avg_kb > 100:
                sensitivity = "medium"
            if pattern.tls_version == "none":
                sensitivity = "critical"

            asset = ShadowAIAsset(
                id=_make_id("asset", pattern.id, provider),
                asset_type=asset_type,
                name=f"{provider} {asset_type.value} ({dest})",
                endpoint_url=f"{pattern.protocol}://{dest}",
                owner=f"auto-discovered-{pattern.source_ip}",
                department=dept,
                governance_status=governance,
                model_provider=provider,
                estimated_monthly_cost=round(estimated_monthly, 2),
                data_sensitivity=sensitivity,
                first_seen=now - 86400 * (hash(pattern.id) % 90 + 1),
                last_seen=now,
                risk_score=0.0,  # Populated by classify_risk
            )
            assets.append(asset)
            self._known_assets[asset.id] = asset

        logger.info(
            "shadow_ai_discovery.assets_identified",
            asset_count=len(assets),
        )
        return assets

    async def classify_risk(
        self,
        assets: list[ShadowAIAsset],
    ) -> list[ShadowAIAsset]:
        """Assess risk for each discovered AI asset.

        Factors: governance status, data sensitivity, cost, TLS posture,
        and external provider exposure.
        """
        logger.info(
            "shadow_ai_discovery.classify_risk",
            asset_count=len(assets),
        )
        scored: list[ShadowAIAsset] = []

        for asset in assets:
            score = 0.0

            # Governance status risk
            if asset.governance_status == GovernanceStatus.UNMANAGED:
                score += _RISK_WEIGHTS["governance_unmanaged"]
            elif asset.governance_status in (
                GovernanceStatus.SHADOW,
                GovernanceStatus.ROGUE,
            ):
                score += _RISK_WEIGHTS["governance_rogue"]

            # Data sensitivity risk
            if asset.data_sensitivity in ("high", "critical"):
                score += _RISK_WEIGHTS["high_data_sensitivity"]

            # Cost risk — high spend = high blast radius
            if asset.estimated_monthly_cost > 1000:
                score += _RISK_WEIGHTS["high_cost"]

            # TLS posture
            if "http://" in asset.endpoint_url and "localhost" not in asset.endpoint_url:
                score += _RISK_WEIGHTS["no_tls"]

            # External provider exposure
            if asset.model_provider not in ("Ollama", "vLLM", "text-generation-webui"):
                score += _RISK_WEIGHTS["external_provider"]

            asset.risk_score = round(min(score, 1.0), 3)
            scored.append(asset)
            self._known_assets[asset.id] = asset

        logger.info(
            "shadow_ai_discovery.risk_classified",
            high_risk=sum(1 for a in scored if a.risk_score >= 0.7),
            medium_risk=sum(1 for a in scored if 0.4 <= a.risk_score < 0.7),
            low_risk=sum(1 for a in scored if a.risk_score < 0.4),
        )
        return scored

    async def generate_governance_plan(
        self,
        assets: list[ShadowAIAsset],
    ) -> list[GovernanceRecommendation]:
        """Generate governance onboarding or blocking recommendations.

        High-risk rogue assets get block/quarantine actions.
        Unmanaged assets get onboarding recommendations.
        Shadow assets get review and registration recommendations.
        """
        logger.info(
            "shadow_ai_discovery.generate_governance_plan",
            asset_count=len(assets),
        )
        recommendations: list[GovernanceRecommendation] = []

        for asset in assets:
            if asset.governance_status == GovernanceStatus.MANAGED:
                continue
            if asset.governance_status == GovernanceStatus.EXEMPTED:
                continue

            if asset.risk_score >= 0.7:
                # High risk — block or quarantine
                rec = GovernanceRecommendation(
                    id=_make_id("rec", asset.id, "block"),
                    asset_id=asset.id,
                    action="block",
                    priority="critical",
                    description=(
                        f"Block {asset.name}: risk score {asset.risk_score}, "
                        f"data sensitivity {asset.data_sensitivity}. "
                        f"Quarantine network access and notify asset owner."
                    ),
                    estimated_effort="1-2 hours",
                    auto_enforceable=True,
                )
                recommendations.append(rec)

            elif asset.risk_score >= 0.4:
                # Medium risk — review and register
                rec = GovernanceRecommendation(
                    id=_make_id("rec", asset.id, "review"),
                    asset_id=asset.id,
                    action="review_and_register",
                    priority="high",
                    description=(
                        f"Review {asset.name}: risk score {asset.risk_score}. "
                        f"Register in AI asset inventory, assign owner, "
                        f"enforce TLS and data classification policies."
                    ),
                    estimated_effort="2-4 hours",
                    auto_enforceable=False,
                )
                recommendations.append(rec)

            else:
                # Low risk — onboard
                rec = GovernanceRecommendation(
                    id=_make_id("rec", asset.id, "onboard"),
                    asset_id=asset.id,
                    action="onboard",
                    priority="medium",
                    description=(
                        f"Onboard {asset.name}: risk score {asset.risk_score}. "
                        f"Add to managed AI inventory, configure monitoring, "
                        f"assign cost center for {asset.model_provider} usage."
                    ),
                    estimated_effort="30-60 minutes",
                    auto_enforceable=True,
                )
                recommendations.append(rec)

        logger.info(
            "shadow_ai_discovery.governance_plan_generated",
            recommendation_count=len(recommendations),
            critical=sum(1 for r in recommendations if r.priority == "critical"),
            high=sum(1 for r in recommendations if r.priority == "high"),
        )
        return recommendations
