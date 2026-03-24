"""ShadowAIDiscovery — Detect and track unregistered AI/LLM API consumers."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ShadowAISource(StrEnum):
    NETWORK_TRAFFIC = "network_traffic"
    CLOUD_LOGS = "cloud_logs"
    DNS_QUERIES = "dns_queries"
    API_GATEWAY = "api_gateway"
    PROXY_LOGS = "proxy_logs"
    BILLING_DATA = "billing_data"


class AIProvider(StrEnum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"
    GOOGLE_VERTEX = "google_vertex"
    AWS_BEDROCK = "aws_bedrock"
    HUGGINGFACE = "huggingface"
    REPLICATE = "replicate"
    COHERE = "cohere"
    MISTRAL = "mistral"
    LOCAL_MODEL = "local_model"


class ShadowAIStatus(StrEnum):
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    CONFIRMED_SHADOW = "confirmed_shadow"
    REGISTERED = "registered"
    FALSE_POSITIVE = "false_positive"


# --- Models ---


class ShadowAIRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    provider: AIProvider = AIProvider.OPENAI
    api_endpoint: str = ""
    calling_service: str = ""
    detection_source: ShadowAISource = ShadowAISource.NETWORK_TRAFFIC
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    request_count: int = 0
    estimated_cost: float = 0.0
    status: ShadowAIStatus = ShadowAIStatus.DETECTED
    owner: str = ""
    created_at: float = Field(default_factory=time.time)


class ShadowAIIndicator(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pattern: str = ""
    provider: AIProvider = AIProvider.OPENAI
    confidence: float = 0.0
    created_at: float = Field(default_factory=time.time)


class ShadowAIReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_indicators: int = 0
    gap_count: int = 0
    avg_confidence: float = 0.0
    by_provider: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Known LLM endpoints for detection ---

_LLM_ENDPOINTS: dict[str, AIProvider] = {
    "api.openai.com": AIProvider.OPENAI,
    "api.anthropic.com": AIProvider.ANTHROPIC,
    "openai.azure.com": AIProvider.AZURE_OPENAI,
    "generativelanguage.googleapis.com": AIProvider.GOOGLE_VERTEX,
    "bedrock-runtime": AIProvider.AWS_BEDROCK,
    "api-inference.huggingface.co": AIProvider.HUGGINGFACE,
    "api.replicate.com": AIProvider.REPLICATE,
    "api.cohere.ai": AIProvider.COHERE,
    "api.mistral.ai": AIProvider.MISTRAL,
}

# Cost-per-1K-request estimates by provider
_PROVIDER_COST_PER_1K: dict[AIProvider, float] = {
    AIProvider.OPENAI: 0.60,
    AIProvider.ANTHROPIC: 0.80,
    AIProvider.AZURE_OPENAI: 0.55,
    AIProvider.GOOGLE_VERTEX: 0.50,
    AIProvider.AWS_BEDROCK: 0.65,
    AIProvider.HUGGINGFACE: 0.10,
    AIProvider.REPLICATE: 0.40,
    AIProvider.COHERE: 0.30,
    AIProvider.MISTRAL: 0.25,
    AIProvider.LOCAL_MODEL: 0.0,
}


# --- Engine ---


class ShadowAIDiscovery:
    """Detect and track unregistered AI/LLM API consumers."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ShadowAIRecord] = []
        self._indicators: list[ShadowAIIndicator] = []
        logger.info(
            "shadow_ai_discovery.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / indicator --------------------------------------------------

    def record_detection(
        self,
        provider: AIProvider = AIProvider.OPENAI,
        api_endpoint: str = "",
        calling_service: str = "",
        detection_source: ShadowAISource = ShadowAISource.NETWORK_TRAFFIC,
        request_count: int = 1,
        owner: str = "",
    ) -> ShadowAIRecord:
        now = time.time()
        # Check if we already track this service+endpoint
        for r in self._records:
            if r.calling_service == calling_service and r.api_endpoint == api_endpoint:
                r.last_seen = now
                r.request_count += request_count
                r.estimated_cost = round(
                    r.request_count / 1000 * _PROVIDER_COST_PER_1K.get(r.provider, 0.5), 2
                )
                logger.info(
                    "shadow_ai_discovery.detection_updated",
                    record_id=r.id,
                    calling_service=calling_service,
                    request_count=r.request_count,
                )
                return r

        estimated_cost = round(request_count / 1000 * _PROVIDER_COST_PER_1K.get(provider, 0.5), 2)
        record = ShadowAIRecord(
            provider=provider,
            api_endpoint=api_endpoint,
            calling_service=calling_service,
            detection_source=detection_source,
            request_count=request_count,
            estimated_cost=estimated_cost,
            owner=owner,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "shadow_ai_discovery.detection_recorded",
            record_id=record.id,
            provider=provider.value,
            calling_service=calling_service,
        )
        return record

    def add_indicator(
        self,
        pattern: str = "",
        provider: AIProvider = AIProvider.OPENAI,
        confidence: float = 0.0,
    ) -> ShadowAIIndicator:
        indicator = ShadowAIIndicator(
            pattern=pattern,
            provider=provider,
            confidence=confidence,
        )
        self._indicators.append(indicator)
        if len(self._indicators) > self._max_records:
            self._indicators = self._indicators[-self._max_records :]
        return indicator

    # -- domain operations ---------------------------------------------------

    def analyze_network_patterns(
        self,
        dns_logs: list[dict[str, Any]] | None = None,
        proxy_logs: list[dict[str, Any]] | None = None,
    ) -> list[ShadowAIRecord]:
        """Detect API calls to known LLM provider endpoints from logs."""
        detections: list[ShadowAIRecord] = []
        logs = (dns_logs or []) + (proxy_logs or [])
        source = ShadowAISource.DNS_QUERIES if dns_logs else ShadowAISource.PROXY_LOGS

        for entry in logs:
            domain = entry.get("domain", "") or entry.get("host", "")
            for endpoint, provider in _LLM_ENDPOINTS.items():
                if endpoint in domain:
                    rec = self.record_detection(
                        provider=provider,
                        api_endpoint=endpoint,
                        calling_service=entry.get("source_service", "unknown"),
                        detection_source=source,
                        request_count=entry.get("count", 1),
                    )
                    detections.append(rec)
                    break
        return detections

    def analyze_billing_anomalies(
        self,
        cloud_billing_data: list[dict[str, Any]] | None = None,
    ) -> list[ShadowAIRecord]:
        """Detect unexpected AI API charges in cloud billing data."""
        detections: list[ShadowAIRecord] = []
        for entry in cloud_billing_data or []:
            service_name = entry.get("service", "").lower()
            cost = entry.get("cost", 0.0)
            # Look for AI-related billing line items
            ai_keywords = ["openai", "anthropic", "bedrock", "vertex", "cognitive"]
            matched_provider: AIProvider | None = None
            for kw in ai_keywords:
                if kw in service_name:
                    for endpoint, provider in _LLM_ENDPOINTS.items():
                        if kw in endpoint or kw in provider.value:
                            matched_provider = provider
                            break
                    break
            if matched_provider and cost > 0:
                rec = self.record_detection(
                    provider=matched_provider,
                    api_endpoint=service_name,
                    calling_service=entry.get("project", "unknown"),
                    detection_source=ShadowAISource.BILLING_DATA,
                    request_count=int(
                        cost / _PROVIDER_COST_PER_1K.get(matched_provider, 0.5) * 1000
                    )
                    if cost > 0
                    else 1,
                )
                detections.append(rec)
        return detections

    def correlate_with_registry(
        self,
        nhi_registry: Any,
    ) -> list[dict[str, Any]]:
        """Identify which detected AI calls are unregistered in the NHI registry."""
        unregistered: list[dict[str, Any]] = []
        for r in self._records:
            if r.status in (ShadowAIStatus.REGISTERED, ShadowAIStatus.FALSE_POSITIVE):
                continue
            # Check if service is registered
            registered = False
            if hasattr(nhi_registry, "search"):
                matches = nhi_registry.search(query=r.calling_service)
                registered = len(matches) > 0
            if not registered:
                unregistered.append(
                    {
                        "shadow_ai_id": r.id,
                        "provider": r.provider.value,
                        "calling_service": r.calling_service,
                        "request_count": r.request_count,
                        "estimated_cost": r.estimated_cost,
                        "status": "unregistered",
                        "recommendation": "Register in NHI registry or block",
                    }
                )
        return unregistered

    # -- standard methods ----------------------------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.calling_service == key or r.provider.value == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        total_requests = sum(r.request_count for r in matched)
        total_cost = round(sum(r.estimated_cost for r in matched), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "total_requests": total_requests,
            "total_estimated_cost": total_cost,
        }

    def generate_report(self) -> ShadowAIReport:
        by_provider: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_source: dict[str, int] = {}
        for r in self._records:
            by_provider[r.provider.value] = by_provider.get(r.provider.value, 0) + 1
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
            by_source[r.detection_source.value] = by_source.get(r.detection_source.value, 0) + 1

        confirmed = [r for r in self._records if r.status != ShadowAIStatus.FALSE_POSITIVE]
        gap_count = len([r for r in confirmed if r.status != ShadowAIStatus.REGISTERED])

        confidences = [i.confidence for i in self._indicators]
        avg_conf = round(sum(confidences) / len(confidences), 2) if confidences else 0.0

        top_by_cost = sorted(confirmed, key=lambda x: x.estimated_cost, reverse=True)
        top_gaps = [f"{r.calling_service} ({r.provider.value})" for r in top_by_cost[:5]]

        recs: list[str] = []
        total_cost = sum(r.estimated_cost for r in confirmed)
        if gap_count > 0:
            recs.append(
                f"{gap_count} unregistered AI consumer(s) detected — est. ${total_cost:.2f}/month"
            )
        if any(r.provider == AIProvider.OPENAI for r in confirmed):
            recs.append("OpenAI API usage detected — verify data handling compliance")
        if not recs:
            recs.append("No shadow AI consumers detected")

        return ShadowAIReport(
            total_records=len(self._records),
            total_indicators=len(self._indicators),
            gap_count=gap_count,
            avg_confidence=avg_conf,
            by_provider=by_provider,
            by_status=by_status,
            by_source=by_source,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._indicators.clear()
        logger.info("shadow_ai_discovery.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        provider_dist: dict[str, int] = {}
        for r in self._records:
            provider_dist[r.provider.value] = provider_dist.get(r.provider.value, 0) + 1
        total_cost = round(sum(r.estimated_cost for r in self._records), 2)
        return {
            "total_records": len(self._records),
            "total_indicators": len(self._indicators),
            "threshold": self._threshold,
            "provider_distribution": provider_dist,
            "unique_services": len({r.calling_service for r in self._records}),
            "total_estimated_monthly_cost": total_cost,
            "total_requests": sum(r.request_count for r in self._records),
        }
