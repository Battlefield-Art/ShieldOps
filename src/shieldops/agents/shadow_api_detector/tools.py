"""Shadow API Detector Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    APICategory,
    APIRiskLevel,
    DocumentationEntry,
    EndpointProfile,
    RiskClassification,
    ShadowAPI,
    TrafficRecord,
)

logger = structlog.get_logger()

_SAMPLE_TRAFFIC: list[dict[str, Any]] = [
    {
        "method": "GET",
        "path": "/api/v1/users",
        "host": "api.internal.corp",
        "source_ip": "10.0.1.20",
        "status_code": 200,
        "latency_ms": 45.2,
        "authenticated": True,
    },
    {
        "method": "POST",
        "path": "/api/v1/users/export",
        "host": "api.internal.corp",
        "source_ip": "10.0.1.20",
        "status_code": 200,
        "latency_ms": 312.5,
        "authenticated": False,
    },
    {
        "method": "GET",
        "path": "/debug/vars",
        "host": "api.internal.corp",
        "source_ip": "10.0.2.15",
        "status_code": 200,
        "latency_ms": 8.1,
        "authenticated": False,
    },
    {
        "method": "GET",
        "path": "/api/v2/admin/config",
        "host": "api.internal.corp",
        "source_ip": "10.0.3.40",
        "status_code": 200,
        "latency_ms": 22.7,
        "authenticated": False,
    },
    {
        "method": "POST",
        "path": "/graphql",
        "host": "api.partner.corp",
        "source_ip": "10.0.5.10",
        "status_code": 200,
        "latency_ms": 89.4,
        "authenticated": True,
    },
    {
        "method": "GET",
        "path": "/api/internal/metrics",
        "host": "api.internal.corp",
        "source_ip": "10.0.1.55",
        "status_code": 200,
        "latency_ms": 15.3,
        "authenticated": False,
    },
    {
        "method": "PUT",
        "path": "/api/v1/settings/global",
        "host": "api.internal.corp",
        "source_ip": "10.0.4.22",
        "status_code": 200,
        "latency_ms": 67.8,
        "authenticated": True,
    },
    {
        "method": "DELETE",
        "path": "/api/old/cleanup",
        "host": "api.internal.corp",
        "source_ip": "10.0.2.30",
        "status_code": 200,
        "latency_ms": 150.0,
        "authenticated": False,
    },
]

_DOCUMENTED_PATHS: set[str] = {
    "/api/v1/users",
    "/api/v1/settings/global",
    "/graphql",
}


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class ShadowAPIDetectorToolkit:
    """Tools for shadow API detection and documentation."""

    def __init__(
        self,
        traffic_source: Any | None = None,
        api_registry: Any | None = None,
    ) -> None:
        self._traffic_source = traffic_source
        self._api_registry = api_registry

    async def discover_traffic(
        self,
        tenant_id: str,
    ) -> list[TrafficRecord]:
        """Discover API traffic from gateway logs."""
        logger.info(
            "sad.discover_traffic",
            tenant_id=tenant_id,
        )

        if self._traffic_source is not None:
            try:
                raw = await self._traffic_source.get_traffic(
                    tenant_id=tenant_id,
                )
                return [TrafficRecord(**r) for r in raw]
            except Exception:
                logger.exception("sad.discover_traffic.error")

        records: list[TrafficRecord] = []
        for i, t in enumerate(_SAMPLE_TRAFFIC):
            noise = random.randint(-5, 5)  # noqa: S311
            records.append(
                TrafficRecord(
                    id=_gen_id("TR", tenant_id, i),
                    timestamp=f"2026-03-30T10:{i:02d}:00Z",
                    method=t["method"],
                    path=t["path"],
                    host=t["host"],
                    source_ip=t["source_ip"],
                    status_code=t["status_code"],
                    latency_ms=t["latency_ms"],
                    request_bytes=128 + noise,
                    response_bytes=512 + noise,
                    authenticated=t["authenticated"],
                )
            )
        return records

    async def analyze_endpoints(
        self,
        records: list[TrafficRecord],
    ) -> list[EndpointProfile]:
        """Analyze traffic to build endpoint profiles."""
        logger.info(
            "sad.analyze_endpoints",
            count=len(records),
        )

        groups: dict[str, list[TrafficRecord]] = {}
        for r in records:
            key = f"{r.method}|{r.path}|{r.host}"
            groups.setdefault(key, []).append(r)

        profiles: list[EndpointProfile] = []
        for i, (key, group) in enumerate(groups.items()):
            method, path, host = key.split("|", 2)
            callers = {r.source_ip for r in group}
            errors = sum(1 for r in group if r.status_code >= 400)
            avg_lat = sum(r.latency_ms for r in group) / len(group)
            has_auth = any(r.authenticated for r in group)
            profiles.append(
                EndpointProfile(
                    id=_gen_id("EP", key, i),
                    method=method,
                    path=path,
                    host=host,
                    request_count=len(group),
                    unique_callers=len(callers),
                    avg_latency_ms=round(avg_lat, 1),
                    error_rate=round(errors / len(group), 2),
                    has_auth=has_auth,
                    documented=path in _DOCUMENTED_PATHS,
                )
            )
        return profiles

    async def detect_shadow_apis(
        self,
        profiles: list[EndpointProfile],
    ) -> list[ShadowAPI]:
        """Detect shadow and undocumented APIs."""
        logger.info(
            "sad.detect_shadow_apis",
            count=len(profiles),
        )

        shadows: list[ShadowAPI] = []
        idx = 0
        for p in profiles:
            if p.documented:
                continue

            category = APICategory.SHADOW
            evidence: list[str] = ["Not in API registry"]
            if "/debug" in p.path or "/internal" in p.path:
                category = APICategory.INTERNAL
                evidence.append("Internal/debug endpoint exposed")
            elif "/old/" in p.path or "/v0/" in p.path:
                category = APICategory.DEPRECATED
                evidence.append("Deprecated API still active")
            elif "/admin" in p.path:
                evidence.append("Admin endpoint undocumented")

            if not p.has_auth:
                evidence.append("No authentication required")

            risk = APIRiskLevel.MEDIUM
            if not p.has_auth and "/admin" in p.path:
                risk = APIRiskLevel.CRITICAL
            elif not p.has_auth:
                risk = APIRiskLevel.HIGH

            shadows.append(
                ShadowAPI(
                    id=_gen_id("SA", p.id, idx),
                    method=p.method,
                    path=p.path,
                    host=p.host,
                    category=category,
                    risk_level=risk,
                    evidence=evidence,
                    first_seen="2026-03-28T00:00:00Z",
                    last_seen="2026-03-30T10:00:00Z",
                    request_count=p.request_count,
                )
            )
            idx += 1
        return shadows

    async def classify_risk(
        self,
        shadows: list[ShadowAPI],
    ) -> list[RiskClassification]:
        """Classify risk for each shadow API."""
        logger.info(
            "sad.classify_risk",
            count=len(shadows),
        )

        classifications: list[RiskClassification] = []
        for i, s in enumerate(shadows):
            factors: list[str] = list(s.evidence)
            pii = "export" in s.path or "users" in s.path
            data_exp = "config" in s.path or "debug" in s.path
            compliance: list[str] = []
            if pii:
                factors.append("Possible PII exposure")
                compliance.append("GDPR")
            if data_exp:
                factors.append("Configuration/debug data leaked")
                compliance.append("SOC2")

            classifications.append(
                RiskClassification(
                    id=_gen_id("RC", s.id, i),
                    api_id=s.id,
                    risk_level=s.risk_level,
                    risk_factors=factors,
                    data_exposure=data_exp,
                    pii_detected=pii,
                    compliance_impact=compliance,
                )
            )
        return classifications

    async def auto_document(
        self,
        shadows: list[ShadowAPI],
    ) -> list[DocumentationEntry]:
        """Auto-generate documentation for discovered APIs."""
        logger.info(
            "sad.auto_document",
            count=len(shadows),
        )

        docs: list[DocumentationEntry] = []
        for i, s in enumerate(shadows):
            desc = (
                f"Undocumented {s.method} endpoint at {s.path} "
                f"on {s.host} — category: {s.category.value}"
            )
            docs.append(
                DocumentationEntry(
                    id=_gen_id("DOC", s.id, i),
                    api_id=s.id,
                    method=s.method,
                    path=s.path,
                    description=desc,
                    parameters=[],
                    response_schema="unknown",
                    status="draft",
                )
            )
        return docs

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Record a shadow API detection metric."""
        logger.info(
            "sad.record_metric",
            metric=metric_name,
            value=value,
        )
        return {"metric": metric_name, "recorded": True}
