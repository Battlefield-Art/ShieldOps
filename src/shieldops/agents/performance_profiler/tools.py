"""Performance Profiler Agent — Tool functions for APM-style analysis."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    BottleneckType,
    ImpactLevel,
    LatencyAnalysis,
    PerformanceBottleneck,
    ResourceContention,
    TraceSpan,
)

logger = structlog.get_logger()

# Simulated service topologies for trace generation
_SERVICE_TOPOLOGIES: dict[str, list[dict[str, Any]]] = {
    "web_app": [
        {
            "service": "api-gateway",
            "operation": "route_request",
            "base_duration": 5.0,
            "status_code": 200,
            "tags": {"component": "nginx", "protocol": "http"},
        },
        {
            "service": "auth-service",
            "operation": "validate_token",
            "base_duration": 12.0,
            "status_code": 200,
            "tags": {"component": "jwt", "cache_hit": "true"},
        },
        {
            "service": "user-service",
            "operation": "get_profile",
            "base_duration": 45.0,
            "status_code": 200,
            "tags": {"component": "postgres", "query_type": "select"},
        },
        {
            "service": "user-service",
            "operation": "db_query",
            "base_duration": 180.0,
            "status_code": 200,
            "tags": {"component": "postgres", "query_type": "join", "rows": "5000"},
        },
        {
            "service": "recommendation-service",
            "operation": "fetch_recommendations",
            "base_duration": 320.0,
            "status_code": 200,
            "tags": {"component": "ml_model", "batch_size": "100"},
        },
        {
            "service": "cache-layer",
            "operation": "redis_get",
            "base_duration": 2.0,
            "status_code": 200,
            "tags": {"component": "redis", "cache_hit": "true"},
        },
        {
            "service": "notification-service",
            "operation": "send_push",
            "base_duration": 95.0,
            "status_code": 200,
            "tags": {"component": "fcm", "protocol": "grpc"},
        },
        {
            "service": "payment-service",
            "operation": "process_payment",
            "base_duration": 450.0,
            "status_code": 200,
            "tags": {"component": "stripe_api", "retries": "0"},
        },
    ],
    "microservice": [
        {
            "service": "ingress-controller",
            "operation": "proxy_pass",
            "base_duration": 3.0,
            "status_code": 200,
            "tags": {"component": "envoy", "protocol": "grpc"},
        },
        {
            "service": "order-service",
            "operation": "create_order",
            "base_duration": 65.0,
            "status_code": 201,
            "tags": {"component": "fastapi", "db": "postgres"},
        },
        {
            "service": "inventory-service",
            "operation": "check_stock",
            "base_duration": 35.0,
            "status_code": 200,
            "tags": {"component": "redis", "query_type": "hash_get"},
        },
        {
            "service": "billing-service",
            "operation": "calculate_total",
            "base_duration": 25.0,
            "status_code": 200,
            "tags": {"component": "cpu_bound", "complexity": "O(n)"},
        },
        {
            "service": "shipping-service",
            "operation": "estimate_delivery",
            "base_duration": 210.0,
            "status_code": 200,
            "tags": {"component": "external_api", "vendor": "fedex"},
        },
    ],
    "default": [
        {
            "service": "frontend-bff",
            "operation": "aggregate",
            "base_duration": 15.0,
            "status_code": 200,
            "tags": {"component": "node", "protocol": "http"},
        },
        {
            "service": "backend-api",
            "operation": "process_request",
            "base_duration": 85.0,
            "status_code": 200,
            "tags": {"component": "python", "db": "postgres"},
        },
        {
            "service": "data-store",
            "operation": "query",
            "base_duration": 120.0,
            "status_code": 200,
            "tags": {"component": "postgres", "query_type": "select"},
        },
    ],
}

# Bottleneck detection rules keyed by tag patterns
_BOTTLENECK_RULES: list[dict[str, Any]] = [
    {
        "tag_match": {"component": "postgres"},
        "min_duration_ms": 100.0,
        "bottleneck_type": BottleneckType.DATABASE_QUERY,
        "description": "Slow database query — N+1 pattern or missing index suspected",
        "optimization": (
            "Add composite index on frequently joined columns; "
            "refactor to batch query or use eager loading"
        ),
        "improvement_pct": 60.0,
    },
    {
        "tag_match": {"component": "stripe_api"},
        "min_duration_ms": 200.0,
        "bottleneck_type": BottleneckType.EXTERNAL_API,
        "description": "High-latency external API call blocking request pipeline",
        "optimization": (
            "Implement async non-blocking call with circuit breaker; "
            "add response caching for idempotent requests"
        ),
        "improvement_pct": 45.0,
    },
    {
        "tag_match": {"component": "external_api"},
        "min_duration_ms": 150.0,
        "bottleneck_type": BottleneckType.EXTERNAL_API,
        "description": "External vendor API introducing tail latency",
        "optimization": (
            "Add hedged requests with deadline propagation; cache responses where TTL allows"
        ),
        "improvement_pct": 40.0,
    },
    {
        "tag_match": {"component": "ml_model"},
        "min_duration_ms": 200.0,
        "bottleneck_type": BottleneckType.CPU_BOUND,
        "description": "CPU-intensive ML inference dominating request latency",
        "optimization": (
            "Move inference to async worker pool; apply model quantization or batched inference"
        ),
        "improvement_pct": 50.0,
    },
    {
        "tag_match": {"component": "cpu_bound"},
        "min_duration_ms": 20.0,
        "bottleneck_type": BottleneckType.CPU_BOUND,
        "description": "CPU-bound computation blocking event loop",
        "optimization": (
            "Offload to thread pool executor or dedicated compute worker; "
            "profile hot path for algorithmic optimization"
        ),
        "improvement_pct": 35.0,
    },
    {
        "tag_match": {"component": "fcm"},
        "min_duration_ms": 50.0,
        "bottleneck_type": BottleneckType.NETWORK_IO,
        "description": "Push notification delivery adding synchronous network wait",
        "optimization": (
            "Move to fire-and-forget via message queue; batch notifications to reduce round-trips"
        ),
        "improvement_pct": 70.0,
    },
]

# Contention patterns keyed by service characteristics
_CONTENTION_PATTERNS: list[dict[str, Any]] = [
    {
        "tag_match": {"component": "postgres"},
        "resource": "database_connection_pool",
        "contention_type": "connection_pool_exhaustion",
        "severity": "high",
        "affected_ops": ["db_query", "get_profile", "create_order"],
    },
    {
        "tag_match": {"component": "redis"},
        "resource": "redis_single_thread",
        "contention_type": "head_of_line_blocking",
        "severity": "medium",
        "affected_ops": ["redis_get", "check_stock", "cache_invalidate"],
    },
    {
        "tag_match": {"component": "cpu_bound"},
        "resource": "cpu_cores",
        "contention_type": "thread_pool_saturation",
        "severity": "medium",
        "affected_ops": ["calculate_total", "process_request"],
    },
    {
        "tag_match": {"component": "envoy"},
        "resource": "sidecar_proxy_threads",
        "contention_type": "proxy_thread_contention",
        "severity": "low",
        "affected_ops": ["proxy_pass", "service_to_service"],
    },
]


def _gen_id(prefix: str, *parts: str) -> str:
    """Generate a deterministic ID from parts."""
    raw = ":".join(parts)
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


def _match_tags(span_tags: dict[str, Any], rule_tags: dict[str, str]) -> bool:
    """Check if a span's tags match a rule's tag requirements."""
    return all(span_tags.get(k) == v for k, v in rule_tags.items())


class PerformanceProfilerToolkit:
    """Tools for APM-style performance profiling and bottleneck detection."""

    def __init__(
        self,
        apm_client: Any | None = None,
        metrics_store: Any | None = None,
    ) -> None:
        self._apm_client = apm_client
        self._metrics_store = metrics_store

    async def collect_trace_spans(
        self, tenant_id: str, service_filter: str = ""
    ) -> list[TraceSpan]:
        """Collect distributed trace spans for a tenant's services.

        Uses an APM client if available, otherwise returns representative
        mock spans based on service topology heuristics.
        """
        logger.info(
            "performance_profiler.collect_trace_spans",
            tenant_id=tenant_id,
            service_filter=service_filter,
        )

        if self._apm_client is not None:
            try:
                raw = await self._apm_client.get_spans(tenant_id=tenant_id, service=service_filter)
                return [TraceSpan(**s) for s in raw]
            except Exception:
                logger.exception("performance_profiler.collect_trace_spans.error")

        # Determine topology profile
        filter_lower = service_filter.lower() if service_filter else ""
        if "web" in filter_lower or "app" in filter_lower:
            profile_key = "web_app"
        elif "micro" in filter_lower or "order" in filter_lower:
            profile_key = "microservice"
        else:
            profile_key = "default"

        topology = _SERVICE_TOPOLOGIES[profile_key]
        root_id = _gen_id("TRACE", tenant_id, profile_key)

        spans: list[TraceSpan] = []
        for i, entry in enumerate(topology):
            noise = random.gauss(0, entry["base_duration"] * 0.15)
            duration = max(0.1, entry["base_duration"] + noise)
            parent = root_id if i == 0 else spans[max(0, i - 1)].id

            spans.append(
                TraceSpan(
                    id=_gen_id("SPAN", tenant_id, entry["service"], str(i)),
                    service=entry["service"],
                    operation=entry["operation"],
                    duration_ms=round(duration, 2),
                    parent_id=parent,
                    status_code=entry["status_code"],
                    tags=entry["tags"],
                )
            )

        return spans

    async def analyze_latency_distribution(self, spans: list[TraceSpan]) -> list[LatencyAnalysis]:
        """Compute latency percentiles per service endpoint from trace spans.

        Groups spans by (service, operation) and calculates p50/p95/p99
        distributions plus error rates and throughput estimates.
        """
        logger.info(
            "performance_profiler.analyze_latency_distribution",
            span_count=len(spans),
        )

        if self._metrics_store is not None:
            try:
                raw = await self._metrics_store.get_latency_stats(spans=spans)
                return [LatencyAnalysis(**r) for r in raw]
            except Exception:
                logger.exception("performance_profiler.analyze_latency_distribution.error")

        # Group spans by service+operation
        groups: dict[str, list[float]] = {}
        error_counts: dict[str, int] = {}
        for span in spans:
            key = f"{span.service}:{span.operation}"
            groups.setdefault(key, []).append(span.duration_ms)
            error_counts.setdefault(key, 0)
            if span.status_code >= 400:
                error_counts[key] += 1

        analyses: list[LatencyAnalysis] = []
        for key, durations in groups.items():
            service, operation = key.split(":", 1)
            sorted_d = sorted(durations)
            n = len(sorted_d)

            p50 = sorted_d[int(n * 0.5)] if n else 0.0
            p95 = sorted_d[min(int(n * 0.95), n - 1)] if n else 0.0
            p99 = sorted_d[min(int(n * 0.99), n - 1)] if n else 0.0
            err_rate = error_counts[key] / n if n else 0.0
            rps = round(random.uniform(50, 2000), 1)  # noqa: S311

            analyses.append(
                LatencyAnalysis(
                    id=_gen_id("LAT", service, operation),
                    service=service,
                    endpoint=operation,
                    p50_ms=round(p50, 2),
                    p95_ms=round(p95, 2),
                    p99_ms=round(p99, 2),
                    error_rate=round(err_rate, 4),
                    requests_per_sec=rps,
                )
            )

        # Sort by p99 descending to surface worst endpoints first
        analyses.sort(key=lambda a: a.p99_ms, reverse=True)
        return analyses

    async def detect_bottlenecks(
        self,
        spans: list[TraceSpan],
        latency_analyses: list[LatencyAnalysis],
    ) -> list[PerformanceBottleneck]:
        """Detect performance bottlenecks from trace and latency data.

        Applies rule-based detection matching span tags and durations
        against known bottleneck patterns.
        """
        logger.info(
            "performance_profiler.detect_bottlenecks",
            span_count=len(spans),
            analysis_count=len(latency_analyses),
        )

        bottlenecks: list[PerformanceBottleneck] = []
        seen: set[str] = set()

        for span in spans:
            for rule in _BOTTLENECK_RULES:
                if not _match_tags(span.tags, rule["tag_match"]):
                    continue
                if span.duration_ms < rule["min_duration_ms"]:
                    continue

                dedup_key = f"{span.service}:{rule['bottleneck_type']}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Determine impact level from duration ratio
                ratio = span.duration_ms / rule["min_duration_ms"]
                if ratio >= 4.0:
                    impact = ImpactLevel.CRITICAL
                elif ratio >= 2.5:
                    impact = ImpactLevel.HIGH
                elif ratio >= 1.5:
                    impact = ImpactLevel.MEDIUM
                else:
                    impact = ImpactLevel.LOW

                bottlenecks.append(
                    PerformanceBottleneck(
                        id=_gen_id("BN", span.service, rule["bottleneck_type"]),
                        service=span.service,
                        bottleneck_type=rule["bottleneck_type"],
                        description=rule["description"],
                        impact=impact,
                        avg_latency_ms=round(span.duration_ms, 2),
                        optimization=rule["optimization"],
                        estimated_improvement_pct=rule["improvement_pct"],
                    )
                )

        # Sort by impact severity
        impact_order = {
            ImpactLevel.CRITICAL: 0,
            ImpactLevel.HIGH: 1,
            ImpactLevel.MEDIUM: 2,
            ImpactLevel.LOW: 3,
            ImpactLevel.NEGLIGIBLE: 4,
        }
        bottlenecks.sort(key=lambda b: impact_order.get(b.impact, 5))
        return bottlenecks

    async def identify_resource_contention(
        self, spans: list[TraceSpan]
    ) -> list[ResourceContention]:
        """Identify resource contention from span tag patterns.

        Matches spans against known contention patterns to surface
        shared-resource conflicts (connection pools, thread pools, etc.).
        """
        logger.info(
            "performance_profiler.identify_resource_contention",
            span_count=len(spans),
        )

        contentions: list[ResourceContention] = []
        seen: set[str] = set()

        for span in spans:
            for pattern in _CONTENTION_PATTERNS:
                if not _match_tags(span.tags, pattern["tag_match"]):
                    continue

                dedup_key = f"{span.service}:{pattern['resource']}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                contentions.append(
                    ResourceContention(
                        id=_gen_id("RC", span.service, pattern["resource"]),
                        service=span.service,
                        resource=pattern["resource"],
                        contention_type=pattern["contention_type"],
                        severity=pattern["severity"],
                        affected_operations=pattern["affected_ops"],
                    )
                )

        return contentions
