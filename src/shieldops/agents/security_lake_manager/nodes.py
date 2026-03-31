"""Node implementations for the Security Lake Manager
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_lake_manager.models import (
    LakeStage,
    SecurityLakeState,
)
from shieldops.agents.security_lake_manager.prompts import (
    SYSTEM_REPORT,
    SYSTEM_SCHEMA_NORMALIZATION,
    SYSTEM_SOURCE_DISCOVERY,
    SYSTEM_STORAGE_OPTIMIZATION,
    LakeReportOutput,
    SchemaNormalizationOutput,
    SourceDiscoveryOutput,
    StorageOptimizationOutput,
)
from shieldops.agents.security_lake_manager.tools import (
    SecurityLakeManagerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityLakeManagerToolkit | None = None


def set_toolkit(
    toolkit: SecurityLakeManagerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityLakeManagerToolkit:
    if _toolkit is None:
        return SecurityLakeManagerToolkit()
    return _toolkit


# ------------------------------------------------------------------
# Node: discover_sources
# ------------------------------------------------------------------


async def discover_sources(
    state: SecurityLakeState,
) -> dict[str, Any]:
    """Discover security data sources across the
    environment."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sources = await toolkit.discover_sources(
        tenant_id=state.tenant_id,
    )

    try:
        ctx = _json.dumps(
            {"tenant_id": state.tenant_id, "existing": sources[:5]},
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_SOURCE_DISCOVERY,
            user_prompt=f"Discover data sources:\n{ctx}",
            schema=SourceDiscoveryOutput,
        )
        if llm_out.sources:  # type: ignore[union-attr]
            sources = [*sources, *llm_out.sources]  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="discover_sources",
            count=len(llm_out.sources),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="discover_sources")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "data_sources": sources,
        "total_sources": len(sources),
        "stage": LakeStage.DISCOVER_SOURCES,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Discovered {len(sources)} sources ({elapsed}ms)",
        ],
        "current_step": "discover_sources",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: ingest_data
# ------------------------------------------------------------------


async def ingest_data(
    state: SecurityLakeState,
) -> dict[str, Any]:
    """Ingest data from discovered sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    records = await toolkit.ingest_data(sources=state.data_sources)

    total_bytes = sum(r.get("bytes_ingested", 0) for r in records)
    volume_gb = total_bytes / (1024**3) if total_bytes > 0 else 0.0

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "ingestion_records": records,
        "total_daily_volume_gb": volume_gb,
        "stage": LakeStage.INGEST_DATA,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Ingested {len(records)} batches ({elapsed}ms)",
        ],
        "current_step": "ingest_data",
    }


# ------------------------------------------------------------------
# Node: normalize_schema
# ------------------------------------------------------------------


async def normalize_schema(
    state: SecurityLakeState,
) -> dict[str, Any]:
    """Normalize ingested data to OCSF schema."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mappings = await toolkit.normalize_schema(
        ingestion_records=state.ingestion_records,
    )

    try:
        ctx = _json.dumps(
            {"records": state.ingestion_records[:5]},
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_SCHEMA_NORMALIZATION,
            user_prompt=f"Normalize schemas:\n{ctx}",
            schema=SchemaNormalizationOutput,
        )
        if llm_out.mappings:  # type: ignore[union-attr]
            mappings = [*mappings, *llm_out.mappings]  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="normalize_schema",
            count=len(llm_out.mappings),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="normalize_schema")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "schema_mappings": mappings,
        "stage": LakeStage.NORMALIZE_SCHEMA,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Normalized {len(mappings)} schemas ({elapsed}ms)",
        ],
        "current_step": "normalize_schema",
    }


# ------------------------------------------------------------------
# Node: optimize_storage
# ------------------------------------------------------------------


async def optimize_storage(
    state: SecurityLakeState,
) -> dict[str, Any]:
    """Generate storage tiering recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    optimizations = await toolkit.optimize_storage(
        partitions=state.ingestion_records,
    )

    try:
        ctx = _json.dumps(
            {
                "sources": len(state.data_sources),
                "volume_gb": state.total_daily_volume_gb,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_STORAGE_OPTIMIZATION,
            user_prompt=f"Optimize storage:\n{ctx}",
            schema=StorageOptimizationOutput,
        )
        if llm_out.recommendations:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            optimizations.append(
                {
                    "id": f"llm-opt-{rand_id}",
                    "savings_pct": llm_out.total_savings_pct,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info("llm_enhanced", node="optimize_storage")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="optimize_storage")

    savings = max(
        (o.get("savings_pct", 0) for o in optimizations),
        default=0.0,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "storage_optimizations": optimizations,
        "cost_savings_pct": savings,
        "stage": LakeStage.OPTIMIZE_STORAGE,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Generated {len(optimizations)} optimizations ({elapsed}ms)",
        ],
        "current_step": "optimize_storage",
    }


# ------------------------------------------------------------------
# Node: query_analytics
# ------------------------------------------------------------------


async def query_analytics(
    state: SecurityLakeState,
) -> dict[str, Any]:
    """Run analytics queries against the lake."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.run_analytics(
        queries=["threat_summary", "ingestion_health"],
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "analytics_results": results,
        "stage": LakeStage.QUERY_ANALYTICS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Ran {len(results)} analytics queries ({elapsed}ms)",
        ],
        "current_step": "query_analytics",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityLakeState,
) -> dict[str, Any]:
    """Generate the security lake operational report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_sources": state.total_sources,
        "daily_volume_gb": state.total_daily_volume_gb,
        "cost_savings_pct": state.cost_savings_pct,
    }

    try:
        ctx = _json.dumps(
            {
                "total_sources": state.total_sources,
                "volume_gb": state.total_daily_volume_gb,
                "optimizations": state.storage_optimizations[:5],
                "analytics": state.analytics_results[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate lake report:\n{ctx}",
            schema=LakeReportOutput,
        )
        if isinstance(llm_out, LakeReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "health_score": llm_out.health_score,
                }
            )
        logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_report")

    await toolkit.record_metric(
        "daily_volume_gb",
        state.total_daily_volume_gb,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    return {
        "stats": report,
        "stage": LakeStage.REPORT,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report generated ({elapsed}ms)",
        ],
        "current_step": "complete",
    }
