"""Vendor Normalizer Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    NormalizedEvent,
    NormalizerStage,
    SchemaMapping,
    VendorEvent,
)
from .tools import VendorNormalizerToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: VendorNormalizerToolkit | None = None


def set_toolkit(toolkit: VendorNormalizerToolkit) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> VendorNormalizerToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = VendorNormalizerToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def ingest_telemetry(
    state: dict[str, Any], toolkit: VendorNormalizerToolkit
) -> dict[str, Any]:
    """Ingest raw vendor events and parse into structured format."""
    logger.info("vendor_normalizer.node.ingest_telemetry")
    state = _to_dict(state)

    raw_events = state.get("vendor_events", [])
    # Accept raw dicts or already-parsed VendorEvent dicts
    raw_list = (
        [
            e if isinstance(e, dict) and "raw_data" not in e else e.get("raw_data", e)
            for e in raw_events
        ]
        if raw_events
        else []
    )

    # If events are already VendorEvent-shaped, pass through
    if raw_list and isinstance(raw_list[0], dict) and "vendor" in raw_list[0]:
        parsed = [VendorEvent(**e) for e in raw_events]
    else:
        parsed = await toolkit.ingest_vendor_events(raw_list if raw_list else raw_events)

    parsed_data = [e.model_dump() for e in parsed]

    return {
        "stage": NormalizerStage.DETECT_SCHEMA.value,
        "vendor_events": parsed_data,
        "session_start": state.get("session_start", ""),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Ingested {len(parsed)} vendor events"],
        "current_step": "ingest_telemetry",
    }


async def detect_schema(state: dict[str, Any], toolkit: VendorNormalizerToolkit) -> dict[str, Any]:
    """Auto-detect vendor schemas and generate field mappings."""
    logger.info("vendor_normalizer.node.detect_schema")
    state = _to_dict(state)

    raw_events = state.get("vendor_events", [])
    events = [VendorEvent(**e) for e in raw_events]
    mappings = await toolkit.detect_schema(events)
    mappings_data = [m.model_dump() for m in mappings]

    vendors = {e.vendor.value for e in events}
    reasoning_note = (
        f"Detected schemas for {len(vendors)} vendor(s): "
        f"{', '.join(sorted(vendors))} — {len(mappings)} field mappings"
    )

    # LLM enhancement: deeper schema detection
    try:
        from .prompts import SYSTEM_SCHEMA_DETECTION, SchemaDetectionOutput

        context = json.dumps(
            {
                "vendors_detected": sorted(vendors),
                "mapping_count": len(mappings),
                "sample_fields": [
                    {
                        "vendor": m.vendor.value,
                        "vendor_field": m.vendor_field,
                        "ocsf_field": m.ocsf_field,
                    }
                    for m in mappings[:15]
                ],
            },
            default=str,
        )
        llm_result = cast(
            SchemaDetectionOutput,
            await llm_structured(
                system_prompt=SYSTEM_SCHEMA_DETECTION,
                user_prompt=f"Schema detection context:\n{context}",
                schema=SchemaDetectionOutput,
            ),
        )
        logger.info("llm_enhanced", agent="vendor_normalizer", node="detect_schema")
        reasoning_note = (
            f"[LLM] vendor={llm_result.vendor}, "
            f"category={llm_result.suggested_ocsf_category}, "
            f"conf={llm_result.confidence:.2f}. {reasoning_note}"
        )
    except Exception:
        logger.debug("llm_fallback", agent="vendor_normalizer", node="detect_schema")

    return {
        "stage": NormalizerStage.MAP_TO_OCSF.value,
        "schema_mappings": mappings_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
        "current_step": "detect_schema",
    }


async def map_to_ocsf(state: dict[str, Any], toolkit: VendorNormalizerToolkit) -> dict[str, Any]:
    """Transform vendor events to OCSF normalized format."""
    logger.info("vendor_normalizer.node.map_to_ocsf")
    state = _to_dict(state)

    raw_events = state.get("vendor_events", [])
    raw_mappings = state.get("schema_mappings", [])
    events = [VendorEvent(**e) for e in raw_events]
    mappings = [SchemaMapping(**m) for m in raw_mappings]

    normalized = await toolkit.map_to_ocsf(events, mappings)
    normalized_data = [n.model_dump() for n in normalized]

    reasoning_note = f"Mapped {len(events)} vendor events to {len(normalized)} OCSF events"

    # LLM enhancement: mapping quality review
    try:
        from .prompts import SYSTEM_FIELD_MAPPING, MappingOutput

        context = json.dumps(
            {
                "event_count": len(normalized),
                "sample_events": [
                    {
                        "ocsf_category": n.ocsf_category.value,
                        "vendor": n.vendor_source.value,
                        "severity": n.severity,
                        "observable_count": len(n.observables),
                    }
                    for n in normalized[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            MappingOutput,
            await llm_structured(
                system_prompt=SYSTEM_FIELD_MAPPING,
                user_prompt=f"Mapping context:\n{context}",
                schema=MappingOutput,
            ),
        )
        logger.info("llm_enhanced", agent="vendor_normalizer", node="map_to_ocsf")
        unmapped = len(llm_result.unmapped_fields)
        reasoning_note = f"[LLM] {unmapped} unmapped fields noted. {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="vendor_normalizer", node="map_to_ocsf")

    return {
        "stage": NormalizerStage.VALIDATE.value,
        "normalized_events": normalized_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
        "current_step": "map_to_ocsf",
    }


async def validate_normalization(
    state: dict[str, Any], toolkit: VendorNormalizerToolkit
) -> dict[str, Any]:
    """Validate normalized events against OCSF compliance."""
    logger.info("vendor_normalizer.node.validate_normalization")
    state = _to_dict(state)

    raw_normalized = state.get("normalized_events", [])
    events = [NormalizedEvent(**e) for e in raw_normalized]
    results = await toolkit.validate_normalization(events)
    results_data = [r.model_dump() for r in results]

    valid_count = sum(1 for r in results if r.valid)
    error_count = sum(len(r.errors) for r in results)
    avg_completeness = sum(r.completeness_score for r in results) / max(len(results), 1)

    reasoning_note = (
        f"Validation: {valid_count}/{len(results)} valid, "
        f"{error_count} errors, avg completeness {avg_completeness:.0%}"
    )

    # LLM enhancement: validation insights
    try:
        from .prompts import SYSTEM_VALIDATION, ValidationOutput

        context = json.dumps(
            {
                "total_events": len(results),
                "valid_count": valid_count,
                "error_count": error_count,
                "avg_completeness": round(avg_completeness, 2),
                "sample_errors": [e for r in results for e in r.errors[:3]][:10],
            },
            default=str,
        )
        llm_result = cast(
            ValidationOutput,
            await llm_structured(
                system_prompt=SYSTEM_VALIDATION,
                user_prompt=f"Validation context:\n{context}",
                schema=ValidationOutput,
            ),
        )
        logger.info("llm_enhanced", agent="vendor_normalizer", node="validate_normalization")
        reasoning_note = f"[LLM] {llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="vendor_normalizer", node="validate_normalization")

    stats = state.get("stats", {})
    stats.update(
        {
            "valid_count": valid_count,
            "error_count": error_count,
            "avg_completeness": round(avg_completeness, 2),
        }
    )

    return {
        "stage": NormalizerStage.ENRICH.value,
        "validation_results": results_data,
        "stats": stats,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
        "current_step": "validate_normalization",
    }


async def enrich_context(state: dict[str, Any], toolkit: VendorNormalizerToolkit) -> dict[str, Any]:
    """Enrich normalized events with geo-IP, asset context, threat intel."""
    logger.info("vendor_normalizer.node.enrich_context")
    state = _to_dict(state)

    raw_normalized = state.get("normalized_events", [])
    events = [NormalizedEvent(**e) for e in raw_normalized]
    enriched = await toolkit.enrich_context(events)
    enriched_data = [e.model_dump() for e in enriched]

    total_enrichments = sum(len(e.enrichments) for e in enriched)
    reasoning_note = f"Enriched {len(enriched)} events with {total_enrichments} enrichments"

    # LLM enhancement: enrichment insights
    try:
        from .prompts import SYSTEM_ENRICHMENT, EnrichmentOutput

        context = json.dumps(
            {
                "event_count": len(enriched),
                "total_enrichments": total_enrichments,
                "observable_types": list(
                    {obs.get("type", "unknown") for e in enriched for obs in e.observables}
                ),
            },
            default=str,
        )
        llm_result = cast(
            EnrichmentOutput,
            await llm_structured(
                system_prompt=SYSTEM_ENRICHMENT,
                user_prompt=f"Enrichment context:\n{context}",
                schema=EnrichmentOutput,
            ),
        )
        logger.info("llm_enhanced", agent="vendor_normalizer", node="enrich_context")
        reasoning_note = f"[LLM] threat_context={llm_result.threat_context[:80]}. {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="vendor_normalizer", node="enrich_context")

    return {
        "stage": NormalizerStage.EMIT.value,
        "enriched_events": enriched_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
        "current_step": "enrich_context",
    }


async def emit_unified(state: dict[str, Any], toolkit: VendorNormalizerToolkit) -> dict[str, Any]:
    """Emit unified OCSF events and finalize pipeline stats."""
    logger.info("vendor_normalizer.node.emit_unified")
    state = _to_dict(state)

    enriched = state.get("enriched_events", [])
    validation_results = state.get("validation_results", [])
    session_start = state.get("session_start", "")

    # Calculate session duration
    duration_ms = 0.0
    if session_start:
        try:
            start_ts = float(session_start)
            duration_ms = (time.time() - start_ts) * 1000
        except (ValueError, TypeError):
            pass

    stats = state.get("stats", {})
    stats.update(
        {
            "total_emitted": len(enriched),
            "total_validated": len(validation_results),
            "session_duration_ms": round(duration_ms, 1),
        }
    )

    return {
        "stage": NormalizerStage.EMIT.value,
        "stats": stats,
        "session_duration_ms": round(duration_ms, 1),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Emitted {len(enriched)} unified OCSF events"],
        "current_step": "emit_unified",
    }
