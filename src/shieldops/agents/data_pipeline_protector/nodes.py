"""Data Pipeline Protector Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import DataPipeline, DPPStage
from .tools import DataPipelineProtectorToolkit

logger = structlog.get_logger()

_toolkit: DataPipelineProtectorToolkit | None = None


def set_toolkit(
    toolkit: DataPipelineProtectorToolkit,
) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> DataPipelineProtectorToolkit:
    """Get the module-level toolkit, creating default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = DataPipelineProtectorToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_pipelines(
    state: dict[str, Any],
    toolkit: DataPipelineProtectorToolkit,
) -> dict[str, Any]:
    """Discover data pipelines in the target environment."""
    logger.info("dpp.node.discover_pipelines")
    state = _to_dict(state)

    environment = state.get("target_environment", "production")
    pipeline_ids = state.get("pipeline_ids", [])

    pipelines = await toolkit.discover_pipelines(
        environment=environment,
        pipeline_ids=pipeline_ids or None,
    )
    pipelines_data = [p.model_dump() for p in pipelines]

    high_risk = sum(1 for p in pipelines if p.risk in ("critical", "high"))
    reasoning = (
        f"Discovered {len(pipelines)} pipelines in '{environment}', {high_risk} high/critical risk"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_PIPELINE_DISCOVERY,
            PipelineDiscoveryOutput,
        )

        ctx = json.dumps(
            {
                "environment": environment,
                "pipeline_count": len(pipelines),
                "high_risk_count": high_risk,
                "pipelines": [
                    {
                        "name": p.name,
                        "type": p.pipeline_type,
                        "risk": p.risk,
                        "records": p.record_count,
                    }
                    for p in pipelines[:15]
                ],
            },
            default=str,
        )
        llm_out = cast(
            PipelineDiscoveryOutput,
            await llm_structured(
                system_prompt=SYSTEM_PIPELINE_DISCOVERY,
                user_prompt=("Pipeline discovery context:\n" + ctx),
                schema=PipelineDiscoveryOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_pipeline_protector",
            node="discover_pipelines",
        )
        reasoning = f"{llm_out.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_pipeline_protector",
            node="discover_pipelines",
        )

    return {
        "stage": DPPStage.SCAN_INPUTS.value,
        "discovered_pipelines": pipelines_data,
        "current_step": "discover_pipelines",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def scan_inputs(
    state: dict[str, Any],
    toolkit: DataPipelineProtectorToolkit,
) -> dict[str, Any]:
    """Scan pipeline inputs for injection and poisoning."""
    logger.info("dpp.node.scan_inputs")
    state = _to_dict(state)

    raw_pipelines = state.get("discovered_pipelines", [])
    pipelines = [DataPipeline(**p) for p in raw_pipelines]

    scans = await toolkit.scan_inputs(pipelines=pipelines)
    scans_data = [s.model_dump() for s in scans]

    critical = sum(1 for s in scans if s.severity == "critical")
    reasoning = (
        f"Scanned inputs for {len(pipelines)} pipelines, "
        f"found {len(scans)} threats "
        f"({critical} critical)"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_INPUT_SCAN,
            InputScanOutput,
        )

        ctx = json.dumps(
            {
                "pipelines_scanned": len(pipelines),
                "findings_count": len(scans),
                "critical_count": critical,
                "findings": [
                    {
                        "type": s.threat_category,
                        "severity": s.severity,
                        "pipeline": s.pipeline_id,
                        "confidence": s.confidence,
                    }
                    for s in scans[:15]
                ],
            },
            default=str,
        )
        llm_out = cast(
            InputScanOutput,
            await llm_structured(
                system_prompt=SYSTEM_INPUT_SCAN,
                user_prompt=("Input scan context:\n" + ctx),
                schema=InputScanOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_pipeline_protector",
            node="scan_inputs",
        )
        reasoning = f"{llm_out.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_pipeline_protector",
            node="scan_inputs",
        )

    return {
        "stage": DPPStage.DETECT_ANOMALIES.value,
        "input_scans": scans_data,
        "current_step": "scan_inputs",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: DataPipelineProtectorToolkit,
) -> dict[str, Any]:
    """Detect anomalies in pipeline data flows."""
    logger.info("dpp.node.detect_anomalies")
    state = _to_dict(state)

    raw_pipelines = state.get("discovered_pipelines", [])
    pipelines = [DataPipeline(**p) for p in raw_pipelines]

    anomalies = await toolkit.detect_anomalies(pipelines)
    anomalies_data = [a.model_dump() for a in anomalies]

    reasoning = f"Detected {len(anomalies)} anomalies across {len(pipelines)} pipelines"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_ANOMALY_DETECTION,
            AnomalyDetectionOutput,
        )

        ctx = json.dumps(
            {
                "pipeline_count": len(pipelines),
                "anomaly_count": len(anomalies),
                "anomalies": [
                    {
                        "type": a.anomaly_type,
                        "severity": a.severity,
                        "pipeline": a.pipeline_id,
                        "deviation": a.deviation_pct,
                    }
                    for a in anomalies[:15]
                ],
            },
            default=str,
        )
        llm_out = cast(
            AnomalyDetectionOutput,
            await llm_structured(
                system_prompt=SYSTEM_ANOMALY_DETECTION,
                user_prompt=("Anomaly detection context:\n" + ctx),
                schema=AnomalyDetectionOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_pipeline_protector",
            node="detect_anomalies",
        )
        reasoning = f"{llm_out.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_pipeline_protector",
            node="detect_anomalies",
        )

    return {
        "stage": DPPStage.VALIDATE_SCHEMAS.value,
        "data_anomalies": anomalies_data,
        "current_step": "detect_anomalies",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def validate_schemas(
    state: dict[str, Any],
    toolkit: DataPipelineProtectorToolkit,
) -> dict[str, Any]:
    """Validate schemas for drift and tampering."""
    logger.info("dpp.node.validate_schemas")
    state = _to_dict(state)

    raw_pipelines = state.get("discovered_pipelines", [])
    pipelines = [DataPipeline(**p) for p in raw_pipelines]

    validations = await toolkit.validate_schemas(pipelines)
    validations_data = [v.model_dump() for v in validations]

    breaking = sum(1 for v in validations if v.is_breaking)
    reasoning = (
        f"Validated schemas for {len(pipelines)} pipelines, "
        f"found {len(validations)} drifts "
        f"({breaking} breaking)"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_SCHEMA_VALIDATION,
            SchemaValidationOutput,
        )

        ctx = json.dumps(
            {
                "pipeline_count": len(pipelines),
                "drift_count": len(validations),
                "breaking_count": breaking,
                "drifts": [
                    {
                        "field": v.field_name,
                        "expected": v.expected_type,
                        "actual": v.actual_type,
                        "breaking": v.is_breaking,
                        "pipeline": v.pipeline_id,
                    }
                    for v in validations[:15]
                ],
            },
            default=str,
        )
        llm_out = cast(
            SchemaValidationOutput,
            await llm_structured(
                system_prompt=SYSTEM_SCHEMA_VALIDATION,
                user_prompt=("Schema validation context:\n" + ctx),
                schema=SchemaValidationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_pipeline_protector",
            node="validate_schemas",
        )
        reasoning = f"{llm_out.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_pipeline_protector",
            node="validate_schemas",
        )

    return {
        "stage": DPPStage.ENFORCE_ACCESS.value,
        "schema_validations": validations_data,
        "current_step": "validate_schemas",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def enforce_access(
    state: dict[str, Any],
    toolkit: DataPipelineProtectorToolkit,
) -> dict[str, Any]:
    """Enforce access controls on pipelines."""
    logger.info("dpp.node.enforce_access")
    state = _to_dict(state)

    raw_pipelines = state.get("discovered_pipelines", [])
    pipelines = [DataPipeline(**p) for p in raw_pipelines]
    input_scans = state.get("input_scans", [])

    enforcements = await toolkit.enforce_access(
        pipelines=pipelines,
        findings=input_scans,
    )
    enforcements_data = [e.model_dump() for e in enforcements]

    denied = sum(1 for e in enforcements if e.decision == "deny")
    remediated = sum(1 for e in enforcements if e.auto_remediated)
    reasoning = (
        f"Enforced access on {len(pipelines)} pipelines: "
        f"{denied} denied, {remediated} auto-remediated"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_ACCESS_ENFORCEMENT,
            AccessEnforcementOutput,
        )

        ctx = json.dumps(
            {
                "pipeline_count": len(pipelines),
                "enforcement_count": len(enforcements),
                "denied_count": denied,
                "remediated_count": remediated,
                "enforcements": [
                    {
                        "principal": e.principal,
                        "action": e.action,
                        "decision": e.decision,
                        "policy": e.policy_name,
                    }
                    for e in enforcements[:15]
                ],
            },
            default=str,
        )
        llm_out = cast(
            AccessEnforcementOutput,
            await llm_structured(
                system_prompt=SYSTEM_ACCESS_ENFORCEMENT,
                user_prompt=("Access enforcement context:\n" + ctx),
                schema=AccessEnforcementOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_pipeline_protector",
            node="enforce_access",
        )
        reasoning = f"{llm_out.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_pipeline_protector",
            node="enforce_access",
        )

    return {
        "stage": DPPStage.REPORT.value,
        "access_enforcements": enforcements_data,
        "current_step": "enforce_access",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: DataPipelineProtectorToolkit,
) -> dict[str, Any]:
    """Generate the final protection report."""
    logger.info("dpp.node.generate_report")
    state = _to_dict(state)

    start = state.get("session_start", 0.0)
    duration = (time.time() - start) * 1000 if start > 0 else 0.0

    pipelines = len(state.get("discovered_pipelines", []))
    scans = len(state.get("input_scans", []))
    anomalies = len(state.get("data_anomalies", []))
    schema_issues = len(
        state.get("schema_validations", []),
    )
    access_actions = len(
        state.get("access_enforcements", []),
    )

    total = scans + anomalies + schema_issues

    reasoning = (
        f"Protection scan complete: {pipelines} pipelines, "
        f"{total} findings, "
        f"{access_actions} access enforcements, "
        f"{duration:.0f}ms"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_PROTECTION_REPORT,
            ProtectionReportOutput,
        )

        ctx = json.dumps(
            {
                "pipelines_scanned": pipelines,
                "input_threats": scans,
                "anomalies_detected": anomalies,
                "schema_drifts": schema_issues,
                "access_enforcements": access_actions,
                "duration_ms": round(duration, 2),
            },
            default=str,
        )
        llm_out = cast(
            ProtectionReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_PROTECTION_REPORT,
                user_prompt=("Protection report context:\n" + ctx),
                schema=ProtectionReportOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_pipeline_protector",
            node="generate_report",
        )
        reasoning = f"{llm_out.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_pipeline_protector",
            node="generate_report",
        )

    return {
        "stage": DPPStage.REPORT.value,
        "session_duration_ms": round(duration, 2),
        "current_step": "report",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }
