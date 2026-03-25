"""Data Pipeline Security Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import PipelineStage
from .tools import DataPipelineSecurityToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: DataPipelineSecurityToolkit | None = None


def set_toolkit(toolkit: DataPipelineSecurityToolkit) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> DataPipelineSecurityToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = DataPipelineSecurityToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def scan_rag_pipeline(
    state: dict[str, Any], toolkit: DataPipelineSecurityToolkit
) -> dict[str, Any]:
    """Scan RAG pipeline data sources for poisoning indicators."""
    logger.info("data_pipeline_security.node.scan_rag_pipeline")
    state = _to_dict(state)

    pipeline_id = state.get("pipeline_id", "unknown")
    data_sources = state.get("data_sources", [])

    findings = await toolkit.scan_rag_pipeline(pipeline_id, data_sources)
    findings_data = [f.model_dump() for f in findings]

    reasoning_note = (
        f"Scanned {len(data_sources)} data sources, found {len(findings)} poisoning indicators"
    )

    # LLM enhancement: deeper poisoning analysis
    try:
        from .prompts import SYSTEM_POISONING_ANALYSIS, PoisoningAnalysisOutput

        context_json = json.dumps(
            {
                "pipeline_id": pipeline_id,
                "sources_scanned": len(data_sources),
                "findings_count": len(findings),
                "findings_summary": [
                    {
                        "type": f.poisoning_type,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "source": f.source,
                    }
                    for f in findings[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PoisoningAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_POISONING_ANALYSIS,
                user_prompt=f"RAG pipeline poisoning analysis context:\n{context_json}",
                schema=PoisoningAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="data_pipeline_security", node="scan_rag_pipeline")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="data_pipeline_security", node="scan_rag_pipeline")

    return {
        "stage": PipelineStage.AUDIT_DATA_FLOWS.value,
        "poisoning_findings": findings_data,
        "current_step": "scan_rag_pipeline",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def audit_data_flows(
    state: dict[str, Any], toolkit: DataPipelineSecurityToolkit
) -> dict[str, Any]:
    """Audit data flow patterns for anomalies."""
    logger.info("data_pipeline_security.node.audit_data_flows")
    state = _to_dict(state)

    pipeline_id = state.get("pipeline_id", "unknown")

    anomalies = await toolkit.audit_data_flows(pipeline_id)
    anomalies_data = [a.model_dump() for a in anomalies]

    reasoning_note = (
        f"Audited data flows for pipeline '{pipeline_id}', detected {len(anomalies)} anomalies"
    )

    # LLM enhancement: deeper data flow analysis
    try:
        from .prompts import SYSTEM_DATA_FLOW_ANALYSIS, DataFlowOutput

        context_json = json.dumps(
            {
                "pipeline_id": pipeline_id,
                "anomalies_found": len(anomalies),
                "anomalies_summary": [
                    {
                        "type": a.anomaly_type,
                        "severity": a.severity,
                        "source": a.source,
                        "destination": a.destination,
                        "volume_gb": a.data_volume_gb,
                    }
                    for a in anomalies[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            DataFlowOutput,
            await llm_structured(
                system_prompt=SYSTEM_DATA_FLOW_ANALYSIS,
                user_prompt=f"Data flow analysis context:\n{context_json}",
                schema=DataFlowOutput,
            ),
        )
        logger.info("llm_enhanced", agent="data_pipeline_security", node="audit_data_flows")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="data_pipeline_security", node="audit_data_flows")

    return {
        "stage": PipelineStage.DETECT_POISONING.value,
        "data_flow_anomalies": anomalies_data,
        "current_step": "audit_data_flows",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_poisoning(
    state: dict[str, Any], toolkit: DataPipelineSecurityToolkit
) -> dict[str, Any]:
    """Deep poisoning detection on documents and training data."""
    logger.info("data_pipeline_security.node.detect_poisoning")
    state = _to_dict(state)

    pipeline_id = state.get("pipeline_id", "unknown")
    data_sources = state.get("data_sources", [])

    # Collect all documents from data sources for deep analysis
    all_documents: list[dict[str, Any]] = []
    for source in data_sources:
        docs = source.get("documents", source.get("content", []))
        if isinstance(docs, str):
            docs = [{"text": docs}]
        all_documents.extend(docs)

    findings = await toolkit.detect_poisoning(pipeline_id, all_documents)
    findings_data = [f.model_dump() for f in findings]

    # Merge with existing poisoning findings (deduplicate by poisoning_type + source)
    existing = state.get("poisoning_findings", [])
    existing_keys = {(f.get("poisoning_type"), f.get("source")) for f in existing}
    new_findings = [
        f for f in findings_data if (f.get("poisoning_type"), f.get("source")) not in existing_keys
    ]

    reasoning_note = (
        f"Deep-scanned {len(all_documents)} documents, "
        f"found {len(findings)} poisoning indicators ({len(new_findings)} new)"
    )

    # LLM enhancement
    try:
        from .prompts import SYSTEM_POISONING_ANALYSIS, PoisoningAnalysisOutput

        context_json = json.dumps(
            {
                "pipeline_id": pipeline_id,
                "documents_scanned": len(all_documents),
                "total_findings": len(existing) + len(new_findings),
                "new_findings": len(new_findings),
                "finding_types": list({f.get("poisoning_type") for f in findings_data}),
            },
            default=str,
        )
        llm_result = cast(
            PoisoningAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_POISONING_ANALYSIS,
                user_prompt=f"Deep poisoning detection context:\n{context_json}",
                schema=PoisoningAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="data_pipeline_security", node="detect_poisoning")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="data_pipeline_security", node="detect_poisoning")

    return {
        "stage": PipelineStage.ASSESS_PROVENANCE.value,
        "poisoning_findings": existing + new_findings,
        "current_step": "detect_poisoning",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assess_provenance(
    state: dict[str, Any], toolkit: DataPipelineSecurityToolkit
) -> dict[str, Any]:
    """Verify provenance of model and data artifacts."""
    logger.info("data_pipeline_security.node.assess_provenance")
    state = _to_dict(state)

    pipeline_id = state.get("pipeline_id", "unknown")
    data_sources = state.get("data_sources", [])

    # Collect artifacts from data sources
    artifacts: list[dict[str, Any]] = []
    for source in data_sources:
        source_artifacts = source.get("artifacts", [])
        artifacts.extend(source_artifacts)

    records = await toolkit.verify_model_provenance(pipeline_id, artifacts)
    records_data = [r.model_dump() for r in records]

    unverified_count = sum(1 for r in records if not r.verified)
    reasoning_note = (
        f"Verified provenance of {len(artifacts)} artifacts, {unverified_count} unverified"
    )

    # LLM enhancement: provenance assessment
    try:
        from .prompts import SYSTEM_PROVENANCE_VERIFICATION, ProvenanceOutput

        context_json = json.dumps(
            {
                "pipeline_id": pipeline_id,
                "artifacts_checked": len(artifacts),
                "verified": len(artifacts) - unverified_count,
                "unverified": unverified_count,
                "unverified_artifacts": [
                    {
                        "name": r.artifact_name,
                        "type": r.artifact_type,
                        "origin": r.origin,
                        "risk_level": r.risk_level,
                    }
                    for r in records
                    if not r.verified
                ],
            },
            default=str,
        )
        llm_result = cast(
            ProvenanceOutput,
            await llm_structured(
                system_prompt=SYSTEM_PROVENANCE_VERIFICATION,
                user_prompt=f"Provenance verification context:\n{context_json}",
                schema=ProvenanceOutput,
            ),
        )
        logger.info("llm_enhanced", agent="data_pipeline_security", node="assess_provenance")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="data_pipeline_security", node="assess_provenance")

    return {
        "stage": PipelineStage.ENFORCE_POLICIES.value,
        "provenance_records": records_data,
        "current_step": "assess_provenance",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def enforce_policies(
    state: dict[str, Any], toolkit: DataPipelineSecurityToolkit
) -> dict[str, Any]:
    """Enforce data pipeline security policies."""
    logger.info("data_pipeline_security.node.enforce_policies")
    state = _to_dict(state)

    findings = state.get("poisoning_findings", [])
    anomalies = state.get("data_flow_anomalies", [])

    violations = await toolkit.enforce_pipeline_policies(findings, anomalies)
    violations_data = [v.model_dump() for v in violations]

    auto_remediated = [v for v in violations if v.auto_remediated]
    policies_enforced = list({v.policy_name for v in violations})

    reasoning_note = (
        f"Enforced {len(policies_enforced)} policies, "
        f"found {len(violations)} violations "
        f"({len(auto_remediated)} auto-remediated)"
    )

    # LLM enhancement: policy enforcement summary
    try:
        from .prompts import SYSTEM_POLICY_ENFORCEMENT, PolicyOutput

        context_json = json.dumps(
            {
                "poisoning_findings_count": len(findings),
                "anomalies_count": len(anomalies),
                "violations_count": len(violations),
                "auto_remediated_count": len(auto_remediated),
                "policies_enforced": policies_enforced,
                "violations_summary": [
                    {
                        "policy": v.policy_name,
                        "resource": v.resource,
                        "severity": v.severity,
                        "auto_remediated": v.auto_remediated,
                    }
                    for v in violations[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PolicyOutput,
            await llm_structured(
                system_prompt=SYSTEM_POLICY_ENFORCEMENT,
                user_prompt=f"Policy enforcement context:\n{context_json}",
                schema=PolicyOutput,
            ),
        )
        logger.info("llm_enhanced", agent="data_pipeline_security", node="enforce_policies")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="data_pipeline_security", node="enforce_policies")

    return {
        "stage": PipelineStage.REPORT.value,
        "policy_violations": violations_data,
        "policies_enforced": policies_enforced,
        "current_step": "enforce_policies",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any], toolkit: DataPipelineSecurityToolkit
) -> dict[str, Any]:
    """Summarize all findings into final report."""
    logger.info("data_pipeline_security.node.generate_report")
    state = _to_dict(state)

    session_start = state.get("session_start", 0.0)
    duration = (time.time() - session_start) * 1000 if session_start > 0 else 0.0

    total_findings = (
        len(state.get("poisoning_findings", []))
        + len(state.get("data_flow_anomalies", []))
        + len(state.get("policy_violations", []))
    )

    unverified_artifacts = sum(
        1 for r in state.get("provenance_records", []) if not r.get("verified", True)
    )

    return {
        "stage": PipelineStage.REPORT.value,
        "session_duration_ms": round(duration, 2),
        "current_step": "report",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Data Pipeline Security scan complete: {total_findings} total findings, "
            f"{unverified_artifacts} unverified artifacts, "
            f"{len(state.get('policies_enforced', []))} policies enforced"
        ],
    }
