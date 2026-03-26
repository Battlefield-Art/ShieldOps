"""Node implementations for the Cyber Recovery Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cyber_recovery.models import (
    CleanRoomValidation,
    CyberRecoveryState,
    DamageAssessment,
    IntegrityVerification,
    ReasoningStep,
    RecoveryExecution,
    RecoveryPoint,
    ValidationStatus,
)
from shieldops.agents.cyber_recovery.prompts import (
    SYSTEM_CLEAN_ROOM,
    SYSTEM_DAMAGE_ASSESS,
    SYSTEM_RECOVERY_POINT,
    SYSTEM_RUNBOOK,
    CleanRoomAnalysisOutput,
    DamageAssessmentOutput,
    RecoveryPointSelectionOutput,
    RecoveryRunbookOutput,
)
from shieldops.agents.cyber_recovery.tools import CyberRecoveryToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CyberRecoveryToolkit | None = None


def set_toolkit(toolkit: CyberRecoveryToolkit) -> None:
    """Set the toolkit instance for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> CyberRecoveryToolkit:
    if _toolkit is None:
        return CyberRecoveryToolkit()
    return _toolkit


async def assess_damage(
    state: CyberRecoveryState,
) -> dict[str, Any]:
    """Assess damage from the cyber incident."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.assess_damage(state.tenant_id, state.incident_id)
    damage = DamageAssessment(**raw)

    damage_scope: dict[str, Any] = {
        "affected_count": len(damage.affected_systems),
        "encrypted_count": len(damage.encrypted_assets),
        "corrupted_count": len(damage.corrupted_assets),
        "attack_vector": damage.attack_vector,
        "malware_family": damage.malware_family,
        "severity": damage.severity,
        "blast_radius": damage.blast_radius,
    }

    # LLM enhancement: deeper damage analysis
    try:
        ctx = _json.dumps(raw, default=str)
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DAMAGE_ASSESS,
            user_prompt=f"Damage assessment:\n{ctx}",
            schema=DamageAssessmentOutput,
        )
        damage_scope["llm_severity"] = llm_result.severity_score
        damage_scope["attack_class"] = llm_result.attack_classification
        damage_scope["recommended_type"] = llm_result.recommended_recovery_type
        damage_scope["critical_systems"] = llm_result.critical_systems
        logger.info(
            "llm_enhanced",
            node="assess_damage",
            severity=llm_result.severity_score,
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="assess_damage")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_damage",
        input_summary=(f"Incident {state.incident_id}, tenant {state.tenant_id}"),
        output_summary=(
            f"{len(damage.affected_systems)} affected, "
            f"{len(damage.encrypted_assets)} encrypted, "
            f"severity={damage.severity}"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="damage_assessment_engine",
    )

    await toolkit.record_recovery_metric("blast_radius", float(damage.blast_radius))

    return {
        "damage": damage,
        "damage_scope": damage_scope,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_damage",
        "session_start": start,
    }


async def select_recovery_points(
    state: CyberRecoveryState,
) -> dict[str, Any]:
    """Select best recovery points for affected systems."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_points = await toolkit.list_recovery_points(
        state.tenant_id,
        state.damage.affected_systems,
    )
    points = [RecoveryPoint(**p) for p in raw_points if isinstance(p, dict)]

    # Prefer immutable, most recent points
    sorted_points = sorted(
        points,
        key=lambda p: (
            p.is_immutable,
            p.snapshot_time,
        ),
        reverse=True,
    )
    selected_id = sorted_points[0].id if sorted_points else ""

    # LLM enhancement: smarter point selection
    try:
        ctx = _json.dumps(
            {
                "damage": state.damage.model_dump(),
                "points": [p.model_dump() for p in points],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RECOVERY_POINT,
            user_prompt=(f"Recovery point selection:\n{ctx}"),
            schema=RecoveryPointSelectionOutput,
        )
        if llm_result.recommended_point_id:
            selected_id = llm_result.recommended_point_id
        logger.info(
            "llm_enhanced",
            node="select_recovery_points",
            selected=selected_id,
            confidence=llm_result.confidence,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="select_recovery_points",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="select_recovery_points",
        input_summary=(f"{len(state.damage.affected_systems)} affected systems"),
        output_summary=(f"{len(points)} points found, selected={selected_id}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="backup_catalog",
    )

    return {
        "recovery_points": points,
        "selected_point_id": selected_id,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "select_recovery_points",
    }


async def validate_clean_room(
    state: CyberRecoveryState,
) -> dict[str, Any]:
    """Validate recovery points in isolated clean room."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    validations: list[CleanRoomValidation] = []
    for point in state.recovery_points:
        raw = await toolkit.scan_clean_room(point.id)
        validations.append(CleanRoomValidation(**raw))

    has_clean = any(v.validation_status == ValidationStatus.CLEAN for v in validations)

    # LLM enhancement: analyze scan results
    try:
        ctx = _json.dumps(
            [v.model_dump() for v in validations],
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CLEAN_ROOM,
            user_prompt=(f"Clean room scan results:\n{ctx}"),
            schema=CleanRoomAnalysisOutput,
        )
        logger.info(
            "llm_enhanced",
            node="validate_clean_room",
            verdict=llm_result.overall_verdict,
            safe=llm_result.safe_to_restore,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_clean_room",
        )

    clean_count = sum(1 for v in validations if v.validation_status == ValidationStatus.CLEAN)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="validate_clean_room",
        input_summary=(f"Scanning {len(state.recovery_points)} recovery points"),
        output_summary=(f"{clean_count}/{len(validations)} clean, safe_to_restore={has_clean}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="clean_room_scanner",
    )

    await toolkit.record_recovery_metric(
        "clean_room_pass_rate",
        clean_count / max(len(validations), 1),
    )

    return {
        "validations": validations,
        "has_clean_point": has_clean,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_clean_room",
    }


async def execute_recovery(
    state: CyberRecoveryState,
) -> dict[str, Any]:
    """Execute recovery from validated clean points."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Build map of clean recovery points
    clean_point_ids = {
        v.recovery_point_id
        for v in state.validations
        if v.validation_status == ValidationStatus.CLEAN
    }
    clean_points = [p for p in state.recovery_points if p.id in clean_point_ids]

    executions: list[RecoveryExecution] = []
    total_rto = 0.0
    max_rpo = 0.0

    for point in clean_points:
        raw = await toolkit.execute_recovery(
            recovery_point_id=point.id,
            target_system=point.source_system,
            recovery_type=state.recovery_type.value,
            cloud_provider=point.cloud_provider,
        )
        execution = RecoveryExecution(**raw)
        executions.append(execution)
        total_rto += execution.rto_actual_sec

        # RPO = time since snapshot
        import time

        rpo = time.time() - point.snapshot_time
        if rpo > max_rpo:
            max_rpo = rpo

    all_success = all(e.success for e in executions)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_recovery",
        input_summary=(f"Recovering {len(clean_points)} systems, type={state.recovery_type.value}"),
        output_summary=(
            f"{sum(1 for e in executions if e.success)}/"
            f"{len(executions)} succeeded, "
            f"rto={total_rto:.0f}s"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="restore_orchestrator",
    )

    await toolkit.record_recovery_metric("rto_actual_sec", total_rto)
    await toolkit.record_recovery_metric("rpo_actual_sec", max_rpo)

    return {
        "recoveries_executed": executions,
        "recovery_success": all_success,
        "rto_seconds": total_rto,
        "rpo_seconds": max_rpo,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_recovery",
    }


async def verify_integrity(
    state: CyberRecoveryState,
) -> dict[str, Any]:
    """Verify integrity of recovered systems."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results: list[IntegrityVerification] = []
    for execution in state.recoveries_executed:
        if not execution.success:
            continue
        raw = await toolkit.verify_integrity(execution.id, execution.target_system)
        results.append(IntegrityVerification(**raw))

    all_verified = all(
        r.checksum_valid and r.services_healthy and r.data_consistency and r.no_malware_reinfection
        for r in results
    )

    avg_score = sum(r.verification_score for r in results) / max(len(results), 1)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="verify_integrity",
        input_summary=(f"Verifying {len(state.recoveries_executed)} recovered systems"),
        output_summary=(f"Verified={all_verified}, avg_score={avg_score:.2f}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="integrity_verifier",
    )

    await toolkit.record_recovery_metric("integrity_score", avg_score)

    return {
        "integrity_results": results,
        "integrity_verified": all_verified,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "verify_integrity",
    }


async def report(
    state: CyberRecoveryState,
) -> dict[str, Any]:
    """Generate final cyber recovery report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    rto_met = state.rto_seconds <= state.rto_target_seconds
    rpo_met = state.rpo_seconds <= state.rpo_target_seconds

    recovery_report: dict[str, Any] = {
        "tenant_id": state.tenant_id,
        "incident_id": state.incident_id,
        "recovery_type": state.recovery_type.value,
        "damage_scope": state.damage_scope,
        "affected_systems": len(state.damage.affected_systems),
        "recovery_points_evaluated": len(state.recovery_points),
        "clean_room_validations": len(state.validations),
        "recoveries_executed": len(state.recoveries_executed),
        "recovery_success": state.recovery_success,
        "integrity_verified": state.integrity_verified,
        "rto_seconds": state.rto_seconds,
        "rto_target_seconds": state.rto_target_seconds,
        "rto_met": rto_met,
        "rpo_seconds": state.rpo_seconds,
        "rpo_target_seconds": state.rpo_target_seconds,
        "rpo_met": rpo_met,
        "duration_ms": duration_ms,
    }

    # LLM enhancement: generate recovery runbook
    try:
        ctx = _json.dumps(recovery_report, default=str)
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RUNBOOK,
            user_prompt=(f"Recovery results for runbook:\n{ctx}"),
            schema=RecoveryRunbookOutput,
        )
        recovery_report["runbook"] = {
            "title": llm_result.runbook_title,
            "steps": llm_result.steps,
            "estimated_rto_min": llm_result.estimated_rto_min,
            "compliance_notes": llm_result.compliance_notes,
        }
        logger.info(
            "llm_enhanced",
            node="report",
            runbook_steps=len(llm_result.steps),
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="report")

    await toolkit.record_recovery_metric("report_duration_ms", float(duration_ms))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary=(f"Generating report for incident {state.incident_id}"),
        output_summary=(
            f"Recovery {'succeeded' if state.recovery_success else 'failed'}, "
            f"RTO met={rto_met}, RPO met={rpo_met}, "
            f"duration={duration_ms}ms"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "report": recovery_report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
