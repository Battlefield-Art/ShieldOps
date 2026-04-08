"""Node implementations for the Ransomware Forensics Agent."""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.ransomware_forensics.models import (
    BlastRadiusLevel,
    ForensicsStage,
    RansomwareForensicsState,
    ReasoningStep,
)
from shieldops.agents.ransomware_forensics.prompts import (
    SYSTEM_ATTACK_CHAIN,
    SYSTEM_BLAST_RADIUS,
    SYSTEM_RECOVERY,
    SYSTEM_REPORT,
    SYSTEM_VARIANT_ID,
    AttackChainOutput,
    BlastRadiusOutput,
    ForensicsReportOutput,
    RecoveryOutput,
    VariantOutput,
)
from shieldops.agents.ransomware_forensics.tools import (
    RansomwareForensicsToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: RansomwareForensicsToolkit | None = None


def _get_toolkit() -> RansomwareForensicsToolkit:
    if _toolkit is None:
        return RansomwareForensicsToolkit()
    return _toolkit


async def collect_artifacts(
    state: RansomwareForensicsState,
) -> dict[str, Any]:
    """Collect forensic artifacts from target systems."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    encrypted = await toolkit.collect_encrypted_files(state.target_systems)
    notes = await toolkit.collect_ransom_notes(state.target_systems)
    procs = await toolkit.collect_process_traces(state.target_systems)
    registry = await toolkit.collect_registry_changes(state.target_systems)
    network = await toolkit.collect_network_artifacts(state.target_systems)
    identity = await toolkit.collect_identity_artifacts(state.target_systems)

    all_artifacts = [
        *[{**a, "category": "encrypted_file"} for a in encrypted],
        *[{**a, "category": "ransom_note"} for a in notes],
        *[{**a, "category": "process_trace"} for a in procs],
        *[{**a, "category": "registry_change"} for a in registry],
        *[{**a, "category": "network"} for a in network],
        *[{**a, "category": "identity"} for a in identity],
    ]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_artifacts",
        input_summary=(
            f"Collecting artifacts from "
            f"{len(state.target_systems)} systems "
            f"for incident {state.incident_id}"
        ),
        output_summary=(
            f"Collected {len(all_artifacts)} artifacts "
            f"(encrypted={len(encrypted)}, "
            f"notes={len(notes)}, procs={len(procs)}, "
            f"registry={len(registry)}, "
            f"network={len(network)}, "
            f"identity={len(identity)})"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="edr + network_sensor + identity",
    )

    return {
        "artifacts_collected": all_artifacts,
        "current_stage": ForensicsStage.ANALYZE_ATTACK_CHAIN,
        "reasoning_chain": [*state.reasoning_chain, step],
        "session_start": start,
    }


async def analyze_attack_chain(
    state: RansomwareForensicsState,
) -> dict[str, Any]:
    """Reconstruct the ransomware attack chain with LLM."""
    start = datetime.now(UTC)

    import json as _json

    # Build attack chain from artifacts
    chain: dict[str, Any] = {
        "initial_access_vector": "unknown",
        "lateral_movement_path": [],
        "privilege_escalation": [],
        "persistence_mechanisms": [],
        "c2_servers": [],
        "exfiltration_indicators": [],
        "dwell_time_hours": 0.0,
        "mitre_techniques": [],
        "timeline_events": [],
    }

    # LLM-enhanced attack chain reconstruction
    try:
        artifact_context = _json.dumps(
            {
                "incident_id": state.incident_id,
                "target_systems": state.target_systems,
                "artifact_count": len(state.artifacts_collected),
                "artifacts_sample": (state.artifacts_collected[:20]),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ATTACK_CHAIN,
            user_prompt=(
                "Analyze these forensic artifacts and "
                "reconstruct the attack chain:\n"
                f"{artifact_context}"
            ),
            schema=AttackChainOutput,
        )
        chain["initial_access_vector"] = llm_result.initial_access_vector
        chain["lateral_movement_path"] = llm_result.lateral_movement_path
        chain["privilege_escalation"] = llm_result.privilege_escalation
        chain["persistence_mechanisms"] = llm_result.persistence_mechanisms
        chain["c2_servers"] = llm_result.c2_servers
        chain["exfiltration_indicators"] = llm_result.exfiltration_indicators
        chain["dwell_time_hours"] = llm_result.dwell_time_hours
        chain["mitre_techniques"] = llm_result.mitre_techniques
        logger.info(
            "llm_enhanced",
            node="analyze_attack_chain",
            confidence=llm_result.confidence,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_attack_chain",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_attack_chain",
        input_summary=(f"Analyzing {len(state.artifacts_collected)} artifacts for attack chain"),
        output_summary=(
            f"Chain: access={chain['initial_access_vector']}"
            f", techniques="
            f"{len(chain['mitre_techniques'])}"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "attack_chain": chain,
        "current_stage": ForensicsStage.IDENTIFY_VARIANT,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def identify_variant(
    state: RansomwareForensicsState,
) -> dict[str, Any]:
    """Identify ransomware variant using LLM analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    import json as _json

    variant: dict[str, Any] = {
        "variant": "unknown",
        "confidence": 0.0,
        "file_extension_pattern": "",
        "encryption_algorithm": "",
        "ransom_note_pattern": "",
        "c2_signature": "",
        "known_decryptor_available": False,
        "threat_actor_group": "",
        "iocs": [],
    }

    # Extract IOCs from artifacts for threat intel query
    iocs = [a.get("hash_sha256", "") for a in state.artifacts_collected if a.get("hash_sha256")]
    iocs.extend(state.attack_chain.get("c2_servers", []))

    if iocs:
        await toolkit.query_threat_intel(iocs)

    # LLM-enhanced variant identification
    try:
        variant_context = _json.dumps(
            {
                "artifacts": state.artifacts_collected[:15],
                "attack_chain": state.attack_chain,
                "iocs": iocs[:20],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VARIANT_ID,
            user_prompt=(
                "Identify the ransomware variant "
                "from these forensic indicators:\n"
                f"{variant_context}"
            ),
            schema=VariantOutput,
        )
        variant["variant"] = llm_result.variant
        variant["confidence"] = llm_result.confidence
        variant["encryption_algorithm"] = llm_result.encryption_algorithm
        variant["threat_actor_group"] = llm_result.threat_actor_group
        variant["known_decryptor_available"] = llm_result.known_decryptor_available
        variant["iocs"] = llm_result.iocs
        logger.info(
            "llm_enhanced",
            node="identify_variant",
            variant=llm_result.variant,
            confidence=llm_result.confidence,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_variant",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="identify_variant",
        input_summary=(
            f"Identifying variant from "
            f"{len(state.artifacts_collected)} artifacts "
            f"and {len(iocs)} IOCs"
        ),
        output_summary=(f"Variant={variant['variant']}, confidence={variant['confidence']}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="threat_intel + llm",
    )

    return {
        "variant_identified": variant,
        "current_stage": (ForensicsStage.ASSESS_BLAST_RADIUS),
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def assess_blast_radius(
    state: RansomwareForensicsState,
) -> dict[str, Any]:
    """Assess and predict blast radius using LLM."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    import json as _json

    # Get network topology for spread prediction
    topology = await toolkit.get_network_topology(state.target_systems)

    blast: dict[str, Any] = {
        "level": BlastRadiusLevel.CONTAINED,
        "affected_hosts": list(state.target_systems),
        "affected_services": [],
        "affected_cloud_accounts": [],
        "affected_identities": [],
        "predicted_spread_hosts": [],
        "predicted_spread_services": [],
        "data_encrypted_gb": 0.0,
        "data_exfiltrated_gb": 0.0,
        "business_impact_score": 0.0,
        "propagation_vectors": [],
    }

    # LLM-enhanced blast radius prediction
    try:
        radius_context = _json.dumps(
            {
                "attack_chain": state.attack_chain,
                "variant": state.variant_identified,
                "target_systems": state.target_systems,
                "topology": topology,
                "artifact_count": len(state.artifacts_collected),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BLAST_RADIUS,
            user_prompt=(f"Predict blast radius for this ransomware incident:\n{radius_context}"),
            schema=BlastRadiusOutput,
        )
        blast["level"] = llm_result.level
        blast["affected_hosts"] = llm_result.affected_hosts
        blast["predicted_spread_hosts"] = llm_result.predicted_spread_hosts
        blast["data_encrypted_gb"] = llm_result.data_encrypted_gb
        blast["data_exfiltrated_gb"] = llm_result.data_exfiltrated_gb
        blast["business_impact_score"] = llm_result.business_impact_score
        blast["propagation_vectors"] = llm_result.propagation_vectors
        logger.info(
            "llm_enhanced",
            node="assess_blast_radius",
            level=llm_result.level,
            impact=llm_result.business_impact_score,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_blast_radius",
        )

    affected_count = len(blast["affected_hosts"])
    encrypted_gb = blast["data_encrypted_gb"]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_blast_radius",
        input_summary=(f"Assessing blast radius for {len(state.target_systems)} targets"),
        output_summary=(
            f"Level={blast['level']}, affected={affected_count}, encrypted={encrypted_gb}GB"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="topology + llm",
    )

    return {
        "blast_radius": blast,
        "affected_systems_count": affected_count,
        "estimated_data_encrypted_gb": encrypted_gb,
        "current_stage": (ForensicsStage.RECOMMEND_RECOVERY),
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def recommend_recovery(
    state: RansomwareForensicsState,
) -> dict[str, Any]:
    """Generate recovery recommendations using LLM."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    import json as _json

    # Check backup status for affected systems
    affected = state.blast_radius.get("affected_hosts", state.target_systems)
    backup_status = await toolkit.check_backup_status(affected)

    recovery: list[dict[str, Any]] = []

    # LLM-enhanced recovery planning
    try:
        recovery_context = _json.dumps(
            {
                "variant": state.variant_identified,
                "blast_radius": state.blast_radius,
                "attack_chain": state.attack_chain,
                "backup_status": backup_status,
                "affected_systems": affected,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RECOVERY,
            user_prompt=(
                f"Recommend recovery strategy for this ransomware incident:\n{recovery_context}"
            ),
            schema=RecoveryOutput,
        )
        for i, rec in enumerate(llm_result.recommendations):
            recovery.append(
                {
                    "priority": i + 1,
                    "action": rec.get("action", ""),
                    "target_system": rec.get("target", ""),
                    "estimated_time_hours": float(rec.get("hours", 0)),
                    "requires_backup_restore": rec.get("backup", False),
                }
            )
        logger.info(
            "llm_enhanced",
            node="recommend_recovery",
            recommendation_count=len(recovery),
            confidence=llm_result.confidence,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend_recovery",
        )
        # Fallback: basic recovery steps
        recovery = [
            {
                "priority": 1,
                "action": "Isolate affected systems",
                "target_system": "all",
                "estimated_time_hours": 1.0,
            },
            {
                "priority": 2,
                "action": "Preserve forensic evidence",
                "target_system": "all",
                "estimated_time_hours": 2.0,
            },
            {
                "priority": 3,
                "action": "Restore from clean backups",
                "target_system": "all",
                "estimated_time_hours": 8.0,
            },
            {
                "priority": 4,
                "action": "Rotate all credentials",
                "target_system": "all",
                "estimated_time_hours": 4.0,
            },
        ]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="recommend_recovery",
        input_summary=(f"Planning recovery for {len(affected)} affected systems"),
        output_summary=(f"Generated {len(recovery)} recovery recommendations"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="backup_connector + llm",
    )

    return {
        "recovery_plan": recovery,
        "current_stage": ForensicsStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def generate_report(
    state: RansomwareForensicsState,
) -> dict[str, Any]:
    """Generate the final forensic investigation report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    import json as _json

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report_data = await toolkit.generate_report(
        {
            "incident_id": state.incident_id,
            "tenant_id": state.tenant_id,
            "artifacts_collected": len(state.artifacts_collected),
            "attack_chain": state.attack_chain,
            "variant": state.variant_identified,
            "blast_radius": state.blast_radius,
            "recovery_plan": state.recovery_plan,
            "affected_systems": (state.affected_systems_count),
            "data_encrypted_gb": (state.estimated_data_encrypted_gb),
        }
    )

    # LLM-enhanced report generation
    try:
        report_context = _json.dumps(
            {
                "incident_id": state.incident_id,
                "attack_chain": state.attack_chain,
                "variant": state.variant_identified,
                "blast_radius": state.blast_radius,
                "recovery_plan": state.recovery_plan,
                "affected_count": (state.affected_systems_count),
                "encrypted_gb": (state.estimated_data_encrypted_gb),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=("Generate the forensic investigation report:\n" + report_context),
            schema=ForensicsReportOutput,
        )
        report_data["executive_summary"] = llm_result.executive_summary
        report_data["severity"] = llm_result.severity
        report_data["key_findings"] = llm_result.key_findings
        report_data["recommendations"] = llm_result.recommendations
        report_data["status"] = "complete"
        logger.info(
            "llm_enhanced",
            node="generate_report",
            severity=llm_result.severity,
            confidence=llm_result.confidence,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=(f"Generating report for incident {state.incident_id}"),
        output_summary=(f"Report status={report_data.get('status', 'unknown')}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="report_generator + llm",
    )

    return {
        "report": report_data,
        "session_duration_ms": duration_ms,
        "current_stage": "complete",
        "reasoning_chain": [*state.reasoning_chain, step],
    }
