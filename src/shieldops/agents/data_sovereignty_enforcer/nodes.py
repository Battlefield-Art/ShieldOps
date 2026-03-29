"""Data Sovereignty Enforcer Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import DataFlow, JurisdictionMapping, ResidencyViolation, TransferValidation
from .tools import DataSovereigntyEnforcerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_data_flows(
    state: dict[str, Any],
    toolkit: DataSovereigntyEnforcerToolkit,
) -> dict[str, Any]:
    """Discover data flows across systems and regions."""
    logger.info("data_sovereignty.node.discover_data_flows")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    session_start = time.time()

    flow_configs = state.get("data_flows", [])
    flows = await toolkit.discover_data_flows(
        tenant_id=tenant_id,
        flow_configs=flow_configs if flow_configs else None,
    )
    flow_dicts = [f.model_dump() for f in flows]

    return {
        "data_flows": flow_dicts,
        "session_start": session_start,
        "current_step": "discover_data_flows",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(flows)} data flows for tenant {tenant_id}"],
    }


async def map_jurisdictions(
    state: dict[str, Any],
    toolkit: DataSovereigntyEnforcerToolkit,
) -> dict[str, Any]:
    """Map data flows to applicable jurisdictions and regulations."""
    logger.info("data_sovereignty.node.map_jurisdictions")
    state = _to_dict(state)
    flow_dicts = state.get("data_flows", [])
    flows = [DataFlow(**f) for f in flow_dicts]

    mappings = await toolkit.map_jurisdictions(flows)
    mapping_dicts = [m.model_dump() for m in mappings]

    cross_border = sum(1 for m in mappings if m.cross_border)
    restricted = sum(1 for m in mappings if m.restricted)

    return {
        "jurisdiction_mappings": mapping_dicts,
        "current_step": "map_jurisdictions",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Mapped {len(mappings)} jurisdiction pairs; "
            f"{cross_border} cross-border, {restricted} restricted"
        ],
    }


async def check_residency(
    state: dict[str, Any],
    toolkit: DataSovereigntyEnforcerToolkit,
) -> dict[str, Any]:
    """Check data residency compliance against regulatory requirements."""
    logger.info("data_sovereignty.node.check_residency")
    state = _to_dict(state)
    flow_dicts = state.get("data_flows", [])
    mapping_dicts = state.get("jurisdiction_mappings", [])

    flows = [DataFlow(**f) for f in flow_dicts]
    mappings = [JurisdictionMapping(**m) for m in mapping_dicts]

    violations = await toolkit.check_residency(flows, mappings)
    violation_dicts = [v.model_dump() for v in violations]

    # LLM enhancement: sovereignty analysis
    reasoning_note = f"Found {len(violations)} residency violations"
    try:
        from .prompts import SYSTEM_ANALYZE, SovereigntyAnalysisResult

        context = json.dumps(
            {
                "flow_count": len(flows),
                "violations": violation_dicts[:20],
                "affected_regulations": list({v.regulation for v in violations}),
                "severity_breakdown": {
                    s: sum(1 for v in violations if v.severity == s)
                    for s in {"critical", "high", "medium", "low"}
                },
            },
            default=str,
        )
        llm_result = cast(
            SovereigntyAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Data sovereignty residency check results:\n{context}",
                schema=SovereigntyAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_sovereignty_enforcer",
            node="check_residency",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_sovereignty_enforcer",
            node="check_residency",
        )

    return {
        "residency_violations": violation_dicts,
        "current_step": "check_residency",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def validate_transfers(
    state: dict[str, Any],
    toolkit: DataSovereigntyEnforcerToolkit,
) -> dict[str, Any]:
    """Validate that cross-border transfers have valid legal mechanisms."""
    logger.info("data_sovereignty.node.validate_transfers")
    state = _to_dict(state)
    flow_dicts = state.get("data_flows", [])
    mapping_dicts = state.get("jurisdiction_mappings", [])

    flows = [DataFlow(**f) for f in flow_dicts]
    mappings = [JurisdictionMapping(**m) for m in mapping_dicts]

    validations = await toolkit.validate_transfers(flows, mappings)
    validation_dicts = [v.model_dump() for v in validations]

    invalid_count = sum(1 for v in validations if not v.valid)

    # LLM enhancement: transfer assessment
    reasoning_note = f"Validated {len(validations)} cross-border transfers; {invalid_count} invalid"
    try:
        from .prompts import SYSTEM_ANALYZE, TransferAssessmentResult

        context = json.dumps(
            {
                "total_transfers": len(validations),
                "invalid": [v.model_dump() for v in validations if not v.valid][:20],
                "mechanisms_used": list({v.mechanism.value for v in validations}),
            },
            default=str,
        )
        llm_result = cast(
            TransferAssessmentResult,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Cross-border transfer validation results:\n{context}",
                schema=TransferAssessmentResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_sovereignty_enforcer",
            node="validate_transfers",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_sovereignty_enforcer",
            node="validate_transfers",
        )

    return {
        "transfer_validations": validation_dicts,
        "current_step": "validate_transfers",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def enforce_policies(
    state: dict[str, Any],
    toolkit: DataSovereigntyEnforcerToolkit,
) -> dict[str, Any]:
    """Enforce sovereignty policies based on violations and transfer validations."""
    logger.info("data_sovereignty.node.enforce_policies")
    state = _to_dict(state)
    flow_dicts = state.get("data_flows", [])
    violation_dicts = state.get("residency_violations", [])
    validation_dicts = state.get("transfer_validations", [])

    flows = [DataFlow(**f) for f in flow_dicts]
    violations = [ResidencyViolation(**v) for v in violation_dicts]
    validations = [TransferValidation(**v) for v in validation_dicts]

    enforcements = await toolkit.enforce_policies(flows, violations, validations)
    enforcement_dicts = [e.model_dump() for e in enforcements]

    blocked = sum(1 for e in enforcements if e.action == "block")
    redirected = sum(1 for e in enforcements if e.action == "redirect")
    return {
        "policy_enforcements": enforcement_dicts,
        "current_step": "enforce_policies",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Enforced policies on {len(enforcements)} flows; "
            f"{blocked} blocked, {redirected} redirected"
        ],
    }


async def report(
    state: dict[str, Any],
    toolkit: DataSovereigntyEnforcerToolkit,
) -> dict[str, Any]:
    """Generate final sovereignty enforcement report with stats."""
    logger.info("data_sovereignty.node.report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    flows = state.get("data_flows", [])
    mappings = state.get("jurisdiction_mappings", [])
    violations = state.get("residency_violations", [])
    validations = state.get("transfer_validations", [])
    enforcements = state.get("policy_enforcements", [])

    # Build stats
    cross_border = sum(1 for m in mappings if m.get("cross_border", False))
    restricted = sum(1 for m in mappings if m.get("restricted", False))
    invalid_transfers = sum(1 for v in validations if not v.get("valid", True))

    severity_counts: dict[str, int] = {}
    for v in violations:
        sev = v.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    action_counts: dict[str, int] = {}
    for e in enforcements:
        act = e.get("action", "unknown")
        action_counts[act] = action_counts.get(act, 0) + 1

    regulation_counts: dict[str, int] = {}
    for v in violations:
        reg = v.get("regulation", "unknown")
        regulation_counts[reg] = regulation_counts.get(reg, 0) + 1

    total_flows = len(flows)
    compliant_flows = total_flows - len(
        {v.get("flow_id") for v in violations}
        | {v.get("flow_id") for v in validations if not v.get("valid", True)}
    )
    compliance_ratio = compliant_flows / total_flows if total_flows else 1.0

    stats = {
        "total_flows": total_flows,
        "cross_border_flows": cross_border,
        "restricted_flows": restricted,
        "residency_violations": len(violations),
        "violation_severity": severity_counts,
        "invalid_transfers": invalid_transfers,
        "transfer_validations": len(validations),
        "enforcements_applied": len(enforcements),
        "enforcement_actions": action_counts,
        "regulations_violated": regulation_counts,
        "compliance_ratio": round(compliance_ratio, 3),
    }

    # Aggregate findings
    findings: list[dict[str, Any]] = []
    for v in violations:
        findings.append(
            {
                "type": "residency_violation",
                "flow_id": v.get("flow_id", ""),
                "regulation": v.get("regulation", ""),
                "severity": v.get("severity", "medium"),
                "detail": v.get("requirement", ""),
                "remediation": v.get("remediation", ""),
            }
        )
    for v in validations:
        if not v.get("valid", True):
            findings.append(
                {
                    "type": "invalid_transfer",
                    "flow_id": v.get("flow_id", ""),
                    "regulation": v.get("regulation", ""),
                    "severity": "high",
                    "detail": v.get("details", ""),
                    "remediation": f"Establish {v.get('mechanism', 'valid')} transfer mechanism",
                }
            )

    # LLM enhancement: executive report
    reasoning_note = (
        f"Report: {total_flows} flows, {len(violations)} violations, "
        f"{invalid_transfers} invalid transfers, compliance={compliance_ratio:.1%}"
    )
    try:
        from .prompts import SYSTEM_REPORT, SovereigntyReportResult

        context = json.dumps(stats, default=str)
        llm_result = cast(
            SovereigntyReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Sovereignty enforcement stats:\n{context}",
                schema=SovereigntyReportResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_sovereignty_enforcer",
            node="report",
        )
        reasoning_note = f"{llm_result.executive_summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_sovereignty_enforcer",
            node="report",
        )

    return {
        "stats": stats,
        "findings": findings,
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }
