"""SaaS Security Posture Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    ConfigFinding,
    ReasoningStep,
    SaaSApp,
    SaaSRisk,
    SharingExposure,
    SSPStage,
)
from .tools import SaaSSecurityPostureToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover Apps
# ------------------------------------------------------------------


async def discover_apps(
    state: dict[str, Any],
    toolkit: SaaSSecurityPostureToolkit,
) -> dict[str, Any]:
    """Discover SaaS applications in use."""
    logger.info("ssp.node.discover_apps")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    apps = await toolkit.discover_apps(tenant_id)
    data = [a.model_dump() for a in apps]

    note = f"Discovered {len(apps)} SaaS applications"

    return {
        "stage": SSPStage.AUDIT_CONFIG.value,
        "apps": data,
        "total_apps": len(apps),
        "current_step": "discover_apps",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="discover_apps",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Audit Config
# ------------------------------------------------------------------


async def audit_config(
    state: dict[str, Any],
    toolkit: SaaSSecurityPostureToolkit,
) -> dict[str, Any]:
    """Audit SaaS app configurations."""
    logger.info("ssp.node.audit_config")
    state = _to_dict(state)

    apps = [SaaSApp(**a) for a in state.get("apps", [])]
    findings = await toolkit.audit_config(apps)
    data = [f.model_dump() for f in findings]

    note = f"Found {len(findings)} misconfigurations"

    try:
        from .prompts import SYSTEM_ANALYZE, ConfigInsight

        ctx = json.dumps(
            {
                "findings": [
                    {
                        "app": f.app_name,
                        "check": f.check_name,
                        "severity": f.severity,
                    }
                    for f in findings[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ConfigInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"SaaS config audit:\n{ctx}",
                schema=ConfigInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ssp",
            node="audit_config",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ssp",
            node="audit_config",
        )

    return {
        "stage": SSPStage.CHECK_SHARING.value,
        "config_findings": data,
        "misconfigs_found": len(findings),
        "current_step": "audit_config",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="audit_config",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Check Sharing
# ------------------------------------------------------------------


async def check_sharing(
    state: dict[str, Any],
    toolkit: SaaSSecurityPostureToolkit,
) -> dict[str, Any]:
    """Check data sharing settings across SaaS apps."""
    logger.info("ssp.node.check_sharing")
    state = _to_dict(state)

    apps = [SaaSApp(**a) for a in state.get("apps", [])]
    exposures = await toolkit.check_sharing(apps)
    data = [e.model_dump() for e in exposures]

    sensitive = sum(1 for e in exposures if e.sensitive_data)
    note = f"Found {len(exposures)} sharing exposures, {sensitive} with sensitive data"

    return {
        "stage": SSPStage.ASSESS_RISK.value,
        "sharing_exposures": data,
        "current_step": "check_sharing",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="check_sharing",
                detail=note,
                confidence=0.83,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Assess Risk
# ------------------------------------------------------------------


async def assess_risk(
    state: dict[str, Any],
    toolkit: SaaSSecurityPostureToolkit,
) -> dict[str, Any]:
    """Assess overall risk for each SaaS app."""
    logger.info("ssp.node.assess_risk")
    state = _to_dict(state)

    apps = [SaaSApp(**a) for a in state.get("apps", [])]
    findings = [ConfigFinding(**f) for f in state.get("config_findings", [])]
    exposures = [SharingExposure(**e) for e in state.get("sharing_exposures", [])]
    assessments = await toolkit.assess_risk(
        apps,
        findings,
        exposures,
    )
    data = [a.model_dump() for a in assessments]

    high_risk = sum(1 for a in assessments if a.overall_risk in (SaaSRisk.CRITICAL, SaaSRisk.HIGH))
    note = f"Assessed {len(assessments)} apps, {high_risk} high-risk"

    return {
        "stage": SSPStage.REMEDIATE.value,
        "risk_assessments": data,
        "high_risk_apps": high_risk,
        "current_step": "assess_risk",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_risk",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Remediate
# ------------------------------------------------------------------


async def remediate(
    state: dict[str, Any],
    toolkit: SaaSSecurityPostureToolkit,
) -> dict[str, Any]:
    """Remediate SaaS misconfigurations."""
    logger.info("ssp.node.remediate")
    state = _to_dict(state)

    findings = [ConfigFinding(**f) for f in state.get("config_findings", [])]
    actions = await toolkit.remediate_misconfig(findings)
    data = [a.model_dump() for a in actions]

    applied = sum(1 for a in actions if a.status == "applied")
    note = f"Remediated {applied}/{len(actions)} findings"

    return {
        "stage": SSPStage.REPORT.value,
        "remediations": data,
        "current_step": "remediate",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="remediate",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: SaaSSecurityPostureToolkit,
) -> dict[str, Any]:
    """Compile the final SaaS security posture report."""
    logger.info("ssp.node.report")
    state = _to_dict(state)

    total_apps = state.get("total_apps", 0)
    misconfigs = state.get("misconfigs_found", 0)
    high_risk = state.get("high_risk_apps", 0)
    remediation_count = len(state.get("remediations", []))

    lines = [
        "# SaaS Security Posture Report",
        "",
        f"**Applications discovered:** {total_apps}",
        f"**Misconfigurations found:** {misconfigs}",
        f"**High-risk applications:** {high_risk}",
        f"**Remediations applied:** {remediation_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_apps": total_apps,
                "misconfigs": misconfigs,
                "high_risk": high_risk,
                "remediations": remediation_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"SaaS posture report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ssp",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ssp",
            node="report",
        )

    return {
        "stage": SSPStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
