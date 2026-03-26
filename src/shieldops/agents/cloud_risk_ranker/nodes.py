"""Cloud Risk Ranker Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AttackerTactic,
    AttackPath,
    CloudFinding,
    ExploitabilityAssessment,
    ExploitabilityLevel,
    RankerStage,
)
from .tools import CloudRiskRankerToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: CloudRiskRankerToolkit | None = None


def set_toolkit(toolkit: CloudRiskRankerToolkit) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> CloudRiskRankerToolkit:
    """Get the module-level toolkit, creating default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = CloudRiskRankerToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ---------------------------------------------------------------
# Node 1: collect_cloud_findings
# ---------------------------------------------------------------
async def collect_cloud_findings(
    state: dict[str, Any],
    toolkit: CloudRiskRankerToolkit,
) -> dict[str, Any]:
    """Collect security findings across cloud providers."""
    logger.info("cloud_risk_ranker.node.collect_cloud_findings")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    providers = state.get("providers", ["aws"])

    findings = await toolkit.collect_findings(tenant_id, providers)
    findings_data = [f.model_dump() for f in findings]

    return {
        "stage": RankerStage.CORRELATE_ATTACKER_TACTICS.value,
        "findings": findings_data,
        "findings_count": len(findings),
        "current_step": "collect_cloud_findings",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(findings)} findings across {', '.join(providers)}"],
    }


# ---------------------------------------------------------------
# Node 2: correlate_attacker_tactics
# ---------------------------------------------------------------
async def correlate_attacker_tactics(
    state: dict[str, Any],
    toolkit: CloudRiskRankerToolkit,
) -> dict[str, Any]:
    """Correlate findings with MITRE ATT&CK tactics."""
    logger.info("cloud_risk_ranker.node.correlate_attacker_tactics")
    state = _to_dict(state)

    raw_findings = state.get("findings", [])
    findings = [CloudFinding(**f) for f in raw_findings]

    tactics = await toolkit.correlate_tactics(findings)
    tactics_data = [t.model_dump() for t in tactics]

    unique_techniques = {t.technique_id for t in tactics}
    campaigns = set()
    for t in tactics:
        campaigns.update(t.known_campaigns)

    reasoning_note = (
        f"Correlated {len(tactics)} tactic mappings, "
        f"{len(unique_techniques)} unique techniques, "
        f"{len(campaigns)} known campaigns"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_TACTIC_CORRELATION,
            TacticCorrelationOutput,
        )

        context = json.dumps(
            {
                "total_tactics": len(tactics),
                "unique_techniques": list(unique_techniques),
                "campaigns": list(campaigns),
                "top_correlations": [
                    {
                        "finding": t.finding_id,
                        "technique": t.technique_name,
                        "tactic": t.tactic_name,
                        "confidence": t.confidence,
                    }
                    for t in sorted(
                        tactics,
                        key=lambda x: x.confidence,
                        reverse=True,
                    )[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            TacticCorrelationOutput,
            await llm_structured(
                system_prompt=SYSTEM_TACTIC_CORRELATION,
                user_prompt=(f"Tactic correlation context:\n{context}"),
                schema=TacticCorrelationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cloud_risk_ranker",
            node="correlate_attacker_tactics",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cloud_risk_ranker",
            node="correlate_attacker_tactics",
        )

    return {
        "stage": RankerStage.RANK_BY_EXPLOITABILITY.value,
        "tactics": tactics_data,
        "current_step": "correlate_attacker_tactics",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


# ---------------------------------------------------------------
# Node 3: rank_by_exploitability
# ---------------------------------------------------------------
async def rank_by_exploitability(
    state: dict[str, Any],
    toolkit: CloudRiskRankerToolkit,
) -> dict[str, Any]:
    """Assess exploitability using EPSS and CISA KEV."""
    logger.info("cloud_risk_ranker.node.rank_by_exploitability")
    state = _to_dict(state)

    raw_findings = state.get("findings", [])
    findings = [CloudFinding(**f) for f in raw_findings]

    assessments = await toolkit.assess_exploitability(findings)
    assessments_data = [a.model_dump() for a in assessments]

    active = sum(1 for a in assessments if a.level == ExploitabilityLevel.ACTIVELY_EXPLOITED)
    kev_count = sum(1 for a in assessments if a.in_cisa_kev)
    weapon_count = sum(1 for a in assessments if a.weapon_ready)

    reasoning_note = (
        f"Assessed {len(assessments)} findings: "
        f"{active} actively exploited, {kev_count} in CISA "
        f"KEV, {weapon_count} weapon-ready"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_EXPLOITABILITY_ASSESSMENT,
            ExploitabilityOutput,
        )

        context = json.dumps(
            {
                "total_assessed": len(assessments),
                "actively_exploited": active,
                "in_kev": kev_count,
                "weapon_ready": weapon_count,
                "top_scores": [
                    {
                        "finding_id": a.finding_id,
                        "level": a.level.value,
                        "epss": a.epss_score,
                        "composite": a.composite_score,
                    }
                    for a in sorted(
                        assessments,
                        key=lambda x: x.composite_score,
                        reverse=True,
                    )[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ExploitabilityOutput,
            await llm_structured(
                system_prompt=SYSTEM_EXPLOITABILITY_ASSESSMENT,
                user_prompt=(f"Exploitability context:\n{context}"),
                schema=ExploitabilityOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cloud_risk_ranker",
            node="rank_by_exploitability",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cloud_risk_ranker",
            node="rank_by_exploitability",
        )

    return {
        "stage": RankerStage.GENERATE_ATTACK_PATHS.value,
        "assessments": assessments_data,
        "current_step": "rank_by_exploitability",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


# ---------------------------------------------------------------
# Node 4: generate_attack_paths
# ---------------------------------------------------------------
async def generate_attack_paths(
    state: dict[str, Any],
    toolkit: CloudRiskRankerToolkit,
) -> dict[str, Any]:
    """Generate attack paths from findings through tactics."""
    logger.info("cloud_risk_ranker.node.generate_attack_paths")
    state = _to_dict(state)

    raw_findings = state.get("findings", [])
    raw_tactics = state.get("tactics", [])
    raw_assessments = state.get("assessments", [])

    findings = [CloudFinding(**f) for f in raw_findings]
    tactics = [AttackerTactic(**t) for t in raw_tactics]
    assessments = [ExploitabilityAssessment(**a) for a in raw_assessments]

    paths = await toolkit.generate_attack_paths(findings, tactics, assessments)
    paths_data = [p.model_dump() for p in paths]

    critical_paths = sum(1 for p in paths if p.overall_risk_score >= 80.0)

    reasoning_note = f"Generated {len(paths)} attack paths, {critical_paths} critical (score >= 80)"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_ATTACK_PATH_GENERATION,
            AttackPathOutput,
        )

        context = json.dumps(
            {
                "total_paths": len(paths),
                "critical_paths": critical_paths,
                "top_paths": [
                    {
                        "id": p.id,
                        "impact": p.impact,
                        "blast_radius": p.blast_radius,
                        "likelihood": p.likelihood,
                        "risk_score": p.overall_risk_score,
                        "steps": len(p.steps),
                    }
                    for p in sorted(
                        paths,
                        key=lambda x: x.overall_risk_score,
                        reverse=True,
                    )[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            AttackPathOutput,
            await llm_structured(
                system_prompt=SYSTEM_ATTACK_PATH_GENERATION,
                user_prompt=(f"Attack path context:\n{context}"),
                schema=AttackPathOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cloud_risk_ranker",
            node="generate_attack_paths",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cloud_risk_ranker",
            node="generate_attack_paths",
        )

    return {
        "stage": RankerStage.PRIORITIZE_REMEDIATION.value,
        "attack_paths": paths_data,
        "current_step": "generate_attack_paths",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


# ---------------------------------------------------------------
# Node 5: prioritize_remediation
# ---------------------------------------------------------------
async def prioritize_remediation(
    state: dict[str, Any],
    toolkit: CloudRiskRankerToolkit,
) -> dict[str, Any]:
    """Prioritize remediation by risk-to-effort ratio."""
    logger.info("cloud_risk_ranker.node.prioritize_remediation")
    state = _to_dict(state)

    raw_findings = state.get("findings", [])
    raw_paths = state.get("attack_paths", [])
    raw_assessments = state.get("assessments", [])

    findings = [CloudFinding(**f) for f in raw_findings]
    paths = [AttackPath(**p) for p in raw_paths]
    assessments = [ExploitabilityAssessment(**a) for a in raw_assessments]

    priorities = await toolkit.prioritize_remediation(findings, paths, assessments)
    priorities_data = [p.model_dump() for p in priorities]

    auto_count = sum(1 for p in priorities if p.auto_remediable)
    total_hours = sum(p.estimated_hours for p in priorities)
    mttr = round(total_hours / len(priorities), 1) if priorities else 0.0
    critical_count = sum(1 for p in priorities if p.risk_reduction >= 60.0)

    reasoning_note = (
        f"Prioritized {len(priorities)} remediations, "
        f"{auto_count} auto-remediable, "
        f"est. MTTR {mttr}h"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_REMEDIATION_PRIORITIZATION,
            RemediationRankOutput,
        )

        context = json.dumps(
            {
                "total_actions": len(priorities),
                "auto_remediable": auto_count,
                "total_hours": total_hours,
                "mttr": mttr,
                "top_priorities": [
                    {
                        "rank": p.rank,
                        "action": p.action,
                        "effort": p.effort,
                        "risk_reduction": p.risk_reduction,
                        "auto": p.auto_remediable,
                    }
                    for p in priorities[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RemediationRankOutput,
            await llm_structured(
                system_prompt=SYSTEM_REMEDIATION_PRIORITIZATION,
                user_prompt=(f"Remediation context:\n{context}"),
                schema=RemediationRankOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cloud_risk_ranker",
            node="prioritize_remediation",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cloud_risk_ranker",
            node="prioritize_remediation",
        )

    return {
        "stage": RankerStage.REPORT.value,
        "remediation_priorities": priorities_data,
        "critical_risks": critical_count,
        "mean_time_to_remediate": mttr,
        "current_step": "prioritize_remediation",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


# ---------------------------------------------------------------
# Node 6: generate_report
# ---------------------------------------------------------------
async def generate_report(
    state: dict[str, Any],
    toolkit: CloudRiskRankerToolkit,
) -> dict[str, Any]:
    """Generate the final cloud risk ranking report."""
    logger.info("cloud_risk_ranker.node.generate_report")
    state = _to_dict(state)

    raw_findings = state.get("findings", [])
    raw_tactics = state.get("tactics", [])
    raw_assessments = state.get("assessments", [])
    raw_paths = state.get("attack_paths", [])
    raw_priorities = state.get("remediation_priorities", [])
    critical_risks = state.get("critical_risks", 0)
    mttr = state.get("mean_time_to_remediate", 0.0)

    # Category distribution
    cat_dist: dict[str, int] = {}
    for f in raw_findings:
        cat = f.get("category", "unknown")
        cat_dist[cat] = cat_dist.get(cat, 0) + 1

    # Severity distribution
    sev_dist: dict[str, int] = {}
    for f in raw_findings:
        sev = f.get("severity", "medium")
        sev_dist[sev] = sev_dist.get(sev, 0) + 1

    # Provider distribution
    prov_dist: dict[str, int] = {}
    for f in raw_findings:
        prov = f.get("provider", "unknown")
        prov_dist[prov] = prov_dist.get(prov, 0) + 1

    active_exploits = sum(1 for a in raw_assessments if a.get("level") == "actively_exploited")

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "findings_total": len(raw_findings),
        "tactics_mapped": len(raw_tactics),
        "assessments": len(raw_assessments),
        "attack_paths": len(raw_paths),
        "remediation_priorities": len(raw_priorities),
        "critical_risks": critical_risks,
        "actively_exploited": active_exploits,
        "mean_time_to_remediate_hours": mttr,
        "category_distribution": cat_dist,
        "severity_distribution": sev_dist,
        "provider_distribution": prov_dist,
        "providers": state.get("providers", []),
    }

    # LLM enhancement
    report_summary = (
        f"Ranked {len(raw_findings)} cloud risks across "
        f"{len(prov_dist)} providers. "
        f"{critical_risks} critical risks, "
        f"{active_exploits} actively exploited, "
        f"{len(raw_paths)} attack paths identified."
    )
    try:
        from .prompts import (
            SYSTEM_RISK_REPORT,
            RiskRankerReportOutput,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            RiskRankerReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_RISK_REPORT,
                user_prompt=(f"Risk ranking stats:\n{context}"),
                schema=RiskRankerReportOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cloud_risk_ranker",
            node="generate_report",
        )
        report_summary = llm_result.summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cloud_risk_ranker",
            node="generate_report",
        )

    return {
        "stage": RankerStage.REPORT.value,
        "stats": stats,
        "critical_risks": critical_risks,
        "mean_time_to_remediate": mttr,
        "session_duration_ms": elapsed,
        "current_step": "generate_report",
        "reasoning_chain": (state.get("reasoning_chain", []) + [report_summary]),
    }
