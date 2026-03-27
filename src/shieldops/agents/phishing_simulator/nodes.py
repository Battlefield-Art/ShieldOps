"""Node implementations for the Phishing Simulator Agent."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.agents.phishing_simulator.models import (
    PhishingStage,
)
from shieldops.agents.phishing_simulator.prompts import (
    SYSTEM_CAMPAIGN_DESIGN,
    SYSTEM_PHISHING_REPORT,
    CampaignDesignOutput,
    PhishingReportOutput,
)
from shieldops.agents.phishing_simulator.tools import (
    PhishingSimulatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()


async def design_campaign(
    state: dict[str, Any],
    toolkit: PhishingSimulatorToolkit,
) -> dict[str, Any]:
    """Design a phishing simulation campaign."""
    camp_type = state.get("campaign_type", "credential_harvest")
    departments = state.get("target_departments", [])

    campaigns = await toolkit.design_campaign(camp_type, departments)

    # LLM-enhanced campaign design
    for campaign in campaigns:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_CAMPAIGN_DESIGN,
                user_prompt=(
                    f"Type: {camp_type}, "
                    f"Departments: {departments}, "
                    f"Template: "
                    f"{campaign.get('template_name')}"
                ),
                schema=CampaignDesignOutput,
            )
            campaign["llm_subject"] = getattr(result, "subject_line", "")
            campaign["difficulty"] = getattr(result, "difficulty", "medium")
            logger.info(
                "llm_enhanced",
                node="design_campaign",
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="design_campaign",
            )

    logger.info(
        "phishing_sim.campaign_designed",
        count=len(campaigns),
    )
    return {
        "campaigns_designed": campaigns,
        "stage": PhishingStage.select_targets,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Designed {len(campaigns)} campaign(s) of type {camp_type}",
        ],
    }


async def select_targets(
    state: dict[str, Any],
    toolkit: PhishingSimulatorToolkit,
) -> dict[str, Any]:
    """Select targets for the simulation."""
    departments = state.get("target_departments", [])
    roles = state.get("target_roles", [])

    targets = await toolkit.select_targets(departments, roles)
    logger.info(
        "phishing_sim.targets_selected",
        count=len(targets),
    )
    return {
        "targets_selected": targets,
        "stage": PhishingStage.send_simulations,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Selected {len(targets)} targets across {len(departments)} departments",
        ],
    }


async def send_simulations(
    state: dict[str, Any],
    toolkit: PhishingSimulatorToolkit,
) -> dict[str, Any]:
    """Send simulation emails (safely marked)."""
    campaigns = state.get("campaigns_designed", [])
    targets = state.get("targets_selected", [])

    deliveries = await toolkit.send_simulations(campaigns, targets)
    delivered = [d for d in deliveries if d.get("delivered")]
    logger.info(
        "phishing_sim.simulations_sent",
        total=len(deliveries),
        delivered=len(delivered),
    )
    return {
        "simulations_sent": deliveries,
        "stage": PhishingStage.track_responses,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Sent {len(delivered)}/{len(deliveries)} simulation emails (all marked)",
        ],
    }


async def track_responses(
    state: dict[str, Any],
    toolkit: PhishingSimulatorToolkit,
) -> dict[str, Any]:
    """Track employee responses."""
    deliveries = state.get("simulations_sent", [])
    responses = await toolkit.track_responses(deliveries)

    total = len(responses)
    clicks = len([r for r in responses if r.get("link_clicked")])
    reports = len([r for r in responses if r.get("reported_as_phishing")])

    c_rate = clicks / total if total else 0.0
    r_rate = reports / total if total else 0.0

    logger.info(
        "phishing_sim.responses_tracked",
        total=total,
        clicks=clicks,
        reports=reports,
    )
    return {
        "responses_tracked": responses,
        "click_rate": round(c_rate, 3),
        "report_rate": round(r_rate, 3),
        "stage": PhishingStage.analyze_results,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Tracked {total} responses: click={c_rate:.1%}, report={r_rate:.1%}",
        ],
    }


async def analyze_results(
    state: dict[str, Any],
    toolkit: PhishingSimulatorToolkit,
) -> dict[str, Any]:
    """Analyze results by department/role."""
    targets = state.get("targets_selected", [])
    responses = state.get("responses_tracked", [])

    analyses = await toolkit.analyze_results(targets, responses)
    high_risk = [a for a in analyses if a.get("risk_level") == "high_risk"]
    logger.info(
        "phishing_sim.results_analyzed",
        groups=len(analyses),
        high_risk=len(high_risk),
    )
    return {
        "risk_assessments": analyses,
        "stage": PhishingStage.report,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Analyzed {len(analyses)} groups, {len(high_risk)} high-risk",
        ],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: PhishingSimulatorToolkit,
) -> dict[str, Any]:
    """Generate phishing simulation report."""
    targets = state.get("targets_selected", [])
    responses = state.get("responses_tracked", [])
    assessments = state.get("risk_assessments", [])
    click_rate = state.get("click_rate", 0.0)
    report_rate = state.get("report_rate", 0.0)

    report: dict[str, Any] = {
        "targets_count": len(targets),
        "responses_count": len(responses),
        "click_rate": click_rate,
        "report_rate": report_rate,
        "departments_analyzed": len(assessments),
        "high_risk_groups": len([a for a in assessments if a.get("risk_level") == "high_risk"]),
        "training_recommended": len([a for a in assessments if a.get("training_recommended")]),
    }

    # LLM-enhanced report
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "click_rate": click_rate,
                "report_rate": report_rate,
                "assessments": assessments[:10],
                "targets": len(targets),
            },
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_PHISHING_REPORT,
            user_prompt=(f"Phishing sim results:\n{ctx}"),
            schema=PhishingReportOutput,
        )
        report["executive_summary"] = getattr(result, "executive_summary", "")
        report["recommendations"] = getattr(result, "recommendations", [])
        logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    return {
        "report_summary": report,
        "stage": PhishingStage.report,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Report: click={click_rate:.1%}, report={report_rate:.1%}",
        ],
    }
