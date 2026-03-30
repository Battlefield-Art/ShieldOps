"""Security Awareness Engine Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    AwarenessBaseline,
    PhishingResult,
    SAEStage,
    TrainingCompletion,
    UserRiskProfile,
)
from .prompts import (
    SYSTEM_PHISHING_ANALYSIS,
    SYSTEM_REPORT,
    SYSTEM_RISK_ASSESSMENT,
    SYSTEM_TRAINING_PLAN,
    AwarenessReportResult,
    PhishingAnalysisResult,
    RiskAssessmentResult,
    TrainingPlanResult,
)
from .tools import SecurityAwarenessEngineToolkit

logger = structlog.get_logger()


async def assess_baseline(
    state: dict[str, Any],
    toolkit: SecurityAwarenessEngineToolkit,
) -> dict[str, Any]:
    """Assess security awareness baseline per department."""
    logger.info("sae.node.assess_baseline")

    tenant_id = state.get("tenant_id", "")
    baselines = await toolkit.assess_baseline(tenant_id)
    baselines_data = [b.model_dump(mode="json") for b in baselines]

    total_users = sum(b.total_users for b in baselines)
    avg_completion = (
        sum(b.completion_rate for b in baselines) / len(baselines) if baselines else 0.0
    )

    return {
        "stage": SAEStage.ANALYZE_PHISHING.value,
        "baselines": baselines_data,
        "total_users": total_users,
        "overall_completion_rate": round(avg_completion, 1),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Assessed baseline for {len(baselines)} "
            f"departments, {total_users} total users, "
            f"avg completion {avg_completion:.1f}%"
        ],
    }


async def analyze_phishing(
    state: dict[str, Any],
    toolkit: SecurityAwarenessEngineToolkit,
) -> dict[str, Any]:
    """Analyze phishing simulation campaign results."""
    logger.info("sae.node.analyze_phishing")

    tenant_id = state.get("tenant_id", "")
    results = await toolkit.get_phishing_results(tenant_id)
    results_data = [r.model_dump(mode="json") for r in results]

    avg_click = sum(r.click_rate for r in results) / len(results) if results else 0.0

    reasoning_note = f"Analyzed {len(results)} phishing campaigns, avg click rate {avg_click:.1f}%"

    if results:
        try:
            context = json.dumps(
                {
                    "campaigns": [
                        {
                            "name": r.campaign_name,
                            "department": r.department,
                            "click_rate": r.click_rate,
                            "report_rate": r.report_rate,
                            "creds_submitted": (r.credentials_submitted),
                        }
                        for r in results
                    ],
                },
                default=str,
            )
            result = cast(
                PhishingAnalysisResult,
                await llm_structured(
                    system_prompt=(SYSTEM_PHISHING_ANALYSIS),
                    user_prompt=(f"Phishing campaign data:\n{context}"),
                    schema=PhishingAnalysisResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug(
                "llm_fallback",
                agent="security_awareness_engine",
                node="analyze_phishing",
            )

    return {
        "stage": SAEStage.EVALUATE_TRAINING.value,
        "phishing_results": results_data,
        "avg_phishing_click_rate": round(avg_click, 1),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def evaluate_training(
    state: dict[str, Any],
    toolkit: SecurityAwarenessEngineToolkit,
) -> dict[str, Any]:
    """Evaluate training module completion status."""
    logger.info("sae.node.evaluate_training")

    tenant_id = state.get("tenant_id", "")
    completions = await toolkit.get_training_completions(tenant_id)
    completions_data = [c.model_dump(mode="json") for c in completions]

    completed_count = sum(1 for c in completions if c.completed)
    overdue_count = sum(1 for c in completions if c.overdue)
    total = len(completions) if completions else 1

    return {
        "stage": SAEStage.IDENTIFY_RISKS.value,
        "training_completions": completions_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Evaluated {total} training records: "
            f"{completed_count} completed, "
            f"{overdue_count} overdue"
        ],
    }


async def identify_risks(
    state: dict[str, Any],
    toolkit: SecurityAwarenessEngineToolkit,
) -> dict[str, Any]:
    """Identify user risk profiles from awareness data."""
    logger.info("sae.node.identify_risks")

    baselines = [AwarenessBaseline(**b) for b in state.get("baselines", [])]
    phishing = [PhishingResult(**p) for p in state.get("phishing_results", [])]
    completions = [TrainingCompletion(**c) for c in state.get("training_completions", [])]

    profiles = await toolkit.build_risk_profiles(baselines, phishing, completions)
    profiles_data = [p.model_dump(mode="json") for p in profiles]

    high_risk = sum(1 for p in profiles if p.risk_tier.value in ("critical_risk", "high_risk"))

    reasoning_note = f"Built {len(profiles)} risk profiles, {high_risk} high/critical risk users"

    if profiles:
        try:
            context = json.dumps(
                {
                    "total_profiles": len(profiles),
                    "high_risk_count": high_risk,
                    "risk_distribution": {
                        tier: sum(1 for p in profiles if p.risk_tier.value == tier)
                        for tier in [
                            "critical_risk",
                            "high_risk",
                            "moderate_risk",
                            "low_risk",
                        ]
                    },
                },
                default=str,
            )
            result = cast(
                RiskAssessmentResult,
                await llm_structured(
                    system_prompt=SYSTEM_RISK_ASSESSMENT,
                    user_prompt=(f"Risk profile data:\n{context}"),
                    schema=RiskAssessmentResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug(
                "llm_fallback",
                agent="security_awareness_engine",
                node="identify_risks",
            )

    return {
        "stage": SAEStage.GENERATE_PLAN.value,
        "risk_profiles": profiles_data,
        "high_risk_user_count": high_risk,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_plan(
    state: dict[str, Any],
    toolkit: SecurityAwarenessEngineToolkit,
) -> dict[str, Any]:
    """Generate risk-based training recommendations."""
    logger.info("sae.node.generate_plan")

    profiles = [UserRiskProfile(**p) for p in state.get("risk_profiles", [])]

    plans = await toolkit.generate_training_plans(profiles)
    plans_data = [p.model_dump(mode="json") for p in plans]

    reasoning_note = f"Generated {len(plans)} training plans across risk tiers"

    if plans:
        try:
            context = json.dumps(
                {
                    "plans": [
                        {
                            "target": p.target,
                            "priority": p.priority.value,
                            "modules": p.modules,
                            "frequency": p.frequency,
                        }
                        for p in plans
                    ],
                },
                default=str,
            )
            result = cast(
                TrainingPlanResult,
                await llm_structured(
                    system_prompt=SYSTEM_TRAINING_PLAN,
                    user_prompt=(f"Training plan data:\n{context}"),
                    schema=TrainingPlanResult,
                ),
            )
            reasoning_note = f"{result.executive_summary}. {reasoning_note}"
        except Exception:
            logger.debug(
                "llm_fallback",
                agent="security_awareness_engine",
                node="generate_plan",
            )

    return {
        "stage": SAEStage.REPORT.value,
        "training_plans": plans_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: SecurityAwarenessEngineToolkit,
) -> dict[str, Any]:
    """Generate final awareness posture report."""
    logger.info("sae.node.generate_report")

    total_users = state.get("total_users", 0)
    completion_rate = state.get("overall_completion_rate", 0.0)
    click_rate = state.get("avg_phishing_click_rate", 0.0)
    high_risk = state.get("high_risk_user_count", 0)
    plans = state.get("training_plans", [])

    summary = (
        f"Awareness posture: {total_users} users, "
        f"{completion_rate}% training completion, "
        f"{click_rate}% avg phishing click rate, "
        f"{high_risk} high-risk users, "
        f"{len(plans)} training plans generated"
    )

    try:
        context = json.dumps(
            {
                "total_users": total_users,
                "overall_completion_rate": completion_rate,
                "avg_phishing_click_rate": click_rate,
                "high_risk_user_count": high_risk,
                "training_plans": len(plans),
                "baselines": len(state.get("baselines", [])),
                "phishing_campaigns": len(state.get("phishing_results", [])),
            },
            default=str,
        )
        result = cast(
            AwarenessReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Awareness report context:\n{context}"),
                schema=AwarenessReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="security_awareness_engine",
            node="report",
        )

    return {
        "stage": SAEStage.REPORT.value,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
