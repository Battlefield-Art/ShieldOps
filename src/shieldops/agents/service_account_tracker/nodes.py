"""Service Account Tracker — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AccountStatus,
    ServiceAccount,
    SharingDetection,
    TrackerStage,
    UsageAnomaly,
)
from .tools import ServiceAccountTrackerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover
# ------------------------------------------------------------------


async def discover(
    state: dict[str, Any],
    toolkit: ServiceAccountTrackerToolkit,
) -> dict[str, Any]:
    """Discover service accounts across all configured cloud providers."""
    logger.info("sa_tracker.node.discover")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    session_start = time.time()

    accounts = await toolkit.discover_accounts(tenant_id=tenant_id)
    account_dicts = [a.model_dump() for a in accounts]

    return {
        "service_accounts": account_dicts,
        "stage": TrackerStage.ANALYZE_USAGE.value,
        "session_start": session_start,
        "current_step": "discover",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(accounts)} service accounts for tenant {tenant_id}"],
    }


# ------------------------------------------------------------------
# Node 2: Analyse Usage
# ------------------------------------------------------------------


async def analyze_usage(
    state: dict[str, Any],
    toolkit: ServiceAccountTrackerToolkit,
) -> dict[str, Any]:
    """Fetch and analyse usage logs for each discovered service account."""
    logger.info("sa_tracker.node.analyze_usage")
    state = _to_dict(state)
    accounts = state.get("service_accounts", [])

    enriched: list[dict[str, Any]] = []
    for acct in accounts:
        usage_logs = await toolkit.fetch_usage_logs(
            account_id=acct.get("id", ""),
            window_days=90,
        )
        acct["_usage_logs"] = usage_logs
        acct["_usage_count"] = len(usage_logs)
        enriched.append(acct)

    reasoning_note = f"Analysed usage for {len(enriched)} accounts"

    # LLM enhancement
    try:
        from .prompts import SYSTEM_USAGE_ANALYSIS, UsageAnalysisResult

        context = json.dumps(
            {
                "tenant_id": state.get("tenant_id", ""),
                "account_count": len(enriched),
                "accounts_summary": [
                    {
                        "id": a.get("id"),
                        "name": a.get("name"),
                        "cloud_source": a.get("cloud_source"),
                        "days_inactive": a.get("days_inactive"),
                        "permissions": a.get("permissions", [])[:5],
                        "mfa_enabled": a.get("mfa_enabled"),
                        "key_count": a.get("key_count"),
                        "usage_count": a.get("_usage_count", 0),
                    }
                    for a in enriched[:30]
                ],
            },
            default=str,
        )
        llm_result = cast(
            UsageAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_USAGE_ANALYSIS,
                user_prompt=f"Service account usage data:\n{context}",
                schema=UsageAnalysisResult,
            ),
        )
        logger.info("llm_enhanced", agent="sa_tracker", node="analyze_usage")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="sa_tracker", node="analyze_usage")

    return {
        "service_accounts": enriched,
        "stage": TrackerStage.DETECT_ANOMALIES.value,
        "current_step": "analyze_usage",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 3: Detect Anomalies
# ------------------------------------------------------------------


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: ServiceAccountTrackerToolkit,
) -> dict[str, Any]:
    """Detect usage anomalies and credential sharing across accounts."""
    logger.info("sa_tracker.node.detect_anomalies")
    state = _to_dict(state)
    accounts = state.get("service_accounts", [])

    all_anomalies: list[dict[str, Any]] = []
    all_sharing: list[dict[str, Any]] = []
    shared_count = 0

    for acct in accounts:
        usage_logs = acct.get("_usage_logs", [])
        account_id = acct.get("id", "")

        # Anomaly detection
        anomalies = await toolkit.detect_usage_anomalies(
            account_id=account_id,
            usage_logs=usage_logs,
        )
        all_anomalies.extend([a.model_dump() for a in anomalies])

        # Credential sharing detection
        sharing = await toolkit.detect_credential_sharing(
            account_id=account_id,
            usage_logs=usage_logs,
        )
        if sharing:
            all_sharing.append(sharing.model_dump())
            shared_count += 1

    reasoning_note = (
        f"Detected {len(all_anomalies)} anomalies and {shared_count} shared credentials"
    )

    # LLM assessment
    try:
        from .prompts import SYSTEM_ANOMALY_ASSESSMENT, AnomalyAssessmentResult

        context = json.dumps(
            {
                "account_count": len(accounts),
                "anomaly_count": len(all_anomalies),
                "sharing_count": shared_count,
                "anomalies_summary": all_anomalies[:20],
                "sharing_summary": all_sharing[:10],
            },
            default=str,
        )
        llm_result = cast(
            AnomalyAssessmentResult,
            await llm_structured(
                system_prompt=SYSTEM_ANOMALY_ASSESSMENT,
                user_prompt=f"Anomaly detection data:\n{context}",
                schema=AnomalyAssessmentResult,
            ),
        )
        logger.info("llm_enhanced", agent="sa_tracker", node="detect_anomalies")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="sa_tracker", node="detect_anomalies")

    return {
        "usage_anomalies": all_anomalies,
        "sharing_detections": all_sharing,
        "shared_count": shared_count,
        "stage": TrackerStage.CLASSIFY_RISK.value,
        "current_step": "detect_anomalies",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 4: Classify Risk
# ------------------------------------------------------------------


async def classify_risk(
    state: dict[str, Any],
    toolkit: ServiceAccountTrackerToolkit,
) -> dict[str, Any]:
    """Classify risk for each service account based on all findings."""
    logger.info("sa_tracker.node.classify_risk")
    state = _to_dict(state)
    accounts = state.get("service_accounts", [])
    anomalies_all = state.get("usage_anomalies", [])
    sharing_all = state.get("sharing_detections", [])

    # Index anomalies and sharing by account_id
    anomalies_by_acct: dict[str, list[UsageAnomaly]] = {}
    for a in anomalies_all:
        aid = a.get("account_id", "")
        anomalies_by_acct.setdefault(aid, []).append(UsageAnomaly(**a))

    sharing_by_acct: dict[str, SharingDetection] = {}
    for s in sharing_all:
        sharing_by_acct[s.get("account_id", "")] = SharingDetection(**s)

    classified: list[dict[str, Any]] = []
    orphaned_count = 0

    for acct_dict in accounts:
        sa = ServiceAccount(**{k: v for k, v in acct_dict.items() if not k.startswith("_")})
        acct_anomalies = anomalies_by_acct.get(sa.id, [])
        acct_sharing = sharing_by_acct.get(sa.id)

        sa = await toolkit.classify_risk(
            account=sa,
            anomalies=acct_anomalies,
            sharing=acct_sharing,
        )
        if sa.status == AccountStatus.ORPHANED:
            orphaned_count += 1

        result = sa.model_dump()
        # Preserve internal usage data for downstream nodes
        result["_usage_logs"] = acct_dict.get("_usage_logs", [])
        result["_usage_count"] = acct_dict.get("_usage_count", 0)
        classified.append(result)

    reasoning_note = (
        f"Classified {len(classified)} accounts — "
        f"{orphaned_count} orphaned, "
        f"{state.get('shared_count', 0)} shared"
    )

    # LLM risk classification
    try:
        from .prompts import SYSTEM_RISK_CLASSIFICATION, RiskClassificationResult

        context = json.dumps(
            {
                "classified_count": len(classified),
                "orphaned_count": orphaned_count,
                "shared_count": state.get("shared_count", 0),
                "high_risk": [
                    {"id": c["id"], "name": c["name"], "risk_score": c["risk_score"]}
                    for c in classified
                    if c.get("risk_score", 0) >= 0.6
                ],
            },
            default=str,
        )
        llm_result = cast(
            RiskClassificationResult,
            await llm_structured(
                system_prompt=SYSTEM_RISK_CLASSIFICATION,
                user_prompt=f"Risk classification data:\n{context}",
                schema=RiskClassificationResult,
            ),
        )
        logger.info("llm_enhanced", agent="sa_tracker", node="classify_risk")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="sa_tracker", node="classify_risk")

    return {
        "service_accounts": classified,
        "orphaned_count": orphaned_count,
        "stage": TrackerStage.REMEDIATE.value,
        "current_step": "classify_risk",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 5: Remediate
# ------------------------------------------------------------------


async def remediate(
    state: dict[str, Any],
    toolkit: ServiceAccountTrackerToolkit,
) -> dict[str, Any]:
    """Propose and optionally apply remediation actions."""
    logger.info("sa_tracker.node.remediate")
    state = _to_dict(state)
    accounts = state.get("service_accounts", [])
    sharing_all = state.get("sharing_detections", [])

    sharing_by_acct: dict[str, SharingDetection] = {}
    for s in sharing_all:
        sharing_by_acct[s.get("account_id", "")] = SharingDetection(**s)

    anomalies_all = state.get("usage_anomalies", [])
    anomalies_by_acct: dict[str, list[UsageAnomaly]] = {}
    for a in anomalies_all:
        aid = a.get("account_id", "")
        anomalies_by_acct.setdefault(aid, []).append(UsageAnomaly(**a))

    all_actions: list[dict[str, Any]] = []

    for acct_dict in accounts:
        sa = ServiceAccount(**{k: v for k, v in acct_dict.items() if not k.startswith("_")})
        if sa.risk_score < 0.3:
            continue  # skip low-risk accounts

        acct_anomalies = anomalies_by_acct.get(sa.id, [])
        acct_sharing = sharing_by_acct.get(sa.id)

        actions = await toolkit.propose_remediations(
            account=sa,
            anomalies=acct_anomalies,
            sharing=acct_sharing,
        )
        all_actions.extend([act.model_dump() for act in actions])

    reasoning_note = f"Proposed {len(all_actions)} remediation actions"

    # LLM remediation planning
    try:
        from .prompts import SYSTEM_REMEDIATION_PLAN, RemediationPlanResult

        context = json.dumps(
            {
                "total_accounts": len(accounts),
                "actions_proposed": len(all_actions),
                "actions_summary": all_actions[:20],
            },
            default=str,
        )
        llm_result = cast(
            RemediationPlanResult,
            await llm_structured(
                system_prompt=SYSTEM_REMEDIATION_PLAN,
                user_prompt=f"Remediation planning data:\n{context}",
                schema=RemediationPlanResult,
            ),
        )
        logger.info("llm_enhanced", agent="sa_tracker", node="remediate")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="sa_tracker", node="remediate")

    return {
        "remediation_actions": all_actions,
        "stage": TrackerStage.REPORT.value,
        "current_step": "remediate",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


# ------------------------------------------------------------------
# Node 6: Generate Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: ServiceAccountTrackerToolkit,
) -> dict[str, Any]:
    """Generate the final tracking report with statistics."""
    logger.info("sa_tracker.node.generate_report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    accounts = state.get("service_accounts", [])
    anomalies = state.get("usage_anomalies", [])
    sharing = state.get("sharing_detections", [])
    actions = state.get("remediation_actions", [])

    # Compute stats
    status_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    risk_buckets: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}

    for acct in accounts:
        status = acct.get("status", "active")
        status_counts[status] = status_counts.get(status, 0) + 1
        src = acct.get("cloud_source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1
        score = acct.get("risk_score", 0.0)
        if score >= 0.8:
            risk_buckets["critical"] += 1
        elif score >= 0.6:
            risk_buckets["high"] += 1
        elif score >= 0.3:
            risk_buckets["medium"] += 1
        else:
            risk_buckets["low"] += 1

    stats = {
        "total_accounts": len(accounts),
        "orphaned_count": state.get("orphaned_count", 0),
        "shared_count": state.get("shared_count", 0),
        "anomaly_count": len(anomalies),
        "remediation_count": len(actions),
        "status_distribution": status_counts,
        "source_distribution": source_counts,
        "risk_distribution": risk_buckets,
        "duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "stage": TrackerStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report complete: {len(accounts)} accounts, "
            f"{len(anomalies)} anomalies, "
            f"{len(sharing)} shared credentials, "
            f"{len(actions)} remediation actions"
        ],
    }
