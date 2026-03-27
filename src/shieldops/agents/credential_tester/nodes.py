"""Node implementations for the Credential Tester Agent."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.agents.credential_tester.models import (
    CredentialStage,
)
from shieldops.agents.credential_tester.prompts import (
    SYSTEM_CREDENTIAL_REPORT,
    SYSTEM_RISK_ASSESSMENT,
    CredentialReportOutput,
    RiskAssessmentOutput,
)
from shieldops.agents.credential_tester.tools import (
    CredentialTesterToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()


async def audit_password_policies(
    state: dict[str, Any],
    toolkit: CredentialTesterToolkit,
) -> dict[str, Any]:
    """Audit password policies."""
    names = state.get("policy_names", [])
    policies = await toolkit.audit_password_policies(names)
    non_compliant = [p for p in policies if not p.get("compliant")]
    logger.info(
        "credential_tester.policies_audited",
        total=len(policies),
        non_compliant=len(non_compliant),
    )
    return {
        "policies_audited": policies,
        "stage": (CredentialStage.check_leaked_credentials),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Audited {len(policies)} policies, {len(non_compliant)} non-compliant",
        ],
    }


async def check_leaked_credentials(
    state: dict[str, Any],
    toolkit: CredentialTesterToolkit,
) -> dict[str, Any]:
    """Check for leaked credentials via k-anonymity."""
    accounts = state.get("account_ids", [])
    results = await toolkit.check_leaked_credentials(accounts)
    leaked = [r for r in results if r.get("is_leaked")]
    logger.info(
        "credential_tester.leaked_checked",
        total=len(results),
        leaked=len(leaked),
    )
    return {
        "leaked_found": results,
        "stage": CredentialStage.test_mfa_coverage,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Checked {len(results)} accounts, {len(leaked)} leaked (k-anonymity)",
        ],
    }


async def test_mfa_coverage(
    state: dict[str, Any],
    toolkit: CredentialTesterToolkit,
) -> dict[str, Any]:
    """Test MFA enrollment coverage."""
    accounts = state.get("account_ids", [])
    results = await toolkit.test_mfa_coverage(accounts)
    gaps = [r for r in results if not r.get("mfa_enabled")]
    logger.info(
        "credential_tester.mfa_tested",
        total=len(results),
        gaps=len(gaps),
    )
    return {
        "mfa_gaps": gaps,
        "stage": (CredentialStage.test_credential_rotation),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"MFA coverage: {len(gaps)}/{len(results)} accounts without MFA",
        ],
    }


async def test_credential_rotation(
    state: dict[str, Any],
    toolkit: CredentialTesterToolkit,
) -> dict[str, Any]:
    """Test credential rotation compliance."""
    accounts = state.get("account_ids", [])
    results = await toolkit.test_credential_rotation(accounts)
    overdue = [r for r in results if r.get("overdue")]
    logger.info(
        "credential_tester.rotation_tested",
        total=len(results),
        overdue=len(overdue),
    )
    return {
        "rotation_issues": overdue,
        "stage": CredentialStage.assess_risk,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Rotation: {len(overdue)}/{len(results)} overdue",
        ],
    }


async def assess_risk(
    state: dict[str, Any],
    toolkit: CredentialTesterToolkit,
) -> dict[str, Any]:
    """Assess credential risk per account."""
    accounts = state.get("account_ids", [])
    leaked_map = {
        r.get("account_id"): r.get("is_leaked", False) for r in state.get("leaked_found", [])
    }
    mfa_map = {r.get("account_id"): True for r in state.get("mfa_gaps", [])}
    rotation_map = {r.get("account_id"): True for r in state.get("rotation_issues", [])}
    policies = state.get("policies_audited", [])
    policy_ok = all(p.get("compliant") for p in policies)

    scores: list[dict[str, Any]] = []
    at_risk: list[dict[str, Any]] = []

    for acct in accounts:
        score = await toolkit.compute_risk_score(
            account_id=acct,
            leaked=leaked_map.get(acct, False),
            mfa=acct not in mfa_map,
            overdue=rotation_map.get(acct, False),
            policy_compliant=policy_ok,
        )
        scores.append(score)
        if score.get("risk_score", 0) >= 20:
            at_risk.append(score)

    # LLM-enhanced risk assessment
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "accounts": len(accounts),
                "at_risk": len(at_risk),
                "scores": scores[:10],
                "policies": policies[:5],
            },
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_RISK_ASSESSMENT,
            user_prompt=(f"Credential risk data:\n{ctx}"),
            schema=RiskAssessmentOutput,
        )
        logger.info(
            "llm_enhanced",
            node="assess_risk",
            overall=getattr(result, "overall_risk", "unknown"),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    logger.info(
        "credential_tester.risk_assessed",
        total=len(scores),
        at_risk=len(at_risk),
    )
    return {
        "risk_scores": scores,
        "accounts_at_risk": at_risk,
        "stage": CredentialStage.report,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Risk: {len(at_risk)}/{len(scores)} accounts at risk",
        ],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: CredentialTesterToolkit,
) -> dict[str, Any]:
    """Generate credential test report."""
    policies = state.get("policies_audited", [])
    leaked = state.get("leaked_found", [])
    mfa_gaps = state.get("mfa_gaps", [])
    rotation = state.get("rotation_issues", [])
    at_risk = state.get("accounts_at_risk", [])
    scores = state.get("risk_scores", [])

    avg_score = 0.0
    if scores:
        avg_score = sum(s.get("risk_score", 0) for s in scores) / len(scores)

    overall = max(0.0, 100.0 - avg_score)

    report: dict[str, Any] = {
        "policies_audited": len(policies),
        "accounts_checked": len(leaked),
        "leaked_credentials": len([item for item in leaked if item.get("is_leaked")]),
        "mfa_gaps": len(mfa_gaps),
        "rotation_overdue": len(rotation),
        "accounts_at_risk": len(at_risk),
        "overall_risk_score": overall,
    }

    # LLM-enhanced report
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "policies": policies[:5],
                "mfa_gaps": len(mfa_gaps),
                "rotation": len(rotation),
                "at_risk": at_risk[:10],
            },
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_CREDENTIAL_REPORT,
            user_prompt=(f"Credential test results:\n{ctx}"),
            schema=CredentialReportOutput,
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
        "overall_risk_score": overall,
        "stage": CredentialStage.report,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Report: risk_score={overall:.1f}, {len(at_risk)} accounts at risk",
        ],
    }
