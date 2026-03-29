"""Phishing Email Analyzer Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import EmailAnalysis, PhishingStage, URLAnalysis
from .tools import PhishingEmailAnalyzerToolkit

logger = structlog.get_logger()

_toolkit: PhishingEmailAnalyzerToolkit | None = None


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def ingest_email(
    state: dict[str, Any],
    toolkit: PhishingEmailAnalyzerToolkit,
) -> dict[str, Any]:
    """Ingest emails for phishing analysis."""
    logger.info("phishing_analyzer.node.ingest_email")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    emails = state.get("emails", [])

    if not emails:
        emails = _sample_emails()

    analyses = await toolkit.ingest_emails(
        tenant_id=tenant_id,
        emails=emails,
    )
    return {
        "email_analyses": [a.model_dump() for a in analyses],
        "total_emails": len(analyses),
        "stage": PhishingStage.INGEST_EMAIL.value,
        "session_start": time.time(),
        "current_step": "ingest_email",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Ingested {len(analyses)} emails for analysis"],
    }


async def analyze_sender(
    state: dict[str, Any],
    toolkit: PhishingEmailAnalyzerToolkit,
) -> dict[str, Any]:
    """Analyze email senders."""
    logger.info("phishing_analyzer.node.analyze_sender")
    state = _to_dict(state)
    raw = state.get("email_analyses", [])

    analyses = [EmailAnalysis(**a) if isinstance(a, dict) else a for a in raw]
    updated = await toolkit.analyze_sender(analyses)

    return {
        "email_analyses": [a.model_dump() for a in updated],
        "stage": PhishingStage.ANALYZE_SENDER.value,
        "current_step": "analyze_sender",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Analyzed {len(updated)} sender reputations"],
    }


async def analyze_urls(
    state: dict[str, Any],
    toolkit: PhishingEmailAnalyzerToolkit,
) -> dict[str, Any]:
    """Analyze URLs in emails."""
    logger.info("phishing_analyzer.node.analyze_urls")
    state = _to_dict(state)
    raw = state.get("email_analyses", [])

    analyses = [EmailAnalysis(**a) if isinstance(a, dict) else a for a in raw]
    url_analyses, malicious = await toolkit.analyze_urls(analyses)

    reasoning_note = f"Analyzed {len(url_analyses)} URLs, {malicious} malicious"

    try:
        from .prompts import SYSTEM_URL_RISK, URLRiskOutput

        context = json.dumps(
            {
                "urls": [u.model_dump() for u in url_analyses[:20]],
                "malicious_count": malicious,
            },
            default=str,
        )
        llm_out = cast(
            URLRiskOutput,
            await llm_structured(
                system_prompt=SYSTEM_URL_RISK,
                user_prompt=f"URL analysis:\n{context}",
                schema=URLRiskOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="phishing_email_analyzer",
            node="analyze_urls",
        )
        reasoning_note = f"{llm_out.summary} [risk={llm_out.risk_level}]"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="phishing_email_analyzer",
            node="analyze_urls",
        )

    return {
        "url_analyses": [u.model_dump() for u in url_analyses],
        "malicious_urls": malicious,
        "stage": PhishingStage.ANALYZE_URLS.value,
        "current_step": "analyze_urls",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def analyze_content(
    state: dict[str, Any],
    toolkit: PhishingEmailAnalyzerToolkit,
) -> dict[str, Any]:
    """Analyze email content for phishing patterns."""
    logger.info("phishing_analyzer.node.analyze_content")
    state = _to_dict(state)
    raw = state.get("email_analyses", [])

    analyses = [EmailAnalysis(**a) if isinstance(a, dict) else a for a in raw]
    content_analyses, impersonations = await toolkit.analyze_content(analyses)

    reasoning_note = f"Content analysis: {impersonations} brand impersonations detected"

    try:
        from .prompts import (
            SYSTEM_PHISHING_CONTENT,
            PhishingContentOutput,
        )

        context = json.dumps(
            {
                "content": content_analyses[:20],
                "impersonations": impersonations,
            },
            default=str,
        )
        llm_out = cast(
            PhishingContentOutput,
            await llm_structured(
                system_prompt=SYSTEM_PHISHING_CONTENT,
                user_prompt=(f"Email content analysis:\n{context}"),
                schema=PhishingContentOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="phishing_email_analyzer",
            node="analyze_content",
        )
        reasoning_note = f"{llm_out.summary} [confidence={llm_out.confidence:.0%}]"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="phishing_email_analyzer",
            node="analyze_content",
        )

    return {
        "content_analyses": content_analyses,
        "brand_impersonations": impersonations,
        "stage": PhishingStage.ANALYZE_CONTENT.value,
        "current_step": "analyze_content",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def score_risk(
    state: dict[str, Any],
    toolkit: PhishingEmailAnalyzerToolkit,
) -> dict[str, Any]:
    """Score overall phishing risk."""
    logger.info("phishing_analyzer.node.score_risk")
    state = _to_dict(state)
    raw_analyses = state.get("email_analyses", [])
    raw_urls = state.get("url_analyses", [])
    content = state.get("content_analyses", [])

    analyses = [EmailAnalysis(**a) if isinstance(a, dict) else a for a in raw_analyses]
    url_analyses = [URLAnalysis(**u) if isinstance(u, dict) else u for u in raw_urls]

    scores, high_risk, avg = await toolkit.score_risk(
        analyses,
        url_analyses,
        content,
    )

    return {
        "risk_scores": scores,
        "high_risk_count": high_risk,
        "avg_risk_score": avg,
        "stage": PhishingStage.SCORE_RISK.value,
        "current_step": "score_risk",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Risk scoring: {high_risk} high-risk, avg score {avg:.2f}"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: PhishingEmailAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate final phishing analysis report."""
    logger.info("phishing_analyzer.node.generate_report")
    state = _to_dict(state)

    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    stats = {
        "total_emails": state.get("total_emails", 0),
        "malicious_urls": state.get("malicious_urls", 0),
        "brand_impersonations": state.get("brand_impersonations", 0),
        "high_risk_count": state.get("high_risk_count", 0),
        "avg_risk_score": state.get("avg_risk_score", 0.0),
        "analysis_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "stage": PhishingStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Report: {stats['total_emails']} emails, {stats['high_risk_count']} high-risk"],
    }


def _sample_emails() -> list[dict[str, Any]]:
    return [
        {
            "from": "security@micr0soft.com",
            "display_name": "Microsoft Security",
            "subject": "Urgent: Verify your account now",
            "body": (
                "Your account will be suspended. "
                "Click https://micr0soft-login.xyz/auth "
                "to verify immediately."
            ),
            "auth_status": "spf=fail dkim=fail",
        },
        {
            "from": "hr@company.com",
            "display_name": "HR Department",
            "subject": "Benefits Update",
            "body": ("Please review updated benefits at https://company.com/benefits"),
            "auth_status": "spf=pass dkim=pass",
        },
    ]
