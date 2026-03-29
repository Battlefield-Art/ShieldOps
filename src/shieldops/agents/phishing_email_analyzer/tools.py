"""Phishing Email Analyzer Agent — Tool functions."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any
from urllib.parse import urlparse

import structlog

from .models import (
    EmailAnalysis,
    PhishingIndicator,
    RiskLevel,
    URLAnalysis,
)

logger = structlog.get_logger()

# Urgency keywords
URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "act now",
    "expire",
    "suspend",
    "verify",
    "confirm",
    "limited time",
    "within 24 hours",
    "account locked",
    "unauthorized",
    "security alert",
    "action required",
]

# Brand keywords for impersonation
BRAND_KEYWORDS: dict[str, list[str]] = {
    "Microsoft": [
        "microsoft",
        "office365",
        "outlook",
        "onedrive",
        "sharepoint",
        "teams",
    ],
    "Google": [
        "google",
        "gmail",
        "drive",
        "workspace",
    ],
    "Apple": ["apple", "icloud", "itunes", "appstore"],
    "Amazon": ["amazon", "aws", "prime"],
    "PayPal": ["paypal", "payment"],
    "Netflix": ["netflix", "streaming"],
    "LinkedIn": ["linkedin", "professional"],
    "DocuSign": ["docusign", "document", "signature"],
}

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "short.io",
}

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".link",
    ".work",
    ".buzz",
    ".surf",
    ".icu",
    ".monster",
}


def _gen_id() -> str:
    return str(uuid.uuid4())[:12]


class PhishingEmailAnalyzerToolkit:
    """Tools for phishing email analysis."""

    def __init__(
        self,
        url_scanner: Any | None = None,
        reputation_client: Any | None = None,
    ) -> None:
        self._url_scanner = url_scanner
        self._reputation = reputation_client

    async def ingest_emails(
        self,
        tenant_id: str,
        emails: list[dict[str, Any]],
    ) -> list[EmailAnalysis]:
        """Ingest and parse emails for analysis."""
        logger.info(
            "phishing_analyzer.ingest",
            tenant_id=tenant_id,
            count=len(emails),
        )
        results: list[EmailAnalysis] = []

        for email_data in emails:
            sender = email_data.get("from", "")
            domain = self._extract_domain(sender)

            analysis = EmailAnalysis(
                id=_gen_id(),
                sender=sender,
                sender_domain=domain,
                display_name=email_data.get("display_name", ""),
                subject=email_data.get("subject", ""),
                body_preview=email_data.get("body", "")[:500],
                has_attachments=bool(email_data.get("attachments")),
                attachment_types=[a.get("type", "") for a in email_data.get("attachments", [])],
                auth_status=email_data.get("auth_status", ""),
            )
            results.append(analysis)

        return results

    async def analyze_sender(
        self,
        analyses: list[EmailAnalysis],
    ) -> list[EmailAnalysis]:
        """Analyze sender reputation and authenticity."""
        logger.info(
            "phishing_analyzer.analyze_sender",
            count=len(analyses),
        )
        for analysis in analyses:
            indicators: list[str] = list(analysis.indicators)

            # Display name vs domain check
            if analysis.display_name and analysis.sender:
                dn_lower = analysis.display_name.lower()
                for brand, kws in BRAND_KEYWORDS.items():
                    if any(k in dn_lower for k in kws):
                        brand_domain = brand.lower() + ".com"
                        if brand_domain not in analysis.sender_domain:
                            indicators.append(PhishingIndicator.DISPLAY_NAME_SPOOF.value)
                            break

            # Auth failure
            if "fail" in analysis.auth_status.lower():
                indicators.append(PhishingIndicator.SPOOFED_SENDER.value)

            # Reputation score
            rep = 50.0
            if self._reputation:
                try:
                    res = await self._reputation.check(analysis.sender_domain)
                    rep = res.get("score", 50.0)
                except Exception:  # noqa: S110
                    pass
            else:
                base = hash(analysis.sender_domain) % 100
                rep = float(max(10, min(95, base)))

            analysis.sender_reputation = rep
            analysis.indicators = indicators

        return analyses

    async def analyze_urls(
        self,
        analyses: list[EmailAnalysis],
    ) -> tuple[list[URLAnalysis], int]:
        """Extract and analyze URLs from emails."""
        logger.info(
            "phishing_analyzer.analyze_urls",
            count=len(analyses),
        )
        url_results: list[URLAnalysis] = []
        malicious_count = 0

        for analysis in analyses:
            body = analysis.body_preview
            urls = re.findall(r"https?://[^\s'\"<>]+", body)

            for raw_url in urls:
                parsed = urlparse(raw_url)
                domain = parsed.netloc.lower()

                is_shortened = domain in SHORTENER_DOMAINS
                is_malicious = False
                brand = ""
                has_login = False
                age_days = 365

                # Check suspicious TLD
                for tld in SUSPICIOUS_TLDS:
                    if domain.endswith(tld):
                        is_malicious = True
                        break

                # Brand impersonation in URL
                for bname, kws in BRAND_KEYWORDS.items():
                    if any(k in domain for k in kws):
                        real = bname.lower() + ".com"
                        if real not in domain:
                            brand = bname
                            is_malicious = True
                            break

                # Login form detection
                path = parsed.path.lower()
                if any(
                    k in path
                    for k in [
                        "login",
                        "signin",
                        "verify",
                        "account",
                        "auth",
                    ]
                ):
                    has_login = True

                # Young domain simulation
                age_days = hash(domain) % 730
                if age_days < 30:
                    is_malicious = True

                risk = self._url_risk_score(
                    is_shortened,
                    is_malicious,
                    has_login,
                    age_days,
                )

                url_analysis = URLAnalysis(
                    url=raw_url,
                    domain=domain,
                    is_shortened=is_shortened,
                    final_url=raw_url,
                    is_malicious=is_malicious,
                    brand_impersonated=brand,
                    has_login_form=has_login,
                    ssl_valid=parsed.scheme == "https",
                    domain_age_days=age_days,
                    risk_score=risk,
                )
                url_results.append(url_analysis)
                if is_malicious:
                    malicious_count += 1

        return url_results, malicious_count

    async def analyze_content(
        self,
        analyses: list[EmailAnalysis],
    ) -> tuple[list[dict[str, Any]], int]:
        """Analyze email content for phishing patterns."""
        logger.info(
            "phishing_analyzer.analyze_content",
            count=len(analyses),
        )
        results: list[dict[str, Any]] = []
        impersonation_count = 0

        for analysis in analyses:
            text = (f"{analysis.subject} {analysis.body_preview}").lower()

            # Urgency scoring
            urgency_hits = sum(1 for kw in URGENCY_KEYWORDS if kw in text)
            urgency_score = min(urgency_hits / 5.0, 1.0)

            # Brand impersonation
            brand_found = ""
            for brand, kws in BRAND_KEYWORDS.items():
                if any(k in text for k in kws):
                    brand_domain = brand.lower() + ".com"
                    if brand_domain not in analysis.sender_domain:
                        brand_found = brand
                        impersonation_count += 1
                        break

            # Credential harvesting
            cred_harvest = any(
                k in text
                for k in [
                    "password",  # noqa: S105
                    "credential",
                    "verify your account",
                    "update payment",
                    "confirm identity",
                    "ssn",
                    "social security",
                ]
            )

            # Attachment risk
            risky_exts = {
                ".exe",
                ".bat",
                ".ps1",
                ".vbs",
                ".js",
                ".hta",
                ".scr",
                ".pif",
            }
            attach_risk = any(ext in risky_exts for ext in analysis.attachment_types)

            results.append(
                {
                    "email_id": analysis.id,
                    "urgency_score": round(urgency_score, 2),
                    "brand_impersonated": brand_found,
                    "credential_harvesting": cred_harvest,
                    "attachment_risk": attach_risk,
                    "indicators_count": len(analysis.indicators),
                }
            )

        return results, impersonation_count

    async def score_risk(
        self,
        analyses: list[EmailAnalysis],
        url_analyses: list[URLAnalysis],
        content_analyses: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int, float]:
        """Calculate overall phishing risk scores."""
        logger.info(
            "phishing_analyzer.score_risk",
            count=len(analyses),
        )
        scores: list[dict[str, Any]] = []
        high_risk = 0
        total_score = 0.0

        content_map = {c["email_id"]: c for c in content_analyses}
        url_map: dict[str, list[URLAnalysis]] = {}
        for ua in url_analyses:
            # Map URLs back to emails (simplified)
            for analysis in analyses:
                if ua.url in analysis.body_preview:
                    eid = analysis.id
                    url_map.setdefault(eid, []).append(ua)

        for analysis in analyses:
            content = content_map.get(analysis.id, {})
            email_urls = url_map.get(analysis.id, [])

            score = 0.0
            level = RiskLevel.SAFE

            # Sender reputation factor
            if analysis.sender_reputation < 30:
                score += 0.3
            elif analysis.sender_reputation < 60:
                score += 0.15

            # URL risk
            if email_urls:
                max_url = max(u.risk_score for u in email_urls)
                score += max_url * 0.3

            # Content risk
            urgency = content.get("urgency_score", 0)
            score += urgency * 0.15
            if content.get("credential_harvesting"):
                score += 0.2
            if content.get("brand_impersonated"):
                score += 0.15
            if content.get("attachment_risk"):
                score += 0.1

            score = min(score, 1.0)

            if score >= 0.8:
                level = RiskLevel.CRITICAL
            elif score >= 0.6:
                level = RiskLevel.HIGH
            elif score >= 0.4:
                level = RiskLevel.MEDIUM
            elif score >= 0.2:
                level = RiskLevel.LOW
            else:
                level = RiskLevel.SAFE

            if level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                high_risk += 1

            scores.append(
                {
                    "email_id": analysis.id,
                    "sender": analysis.sender,
                    "subject": analysis.subject,
                    "risk_score": round(score, 4),
                    "risk_level": level.value,
                    "scored_at": time.time(),
                }
            )
            total_score += score

        avg = round(total_score / max(len(scores), 1), 4)
        return scores, high_risk, avg

    # ----------------------------------------------------------
    # Private helpers
    # ----------------------------------------------------------

    @staticmethod
    def _extract_domain(email: str) -> str:
        match = re.search(r"@([\w.-]+)", email)
        return match.group(1).lower() if match else ""

    @staticmethod
    def _url_risk_score(
        shortened: bool,
        malicious: bool,
        login_form: bool,
        age_days: int,
    ) -> float:
        score = 0.0
        if malicious:
            score += 0.4
        if shortened:
            score += 0.15
        if login_form:
            score += 0.2
        if age_days < 30:
            score += 0.25
        elif age_days < 90:
            score += 0.1
        return min(score, 1.0)
