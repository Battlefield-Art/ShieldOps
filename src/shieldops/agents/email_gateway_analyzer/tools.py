"""Email Gateway Analyzer Agent — Tool functions."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

import structlog

from .models import (
    AuthProtocol,
    EmailHeader,
    SPFResult,
    ThreatLevel,
)

logger = structlog.get_logger()

# Common SPF mechanisms
SPF_PASS_MECHANISMS = {"pass", "+all", "include", "a", "mx", "ip4", "ip6"}
SPF_FAIL_MECHANISMS = {"-all", "~all", "?all"}

# Known suspicious header patterns
SUSPICIOUS_X_HEADERS = [
    "X-Spam-Flag: YES",
    "X-Virus-Scanned",
    "X-Originating-IP",
    "X-PHP-Script",
    "X-Mailer: PHPMailer",
]

# Lookalike domain patterns (homograph)
LOOKALIKE_CHARS: dict[str, str] = {
    "0": "o",
    "1": "l",
    "rn": "m",
    "vv": "w",
    "cl": "d",
}


def _generate_id() -> str:
    return str(uuid.uuid4())[:12]


class EmailGatewayAnalyzerToolkit:
    """Tools for email gateway security analysis."""

    def __init__(
        self,
        dns_client: Any | None = None,
        reputation_client: Any | None = None,
    ) -> None:
        self._dns = dns_client
        self._reputation = reputation_client

    async def collect_dns_records(
        self,
        tenant_id: str,
        domains: list[str],
    ) -> list[dict[str, Any]]:
        """Collect SPF/DKIM/DMARC DNS records."""
        logger.info(
            "email_gateway.collect_dns_records",
            tenant_id=tenant_id,
            domain_count=len(domains),
        )
        records: list[dict[str, Any]] = []

        for domain in domains:
            record: dict[str, Any] = {
                "id": _generate_id(),
                "domain": domain,
                "collected_at": time.time(),
                "spf": None,
                "dkim": None,
                "dmarc": None,
                "mta_sts": None,
            }

            if self._dns:
                try:
                    txt = await self._dns.query(domain, "TXT")
                    record["raw_txt"] = txt
                except Exception:
                    logger.debug("email_gateway.dns_fallback")

            # Simulated DNS records
            record["spf"] = f"v=spf1 include:_spf.{domain} include:sendgrid.net ~all"
            record["dkim"] = {
                "selector": "default",
                "key_length": 2048 if hash(domain) % 3 != 0 else 1024,
                "algorithm": "rsa-sha256",
                "valid": hash(domain) % 4 != 0,
            }
            record["dmarc"] = (
                f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}; "
                f"ruf=mailto:forensics@{domain}; pct=100"
                if hash(domain) % 3 == 0
                else f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}"
            )
            record["mta_sts"] = hash(domain) % 2 == 0
            records.append(record)

        return records

    async def validate_auth_protocols(
        self,
        dns_records: list[dict[str, Any]],
    ) -> tuple[list[SPFResult], float]:
        """Validate SPF/DKIM/DMARC configurations."""
        logger.info(
            "email_gateway.validate_auth",
            record_count=len(dns_records),
        )
        results: list[SPFResult] = []
        valid_count = 0

        for rec in dns_records:
            domain = rec.get("domain", "")

            # SPF validation
            spf_val = rec.get("spf", "")
            spf_issues: list[str] = []
            spf_valid = True
            if not spf_val:
                spf_issues.append("No SPF record found")
                spf_valid = False
            elif "+all" in spf_val:
                spf_issues.append("Permissive +all allows any sender")
                spf_valid = False
            elif "~all" in spf_val:
                spf_issues.append("Soft-fail ~all; recommend -all")
            include_count = spf_val.count("include:")
            if include_count > 10:
                spf_issues.append(f"Too many includes ({include_count}); exceeds DNS lookup limit")
                spf_valid = False

            results.append(
                SPFResult(
                    domain=domain,
                    protocol=AuthProtocol.SPF,
                    result="pass" if spf_valid else "fail",
                    policy=spf_val,
                    record_value=spf_val,
                    is_valid=spf_valid,
                    issues=spf_issues,
                )
            )
            if spf_valid:
                valid_count += 1

            # DKIM validation
            dkim = rec.get("dkim", {})
            dkim_issues: list[str] = []
            dkim_valid = dkim.get("valid", False)
            key_len = dkim.get("key_length", 0)
            if key_len < 2048:
                dkim_issues.append(f"Key length {key_len} < 2048; upgrade recommended")
            if not dkim_valid:
                dkim_issues.append("DKIM signature invalid")

            results.append(
                SPFResult(
                    domain=domain,
                    protocol=AuthProtocol.DKIM,
                    result="pass" if dkim_valid else "fail",
                    alignment=dkim.get("algorithm", ""),
                    is_valid=dkim_valid,
                    issues=dkim_issues,
                )
            )
            if dkim_valid:
                valid_count += 1

            # DMARC validation
            dmarc_val = rec.get("dmarc", "")
            dmarc_issues: list[str] = []
            dmarc_valid = True
            if not dmarc_val:
                dmarc_issues.append("No DMARC record found")
                dmarc_valid = False
            elif "p=none" in dmarc_val:
                dmarc_issues.append("Policy is 'none'; recommend quarantine or reject")
            if "rua=" not in dmarc_val:
                dmarc_issues.append("No aggregate reporting (rua) configured")

            results.append(
                SPFResult(
                    domain=domain,
                    protocol=AuthProtocol.DMARC,
                    result="pass" if dmarc_valid else "fail",
                    policy=dmarc_val,
                    record_value=dmarc_val,
                    is_valid=dmarc_valid,
                    issues=dmarc_issues,
                )
            )
            if dmarc_valid:
                valid_count += 1

        total = max(len(results), 1)
        pass_rate = round(valid_count / total, 4)
        return results, pass_rate

    async def analyze_headers(
        self,
        tenant_id: str,
        messages: list[dict[str, Any]] | None = None,
    ) -> tuple[list[EmailHeader], int]:
        """Analyze email headers for anomalies."""
        logger.info(
            "email_gateway.analyze_headers",
            tenant_id=tenant_id,
        )
        messages = messages or self._sample_messages()
        headers: list[EmailHeader] = []
        suspicious_count = 0

        for msg in messages:
            raw_headers = msg.get("headers", "")
            is_suspicious = False

            # Check for suspicious patterns
            for pattern in SUSPICIOUS_X_HEADERS:
                if pattern.lower() in raw_headers.lower():
                    is_suspicious = True
                    break

            # Check sender/return-path mismatch
            sender = msg.get("from", "")
            return_path = msg.get("return_path", "")
            if sender and return_path:
                sender_domain = self._extract_domain(sender)
                rp_domain = self._extract_domain(return_path)
                if sender_domain and rp_domain and sender_domain != rp_domain:
                    is_suspicious = True

            header = EmailHeader(
                message_id=msg.get("message_id", _generate_id()),
                sender=sender,
                return_path=return_path,
                received_chain=msg.get("received", []),
                subject=msg.get("subject", ""),
                date=msg.get("date", ""),
                authentication_results=msg.get("authentication_results", ""),
                x_mailer=msg.get("x_mailer", ""),
                content_type=msg.get("content_type", ""),
                has_suspicious_headers=is_suspicious,
            )
            headers.append(header)
            if is_suspicious:
                suspicious_count += 1

        return headers, suspicious_count

    async def check_reputation(
        self,
        domains: list[str],
    ) -> tuple[list[dict[str, Any]], float]:
        """Check sender domain reputation."""
        logger.info(
            "email_gateway.check_reputation",
            domain_count=len(domains),
        )
        scores: list[dict[str, Any]] = []
        total_score = 0.0

        for domain in domains:
            score = 0.0
            if self._reputation:
                try:
                    rep = await self._reputation.check(domain)
                    score = rep.get("score", 0.0)
                except Exception:
                    logger.debug("email_gateway.reputation_fallback")

            # Simulated reputation
            if not score:
                base = hash(domain) % 100
                score = round(max(20.0, min(99.0, base * 1.0)), 1)

            scores.append(
                {
                    "domain": domain,
                    "score": score,
                    "category": self._score_category(score),
                    "blacklisted": score < 30,
                    "checked_at": time.time(),
                }
            )
            total_score += score

        avg = round(total_score / max(len(domains), 1), 2)
        return scores, avg

    async def detect_spoofing(
        self,
        headers: list[EmailHeader],
        auth_results: list[SPFResult],
    ) -> list[dict[str, Any]]:
        """Detect spoofing and impersonation attempts."""
        logger.info(
            "email_gateway.detect_spoofing",
            header_count=len(headers),
        )
        spoofing: list[dict[str, Any]] = []
        failed_domains = {r.domain for r in auth_results if not r.is_valid}

        for header in headers:
            indicators: list[str] = []
            threat = ThreatLevel.NONE

            # Auth failure check
            sender_domain = self._extract_domain(header.sender)
            if sender_domain in failed_domains:
                indicators.append("auth_failure")
                threat = ThreatLevel.HIGH

            # Envelope mismatch
            rp_domain = self._extract_domain(header.return_path)
            if sender_domain and rp_domain and sender_domain != rp_domain:
                indicators.append("envelope_mismatch")
                if threat == ThreatLevel.NONE:
                    threat = ThreatLevel.MEDIUM

            # Lookalike domain
            if sender_domain:
                for legit in ["google.com", "microsoft.com"]:
                    if self._is_lookalike(sender_domain, legit):
                        indicators.append(f"lookalike:{legit}")
                        threat = ThreatLevel.CRITICAL

            # Suspicious headers
            if header.has_suspicious_headers:
                indicators.append("suspicious_headers")
                if threat == ThreatLevel.NONE:
                    threat = ThreatLevel.LOW

            if indicators:
                spoofing.append(
                    {
                        "message_id": header.message_id,
                        "sender": header.sender,
                        "threat_level": threat.value,
                        "indicators": indicators,
                        "detected_at": time.time(),
                    }
                )

        return spoofing

    # ----------------------------------------------------------
    # Private helpers
    # ----------------------------------------------------------

    @staticmethod
    def _extract_domain(email: str) -> str:
        """Extract domain from email address."""
        match = re.search(r"@([\w.-]+)", email)
        return match.group(1).lower() if match else ""

    @staticmethod
    def _score_category(score: float) -> str:
        if score >= 80:
            return "good"
        if score >= 60:
            return "neutral"
        if score >= 40:
            return "poor"
        return "bad"

    @staticmethod
    def _is_lookalike(candidate: str, legitimate: str) -> bool:
        """Check for homograph / lookalike domains."""
        if candidate == legitimate:
            return False
        c_lower = candidate.lower().replace("-", "")
        leg_lower = legitimate.lower().replace("-", "")
        # Simple edit-distance check
        if len(c_lower) != len(leg_lower):
            return False
        diffs = sum(1 for a, b in zip(c_lower, leg_lower, strict=False) if a != b)
        return diffs == 1

    @staticmethod
    def _sample_messages() -> list[dict[str, Any]]:
        """Return sample messages for analysis."""
        return [
            {
                "message_id": "msg-001",
                "from": "admin@company.com",
                "return_path": "admin@company.com",
                "subject": "Q3 Report",
                "headers": "X-Mailer: Outlook",
                "received": ["relay1.company.com"],
                "date": "2026-03-28",
                "authentication_results": "spf=pass",
            },
            {
                "message_id": "msg-002",
                "from": "ceo@company.com",
                "return_path": "bounce@evil.com",
                "subject": "Urgent Wire Transfer",
                "headers": "X-PHP-Script: send.php",
                "received": ["mail.evil.com"],
                "date": "2026-03-28",
                "authentication_results": "spf=fail",
            },
            {
                "message_id": "msg-003",
                "from": "hr@company.com",
                "return_path": "hr@company.com",
                "subject": "Benefits Enrollment",
                "headers": "X-Mailer: Gmail",
                "received": ["smtp.google.com"],
                "date": "2026-03-28",
                "authentication_results": "spf=pass dkim=pass",
            },
        ]
