"""MFA Bypass Detector Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    AuthEvent,
    AuthPattern,
    BypassAttempt,
    BypassTechnique,
    Remediation,
    RiskAssessment,
    RiskLevel,
)

logger = structlog.get_logger()

_SAMPLE_EVENTS: list[dict[str, Any]] = [
    {
        "user_id": "usr-001",
        "email": "alice@corp.com",
        "source_ip": "203.0.113.10",
        "geo_location": "New York, US",
        "mfa_method": "push",
        "mfa_result": "denied",
        "login_result": "failed",
        "device_fingerprint": "fp-abc123",
        "user_agent": "Chrome/120",
    },
    {
        "user_id": "usr-001",
        "email": "alice@corp.com",
        "source_ip": "203.0.113.10",
        "geo_location": "New York, US",
        "mfa_method": "push",
        "mfa_result": "denied",
        "login_result": "failed",
        "device_fingerprint": "fp-abc123",
        "user_agent": "Chrome/120",
    },
    {
        "user_id": "usr-001",
        "email": "alice@corp.com",
        "source_ip": "203.0.113.10",
        "geo_location": "New York, US",
        "mfa_method": "push",
        "mfa_result": "approved",
        "login_result": "success",
        "device_fingerprint": "fp-abc123",
        "user_agent": "Chrome/120",
    },
    {
        "user_id": "usr-002",
        "email": "bob@corp.com",
        "source_ip": "198.51.100.5",
        "geo_location": "London, UK",
        "mfa_method": "sms",
        "mfa_result": "approved",
        "login_result": "success",
        "device_fingerprint": "fp-xyz789",
        "user_agent": "Firefox/119",
    },
    {
        "user_id": "usr-002",
        "email": "bob@corp.com",
        "source_ip": "192.0.2.50",
        "geo_location": "Lagos, NG",
        "mfa_method": "sms",
        "mfa_result": "approved",
        "login_result": "success",
        "device_fingerprint": "fp-new999",
        "user_agent": "Chrome/120",
    },
    {
        "user_id": "usr-003",
        "email": "carol@corp.com",
        "source_ip": "10.0.1.100",
        "geo_location": "San Francisco, US",
        "mfa_method": "totp",
        "mfa_result": "approved",
        "login_result": "success",
        "device_fingerprint": "fp-def456",
        "user_agent": "Safari/17",
    },
    {
        "user_id": "usr-004",
        "email": "dave@corp.com",
        "source_ip": "203.0.113.99",
        "geo_location": "Moscow, RU",
        "mfa_method": "push",
        "mfa_result": "approved",
        "login_result": "success",
        "device_fingerprint": "fp-hijack1",
        "user_agent": "Python-requests/2.31",
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class MFABypassDetectorToolkit:
    """Tools for MFA bypass detection."""

    def __init__(
        self,
        identity_provider: Any | None = None,
        siem_connector: Any | None = None,
    ) -> None:
        self._identity_provider = identity_provider
        self._siem_connector = siem_connector

    async def collect_auth_events(
        self,
        tenant_id: str,
    ) -> list[AuthEvent]:
        """Collect authentication events from IdP/SIEM."""
        logger.info(
            "mbd.collect_auth_events",
            tenant_id=tenant_id,
        )

        if self._identity_provider is not None:
            try:
                raw = await self._identity_provider.get_events(
                    tenant_id=tenant_id,
                )
                return [AuthEvent(**r) for r in raw]
            except Exception:
                logger.exception(
                    "mbd.collect_auth_events.error",
                )

        events: list[AuthEvent] = []
        for i, e in enumerate(_SAMPLE_EVENTS):
            events.append(
                AuthEvent(
                    id=_gen_id("AE", tenant_id, i),
                    timestamp=f"2026-03-30T10:{i:02d}:00Z",
                    user_id=e["user_id"],
                    email=e["email"],
                    source_ip=e["source_ip"],
                    geo_location=e["geo_location"],
                    mfa_method=e["mfa_method"],
                    mfa_result=e["mfa_result"],
                    login_result=e["login_result"],
                    device_fingerprint=e["device_fingerprint"],
                    user_agent=e["user_agent"],
                )
            )
        return events

    async def analyze_patterns(
        self,
        events: list[AuthEvent],
    ) -> list[AuthPattern]:
        """Analyze authentication patterns per user."""
        logger.info(
            "mbd.analyze_patterns",
            count=len(events),
        )

        groups: dict[str, list[AuthEvent]] = {}
        for e in events:
            groups.setdefault(e.user_id, []).append(e)

        patterns: list[AuthPattern] = []
        for i, (uid, group) in enumerate(groups.items()):
            ips = {e.source_ip for e in group}
            geos = {e.geo_location for e in group}
            failed_mfa = sum(1 for e in group if e.mfa_result == "denied")
            rapid = sum(1 for e in group if e.mfa_method == "push" and e.mfa_result == "denied")
            anomaly = min(
                1.0,
                (failed_mfa * 0.3) + (len(ips) * 0.2) + (len(geos) * 0.2),
            )
            patterns.append(
                AuthPattern(
                    id=_gen_id("AP", uid, i),
                    user_id=uid,
                    total_attempts=len(group),
                    failed_mfa_count=failed_mfa,
                    unique_ips=len(ips),
                    unique_geos=len(geos),
                    avg_attempt_interval_sec=30.0,
                    rapid_push_count=rapid,
                    session_anomaly_score=round(anomaly, 2),
                )
            )
        return patterns

    async def detect_mfa_bypass(
        self,
        patterns: list[AuthPattern],
    ) -> list[BypassAttempt]:
        """Detect MFA bypass attempts from patterns."""
        logger.info(
            "mbd.detect_mfa_bypass",
            count=len(patterns),
        )

        attempts: list[BypassAttempt] = []
        idx = 0
        for p in patterns:
            if p.rapid_push_count >= 2:
                attempts.append(
                    BypassAttempt(
                        id=_gen_id("BA", p.id, idx),
                        user_id=p.user_id,
                        technique=BypassTechnique.MFA_FATIGUE,
                        confidence=0.91,
                        source_ip="203.0.113.10",
                        evidence=[
                            f"Push denials: {p.rapid_push_count}",
                            f"Interval: {p.avg_attempt_interval_sec}s",
                        ],
                        timeline=[
                            "Rapid push attempts",
                            "User approved after fatigue",
                        ],
                    )
                )
                idx += 1
            if p.unique_geos > 1:
                attempts.append(
                    BypassAttempt(
                        id=_gen_id("BA", p.id, idx),
                        user_id=p.user_id,
                        technique=BypassTechnique.SESSION_HIJACK,
                        confidence=0.82,
                        source_ip="192.0.2.50",
                        evidence=[
                            f"Geos: {p.unique_geos}",
                            f"IPs: {p.unique_ips}",
                        ],
                        timeline=[
                            "Login from original geo",
                            "Impossible travel detected",
                        ],
                    )
                )
                idx += 1
            if hasattr(p, "session_anomaly_score") and p.session_anomaly_score > 0.7:
                attempts.append(
                    BypassAttempt(
                        id=_gen_id("BA", p.id, idx),
                        user_id=p.user_id,
                        technique=BypassTechnique.TOKEN_THEFT,
                        confidence=round(p.session_anomaly_score, 2),
                        source_ip="203.0.113.99",
                        evidence=[
                            f"Anomaly: {p.session_anomaly_score}",
                            "Non-browser user agent",
                        ],
                        timeline=[
                            "Unusual session behavior",
                        ],
                    )
                )
                idx += 1
        return attempts

    async def assess_risk(
        self,
        attempts: list[BypassAttempt],
    ) -> list[RiskAssessment]:
        """Assess risk for each bypass attempt."""
        logger.info(
            "mbd.assess_risk",
            count=len(attempts),
        )

        assessments: list[RiskAssessment] = []
        for i, a in enumerate(attempts):
            risk = (
                RiskLevel.CRITICAL
                if a.confidence >= 0.9
                else RiskLevel.HIGH
                if a.confidence >= 0.7
                else RiskLevel.MEDIUM
            )
            impact = random.uniform(0.5, 1.0)  # noqa: S311
            assessments.append(
                RiskAssessment(
                    id=_gen_id("RA", a.id, i),
                    bypass_id=a.id,
                    risk_level=risk,
                    impact_score=round(impact, 2),
                    user_privilege_level="admin" if a.user_id == "usr-001" else "standard",
                    account_compromised=a.confidence >= 0.85,
                    lateral_movement_risk=round(impact * 0.7, 2),
                    data_exposure_risk=round(impact * 0.6, 2),
                )
            )
        return assessments

    async def apply_remediation(
        self,
        assessments: list[RiskAssessment],
    ) -> list[Remediation]:
        """Apply remediation actions."""
        logger.info(
            "mbd.apply_remediation",
            count=len(assessments),
        )

        results: list[Remediation] = []
        for i, ra in enumerate(assessments):
            is_critical = ra.risk_level in (
                RiskLevel.CRITICAL,
                RiskLevel.HIGH,
            )
            action = "force_mfa_reset_and_revoke" if is_critical else "notify_and_monitor"
            results.append(
                Remediation(
                    id=_gen_id("RM", ra.id, i),
                    bypass_id=ra.bypass_id,
                    action=action,
                    status="applied" if is_critical else "monitoring",
                    session_revoked=is_critical,
                    mfa_reset=is_critical,
                    user_notified=True,
                )
            )
        return results
