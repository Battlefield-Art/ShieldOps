"""SaaS Security Posture Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    ConfigFinding,
    RemediationAction,
    RiskAssessment,
    SaaSApp,
    SaaSRisk,
    SharingExposure,
    SharingScope,
)

logger = structlog.get_logger()

_SAMPLE_APPS: list[dict[str, Any]] = [
    {
        "name": "Slack",
        "vendor": "Salesforce",
        "category": "Communication",
        "users_count": 450,
        "oauth_scopes": ["channels:read", "chat:write", "files:read"],
        "is_sanctioned": True,
        "sso_enabled": True,
        "mfa_enforced": True,
    },
    {
        "name": "Notion",
        "vendor": "Notion Labs",
        "category": "Productivity",
        "users_count": 320,
        "oauth_scopes": ["read_content", "update_content"],
        "is_sanctioned": True,
        "sso_enabled": True,
        "mfa_enforced": False,
    },
    {
        "name": "Dropbox",
        "vendor": "Dropbox Inc",
        "category": "Storage",
        "users_count": 180,
        "oauth_scopes": [
            "files.content.write",
            "files.content.read",
            "sharing.write",
        ],
        "is_sanctioned": True,
        "sso_enabled": False,
        "mfa_enforced": False,
    },
    {
        "name": "Trello",
        "vendor": "Atlassian",
        "category": "Project Management",
        "users_count": 90,
        "oauth_scopes": ["read", "write", "account"],
        "is_sanctioned": False,
        "sso_enabled": False,
        "mfa_enforced": False,
    },
    {
        "name": "GitHub",
        "vendor": "Microsoft",
        "category": "Development",
        "users_count": 200,
        "oauth_scopes": ["repo", "admin:org", "write:packages"],
        "is_sanctioned": True,
        "sso_enabled": True,
        "mfa_enforced": True,
    },
    {
        "name": "Figma",
        "vendor": "Figma Inc",
        "category": "Design",
        "users_count": 60,
        "oauth_scopes": ["file_read", "file_write"],
        "is_sanctioned": True,
        "sso_enabled": False,
        "mfa_enforced": False,
    },
]

_CONFIG_CHECKS: list[dict[str, Any]] = [
    {
        "check": "MFA Enforcement",
        "severity": "critical",
        "expected": "enabled",
    },
    {
        "check": "SSO Integration",
        "severity": "high",
        "expected": "enabled",
    },
    {
        "check": "Admin Session Timeout",
        "severity": "medium",
        "expected": "<=30min",
    },
    {
        "check": "External Sharing Default",
        "severity": "high",
        "expected": "disabled",
    },
    {
        "check": "Audit Logging",
        "severity": "medium",
        "expected": "enabled",
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class SaaSSecurityPostureToolkit:
    """Tools for SaaS security posture management."""

    def __init__(
        self,
        saas_api: Any | None = None,
        identity_provider: Any | None = None,
    ) -> None:
        self._saas_api = saas_api
        self._identity_provider = identity_provider

    async def discover_apps(
        self,
        tenant_id: str,
    ) -> list[SaaSApp]:
        """Discover SaaS applications in use."""
        logger.info(
            "ssp.discover_apps",
            tenant_id=tenant_id,
        )

        if self._saas_api is not None:
            try:
                raw = await self._saas_api.list_apps(
                    tenant_id=tenant_id,
                )
                return [SaaSApp(**r) for r in raw]
            except Exception:
                logger.exception("ssp.discover_apps.error")

        apps: list[SaaSApp] = []
        for i, a in enumerate(_SAMPLE_APPS):
            apps.append(
                SaaSApp(
                    id=_gen_id("SA", tenant_id, i),
                    name=a["name"],
                    vendor=a["vendor"],
                    category=a["category"],
                    users_count=a["users_count"],
                    oauth_scopes=a["oauth_scopes"],
                    is_sanctioned=a["is_sanctioned"],
                    sso_enabled=a["sso_enabled"],
                    mfa_enforced=a["mfa_enforced"],
                )
            )
        return apps

    async def audit_config(
        self,
        apps: list[SaaSApp],
    ) -> list[ConfigFinding]:
        """Audit SaaS app configurations for misconfigurations."""
        logger.info(
            "ssp.audit_config",
            count=len(apps),
        )

        findings: list[ConfigFinding] = []
        idx = 0
        for app in apps:
            if not app.mfa_enforced:
                findings.append(
                    ConfigFinding(
                        id=_gen_id("CF", app.name, idx),
                        app_name=app.name,
                        check_name="MFA Enforcement",
                        severity=SaaSRisk.CRITICAL,
                        description=(f"{app.name} does not enforce MFA"),
                        current_value="disabled",
                        expected_value="enabled",
                        remediation=(f"Enable MFA for all {app.name} users"),
                    )
                )
                idx += 1
            if not app.sso_enabled:
                findings.append(
                    ConfigFinding(
                        id=_gen_id("CF", app.name, idx),
                        app_name=app.name,
                        check_name="SSO Integration",
                        severity=SaaSRisk.HIGH,
                        description=(f"{app.name} not integrated with SSO"),
                        current_value="disabled",
                        expected_value="enabled",
                        remediation=(f"Configure SAML/OIDC SSO for {app.name}"),
                    )
                )
                idx += 1
            if len(app.oauth_scopes) > 2:
                findings.append(
                    ConfigFinding(
                        id=_gen_id("CF", app.name, idx),
                        app_name=app.name,
                        check_name="Excessive OAuth Scopes",
                        severity=SaaSRisk.MEDIUM,
                        description=(f"{app.name} has {len(app.oauth_scopes)} OAuth scopes"),
                        current_value=str(len(app.oauth_scopes)),
                        expected_value="<=2",
                        remediation=("Review and reduce OAuth permissions"),
                    )
                )
                idx += 1
        return findings

    async def check_sharing(
        self,
        apps: list[SaaSApp],
    ) -> list[SharingExposure]:
        """Check data sharing settings across SaaS apps."""
        logger.info(
            "ssp.check_sharing",
            count=len(apps),
        )

        exposures: list[SharingExposure] = []
        idx = 0
        for app in apps:
            scope_val = random.randint(0, 4)  # noqa: S311
            scope = list(SharingScope)[scope_val]
            if scope in (SharingScope.PUBLIC, SharingScope.EXTERNAL):
                exposures.append(
                    SharingExposure(
                        id=_gen_id("SE", app.name, idx),
                        app_name=app.name,
                        resource=f"{app.name}/shared-workspace",
                        scope=scope,
                        shared_with=(
                            "anyone" if scope == SharingScope.PUBLIC else "external@partner.com"
                        ),
                        owner="admin@corp.com",
                        sensitive_data=(
                            random.random() > 0.5  # noqa: S311
                        ),
                        last_accessed="2026-03-29T14:00:00Z",
                    )
                )
                idx += 1
        return exposures

    async def assess_risk(
        self,
        apps: list[SaaSApp],
        findings: list[ConfigFinding],
        exposures: list[SharingExposure],
    ) -> list[RiskAssessment]:
        """Assess overall risk for each SaaS app."""
        logger.info(
            "ssp.assess_risk",
            apps=len(apps),
            findings=len(findings),
            exposures=len(exposures),
        )

        assessments: list[RiskAssessment] = []
        for i, app in enumerate(apps):
            app_findings = [f for f in findings if f.app_name == app.name]
            app_exposures = [e for e in exposures if e.app_name == app.name]

            score = 0.0
            for f in app_findings:
                if f.severity == SaaSRisk.CRITICAL:
                    score += 30.0
                elif f.severity == SaaSRisk.HIGH:
                    score += 20.0
                elif f.severity == SaaSRisk.MEDIUM:
                    score += 10.0
            score += len(app_exposures) * 15.0
            if not app.is_sanctioned:
                score += 25.0
            score = min(score, 100.0)

            risk = SaaSRisk.LOW
            if score >= 60:
                risk = SaaSRisk.CRITICAL
            elif score >= 40:
                risk = SaaSRisk.HIGH
            elif score >= 20:
                risk = SaaSRisk.MEDIUM

            gaps: list[str] = []
            if not app.mfa_enforced:
                gaps.append("MFA not enforced")
            if not app.sso_enabled:
                gaps.append("No SSO integration")

            assessments.append(
                RiskAssessment(
                    id=_gen_id("RA", app.name, i),
                    app_name=app.name,
                    overall_risk=risk,
                    risk_score=round(score, 1),
                    misconfig_count=len(app_findings),
                    sharing_exposures=len(app_exposures),
                    compliance_gaps=gaps,
                )
            )
        return assessments

    async def remediate_misconfig(
        self,
        findings: list[ConfigFinding],
    ) -> list[RemediationAction]:
        """Remediate SaaS misconfigurations."""
        logger.info(
            "ssp.remediate_misconfig",
            count=len(findings),
        )

        actions: list[RemediationAction] = []
        for i, f in enumerate(findings):
            if f.severity in (SaaSRisk.CRITICAL, SaaSRisk.HIGH):
                actions.append(
                    RemediationAction(
                        id=_gen_id("RM", f.app_name, i),
                        app_name=f.app_name,
                        finding_id=f.id,
                        action=f.remediation,
                        status="applied",
                        automated=f.severity == SaaSRisk.CRITICAL,
                        rollback_available=True,
                    )
                )
            else:
                actions.append(
                    RemediationAction(
                        id=_gen_id("RM", f.app_name, i),
                        app_name=f.app_name,
                        finding_id=f.id,
                        action=f.remediation,
                        status="pending_approval",
                        automated=False,
                        rollback_available=True,
                    )
                )
        return actions

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Record a SaaS posture metric."""
        logger.info(
            "ssp.record_metric",
            metric=metric_name,
            value=value,
            tenant_id=tenant_id,
        )
        return {
            "metric": metric_name,
            "value": value,
            "tenant_id": tenant_id,
            "recorded": True,
        }
