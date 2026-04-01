"""Tool functions for the Credential Hygiene Auditor.

Bridges credential inventory, hygiene assessment, violation
detection, risk scoring, and remediation recommendation to
the LangGraph nodes.
"""

from __future__ import annotations

import random  # noqa: S311
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.credential_hygiene_auditor.models import (
    CredentialRecord,
    CredentialRiskScore,
    CredentialType,
    HygieneAssessment,
    HygieneStatus,
    HygieneViolation,
    RemediationRecommendation,
)

logger = structlog.get_logger()


class CredentialHygieneAuditorToolkit:
    """Tools for the credential hygiene auditor agent."""

    def __init__(
        self,
        credential_store: Any | None = None,
        policy_engine: Any | None = None,
        secret_scanner: Any | None = None,
        risk_calculator: Any | None = None,
        remediation_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._credential_store = credential_store
        self._policy_engine = policy_engine
        self._secret_scanner = secret_scanner
        self._risk_calculator = risk_calculator
        self._remediation_engine = remediation_engine
        self._repository = repository
        self._metrics: list[dict[str, Any]] = []

    # ---- Credential Inventory ----

    async def inventory_credentials(
        self,
        tenant_id: str = "",
        scope: str | None = None,
    ) -> list[CredentialRecord]:
        """Inventory all credentials in the organization."""
        records: list[CredentialRecord] = []
        now = datetime.now(UTC)

        if self._credential_store is not None:
            try:
                raw = await self._credential_store.list(
                    tenant_id=tenant_id,
                    scope=scope,
                )
                for item in raw:
                    records.append(
                        CredentialRecord(
                            record_id=item.get("id", f"cred-{uuid4().hex[:8]}"),
                            credential_type=CredentialType(item.get("type", "password")),
                            owner=item.get("owner", ""),
                            system=item.get("system", ""),
                            created_at=item.get("created_at", now),
                            last_rotated=item.get("last_rotated"),
                            age_days=item.get("age_days", 0),
                        )
                    )
            except Exception as e:
                logger.error(
                    "cha_inventory_failed",
                    error=str(e),
                )
        else:
            # Mock credential inventory
            cred_types = list(CredentialType)
            systems = [
                "prod-api",
                "staging-db",
                "ci-pipeline",
                "vault-cluster",
                "k8s-master",
                "monitoring-svc",
                "auth-service",
                "data-lake",
            ]
            owners = [
                "platform-team",
                "dev-ops",
                "security-team",
                "data-eng",
                "sre-team",
                "app-team",
            ]
            count = random.randint(15, 40)  # noqa: S311
            for _i in range(count):
                age = random.randint(1, 365)  # noqa: S311
                created = now - timedelta(days=age)
                rotated_ago = random.randint(0, age)  # noqa: S311
                last_rotated = now - timedelta(
                    days=rotated_ago,
                )
                records.append(
                    CredentialRecord(
                        record_id=f"cred-{uuid4().hex[:8]}",
                        credential_type=random.choice(  # noqa: S311
                            cred_types
                        ),
                        owner=random.choice(owners),  # noqa: S311
                        system=random.choice(systems),  # noqa: S311
                        created_at=created,
                        last_rotated=last_rotated,
                        age_days=age,
                        rotation_policy_days=random.choice(  # noqa: S311
                            [30, 60, 90, 180, 365]
                        ),
                        is_shared=random.random() < 0.2,  # noqa: S311
                        scope=random.choice(  # noqa: S311
                            [
                                "production",
                                "staging",
                                "development",
                            ]
                        ),
                    )
                )

        logger.info(
            "cha_credentials_inventoried",
            tenant_id=tenant_id,
            count=len(records),
        )
        return records

    # ---- Hygiene Assessment ----

    async def assess_hygiene(
        self,
        credentials: list[CredentialRecord],
    ) -> list[HygieneAssessment]:
        """Assess hygiene status for each credential."""
        assessments: list[HygieneAssessment] = []

        for cred in credentials:
            issues: list[str] = []
            status = HygieneStatus.COMPLIANT
            rotation_overdue = False

            if cred.age_days > cred.rotation_policy_days:
                rotation_overdue = True
                issues.append(f"Age {cred.age_days}d exceeds policy {cred.rotation_policy_days}d")
                status = HygieneStatus.NON_COMPLIANT

            if cred.is_shared:
                issues.append("Credential is shared")
                if status == HygieneStatus.COMPLIANT:
                    status = HygieneStatus.WARNING

            if cred.age_days > 365:
                status = HygieneStatus.EXPIRED
                issues.append("Credential older than 1 year")

            mfa = random.random() > 0.3  # noqa: S311
            if not mfa:
                issues.append("MFA not enabled")

            complexity = random.random() > 0.2  # noqa: S311

            assessments.append(
                HygieneAssessment(
                    assessment_id=f"asm-{uuid4().hex[:8]}",
                    record_id=cred.record_id,
                    credential_type=cred.credential_type,
                    status=status,
                    age_days=cred.age_days,
                    rotation_overdue=rotation_overdue,
                    complexity_adequate=complexity,
                    mfa_enabled=mfa,
                    issues=issues,
                )
            )

        logger.info(
            "cha_hygiene_assessed",
            credentials=len(credentials),
            assessments=len(assessments),
        )
        return assessments

    # ---- Violation Detection ----

    async def detect_violations(
        self,
        assessments: list[HygieneAssessment],
    ) -> list[HygieneViolation]:
        """Detect hygiene violations from assessments."""
        violations: list[HygieneViolation] = []
        severities = ["critical", "high", "medium", "low"]

        for assessment in assessments:
            if assessment.status in (HygieneStatus.COMPLIANT,):
                continue

            for issue in assessment.issues:
                if "expired" in issue.lower():
                    severity = "critical"
                elif "rotation" in issue.lower():
                    severity = "high"
                elif "shared" in issue.lower():
                    severity = "medium"
                elif "mfa" in issue.lower():
                    severity = "high"
                else:
                    severity = random.choice(severities)  # noqa: S311

                violations.append(
                    HygieneViolation(
                        violation_id=(f"viol-{uuid4().hex[:8]}"),
                        record_id=assessment.record_id,
                        violation_type=issue.split()[0].lower(),
                        severity=severity,
                        description=issue,
                        policy_reference="SEC-CRED-001",
                        remediation_hint=(f"Address: {issue}"),
                    )
                )

        logger.info(
            "cha_violations_detected",
            assessments=len(assessments),
            violations=len(violations),
        )
        return violations

    # ---- Risk Scoring ----

    async def score_risk(
        self,
        violations: list[HygieneViolation],
    ) -> list[CredentialRiskScore]:
        """Score risk based on violations."""
        scores: list[CredentialRiskScore] = []

        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
        }

        # Group by record
        by_record: dict[str, list[HygieneViolation]] = {}
        for v in violations:
            by_record.setdefault(v.record_id, []).append(v)

        for record_id, record_violations in by_record.items():
            weighted = sum(severity_weights.get(v.severity, 0.3) for v in record_violations)
            overall = min(
                round(
                    weighted / max(len(record_violations), 1),
                    3,
                ),
                1.0,
            )
            highest = max(
                record_violations,
                key=lambda v: severity_weights.get(v.severity, 0),
            )

            if overall > 0.7:
                blast = "high"
            elif overall > 0.4:
                blast = "medium"
            else:
                blast = "low"

            scores.append(
                CredentialRiskScore(
                    score_id=f"rsk-{uuid4().hex[:8]}",
                    scope=record_id,
                    overall_score=overall,
                    violation_count=len(record_violations),
                    highest_severity=highest.severity,
                    contributing_factors=[v.violation_type for v in record_violations],
                    blast_radius=blast,
                )
            )

        logger.info(
            "cha_risk_scored",
            records=len(by_record),
            scores=len(scores),
        )
        return scores

    # ---- Remediation Recommendations ----

    async def recommend_fixes(
        self,
        violations: list[HygieneViolation],
        risk_scores: list[CredentialRiskScore],
    ) -> list[RemediationRecommendation]:
        """Generate remediation recommendations."""
        recommendations: list[RemediationRecommendation] = []

        score_map: dict[str, CredentialRiskScore] = {s.scope: s for s in risk_scores}

        for violation in violations:
            score = score_map.get(violation.record_id)
            if score and score.overall_score > 0.7:
                priority = "critical"
            elif score and score.overall_score > 0.4:
                priority = "high"
            else:
                priority = "medium"

            automated = random.random() > 0.4  # noqa: S311
            effort = random.choice(  # noqa: S311
                ["low", "medium", "high"]
            )

            recommendations.append(
                RemediationRecommendation(
                    recommendation_id=(f"rec-{uuid4().hex[:8]}"),
                    violation_id=violation.violation_id,
                    priority=priority,
                    action=f"Fix: {violation.violation_type}",
                    description=violation.remediation_hint,
                    effort=effort,
                    automated=automated,
                )
            )

        logger.info(
            "cha_fixes_recommended",
            violations=len(violations),
            recommendations=len(recommendations),
        )
        return recommendations

    # ---- Metrics ----

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record a credential hygiene auditor metric."""
        self._metrics.append(
            {
                "name": metric_name,
                "value": value,
                "tags": tags or {},
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
