"""Security Posture Manager Agent — Tool functions for posture assessment."""

from __future__ import annotations

import random
from typing import Any

import structlog

from .models import (
    DomainAssessment,
    PostureDomain,
    PostureGap,
    PostureReport,
    RiskCategory,
)

logger = structlog.get_logger()

# Default control counts and baseline scores per domain
_DOMAIN_PROFILES: dict[str, dict[str, Any]] = {
    "identity": {
        "controls_total": 25,
        "baseline_score": 72.0,
        "common_findings": [
            "MFA not enforced for service accounts",
            "Stale admin credentials older than 90 days",
            "Overprivileged IAM roles detected",
            "No conditional access policies for privileged access",
        ],
        "common_gaps": [
            (
                "Enforce MFA on all service accounts",
                "Deploy MFA enrollment for service accounts",
                8.0,
            ),
            (
                "Rotate stale admin credentials",
                "Implement automated credential rotation policy",
                4.0,
            ),
            (
                "Right-size IAM permissions",
                "Audit and reduce IAM role scope using least privilege",
                16.0,
            ),
        ],
    },
    "network": {
        "controls_total": 30,
        "baseline_score": 68.0,
        "common_findings": [
            "Unrestricted egress traffic on non-production VPCs",
            "Missing network segmentation between tiers",
            "DNS exfiltration detection not enabled",
            "Expired TLS certificates on internal endpoints",
        ],
        "common_gaps": [
            ("Restrict egress traffic", "Implement egress filtering with allow-list", 12.0),
            ("Segment network tiers", "Deploy micro-segmentation between application tiers", 24.0),
            ("Enable DNS monitoring", "Deploy DNS analytics and exfiltration detection", 6.0),
        ],
    },
    "endpoint": {
        "controls_total": 20,
        "baseline_score": 75.0,
        "common_findings": [
            "EDR coverage gap on 12% of endpoints",
            "Outdated OS patches on 8% of fleet",
            "Local admin accounts active on developer workstations",
        ],
        "common_gaps": [
            ("Close EDR coverage gap", "Deploy EDR agent to uncovered endpoints", 10.0),
            ("Patch outdated endpoints", "Accelerate patch cycle for critical OS updates", 6.0),
            ("Remove local admin rights", "Implement PAM for developer workstations", 8.0),
        ],
    },
    "cloud": {
        "controls_total": 35,
        "baseline_score": 65.0,
        "common_findings": [
            "Public S3 buckets with sensitive data classification",
            "Missing encryption at rest for 3 RDS instances",
            "CloudTrail not enabled in 2 regions",
            "Security groups allow 0.0.0.0/0 inbound on non-web ports",
            "No VPC flow logs in staging environment",
        ],
        "common_gaps": [
            ("Remediate public S3 buckets", "Apply bucket policies to restrict public access", 4.0),
            ("Enable encryption at rest", "Enable RDS encryption and rotate KMS keys", 8.0),
            ("Enable CloudTrail globally", "Configure CloudTrail in all active regions", 2.0),
            (
                "Restrict security groups",
                "Audit and tighten inbound rules to least privilege",
                12.0,
            ),
        ],
    },
    "data": {
        "controls_total": 22,
        "baseline_score": 70.0,
        "common_findings": [
            "Data classification incomplete for 30% of data stores",
            "No DLP policies for outbound email",
            "Database audit logging disabled on 2 instances",
        ],
        "common_gaps": [
            (
                "Complete data classification",
                "Run automated classification scan on all data stores",
                16.0,
            ),
            ("Deploy DLP for email", "Configure DLP rules for sensitive data in email", 8.0),
            (
                "Enable database audit logging",
                "Turn on audit logging for all database instances",
                2.0,
            ),
        ],
    },
}

# Risk category assignment thresholds (based on impact_score)
_RISK_THRESHOLDS: list[tuple[float, RiskCategory]] = [
    (80.0, RiskCategory.CRITICAL),
    (60.0, RiskCategory.HIGH),
    (40.0, RiskCategory.MEDIUM),
    (20.0, RiskCategory.LOW),
    (0.0, RiskCategory.INFORMATIONAL),
]


def _assign_risk_category(impact_score: float) -> RiskCategory:
    """Assign risk category based on impact score."""
    for threshold, category in _RISK_THRESHOLDS:
        if impact_score >= threshold:
            return category
    return RiskCategory.INFORMATIONAL


class SecurityPostureToolkit:
    """Tools for security posture assessment and gap analysis."""

    def __init__(
        self,
        rba_client: Any | None = None,
        compliance_store: Any | None = None,
        vuln_scanner: Any | None = None,
        threat_intel: Any | None = None,
    ) -> None:
        self._rba_client = rba_client
        self._compliance_store = compliance_store
        self._vuln_scanner = vuln_scanner
        self._threat_intel = threat_intel

    async def assess_domain(self, domain: PostureDomain | str) -> DomainAssessment:
        """Assess a single security domain and return its posture score.

        Uses external integrations if available, otherwise returns mock assessment
        based on domain profiles.
        """
        if isinstance(domain, str):
            domain = PostureDomain(domain)

        logger.info("security_posture.assess_domain", domain=domain.value)

        if self._compliance_store is not None:
            try:
                raw = await self._compliance_store.assess_domain(domain=domain.value)
                return DomainAssessment(**raw)
            except Exception:
                logger.exception("security_posture.assess_domain.error")

        # Mock fallback
        profile = _DOMAIN_PROFILES.get(domain.value, _DOMAIN_PROFILES["identity"])
        controls_total = profile["controls_total"]

        # Simulate score with some variance
        baseline = profile["baseline_score"]
        noise = random.gauss(0, 5.0)
        score = round(max(0.0, min(100.0, baseline + noise)), 1)

        # Calculate passing controls proportionally to score
        controls_passing = int(controls_total * score / 100.0)

        # Select a subset of findings
        all_findings = profile["common_findings"]
        num_findings = max(1, int(len(all_findings) * (1 - score / 100.0) + 0.5))
        findings = all_findings[:num_findings]

        return DomainAssessment(
            domain=domain,
            score=score,
            findings=findings,
            controls_passing=controls_passing,
            controls_total=controls_total,
        )

    async def identify_gaps(self, assessments: list[DomainAssessment]) -> list[PostureGap]:
        """Identify security gaps based on domain assessments.

        Analyzes each domain's score and findings to produce actionable gaps
        ranked by impact.
        """
        logger.info(
            "security_posture.identify_gaps",
            assessment_count=len(assessments),
        )

        if self._vuln_scanner is not None:
            try:
                raw = await self._vuln_scanner.identify_gaps(
                    assessments=[a.model_dump() for a in assessments]
                )
                return [PostureGap(**g) for g in raw]
            except Exception:
                logger.exception("security_posture.identify_gaps.error")

        # Mock fallback — generate gaps from domain profiles
        gaps: list[PostureGap] = []
        for assessment in assessments:
            profile = _DOMAIN_PROFILES.get(assessment.domain.value, _DOMAIN_PROFILES["identity"])
            gap_defs = profile["common_gaps"]

            # More gaps for lower-scoring domains
            gap_ratio = 1.0 - assessment.score / 100.0
            num_gaps = max(1, int(len(gap_defs) * gap_ratio + 0.5))

            for desc, remediation, effort in gap_defs[:num_gaps]:
                # Impact score inversely related to domain score
                impact = round(
                    max(10.0, min(100.0, 100.0 - assessment.score + random.gauss(0, 5))), 1
                )
                category = _assign_risk_category(impact)

                gaps.append(
                    PostureGap(
                        domain=assessment.domain,
                        category=category,
                        description=desc,
                        remediation=remediation,
                        effort_hours=effort,
                        impact_score=impact,
                    )
                )

        return gaps

    def prioritize_gaps(self, gaps: list[PostureGap]) -> list[PostureGap]:
        """Prioritize gaps by impact-to-effort ratio (highest first).

        Gaps with the highest impact per hour of remediation effort are prioritized,
        following the RBA principle of focusing resources on highest-risk items.
        """
        logger.info("security_posture.prioritize_gaps", gap_count=len(gaps))

        def _priority_score(gap: PostureGap) -> float:
            """Higher is more urgent: impact / effort, with category weight."""
            category_weight = {
                RiskCategory.CRITICAL: 5.0,
                RiskCategory.HIGH: 4.0,
                RiskCategory.MEDIUM: 3.0,
                RiskCategory.LOW: 2.0,
                RiskCategory.INFORMATIONAL: 1.0,
            }
            weight = category_weight.get(gap.category, 1.0)
            effort = max(gap.effort_hours, 0.5)  # Avoid division by zero
            return (gap.impact_score * weight) / effort

        return sorted(gaps, key=_priority_score, reverse=True)

    def generate_posture_report(
        self,
        assessments: list[DomainAssessment],
        gaps: list[PostureGap],
    ) -> PostureReport:
        """Generate a unified security posture report.

        Combines domain scores into an overall score, summarizes gaps,
        and produces actionable recommendations.
        """
        logger.info(
            "security_posture.generate_posture_report",
            assessment_count=len(assessments),
            gap_count=len(gaps),
        )

        # Calculate domain scores and overall score
        domain_scores: dict[str, float] = {}
        for a in assessments:
            domain_scores[a.domain.value] = a.score

        if assessments:
            overall_score = round(sum(a.score for a in assessments) / len(assessments), 1)
        else:
            overall_score = 0.0

        # Determine trend based on overall score
        if overall_score >= 80.0:
            trend = "improving"
        elif overall_score >= 60.0:
            trend = "stable"
        else:
            trend = "declining"

        # Generate recommendations from top gaps
        recommendations: list[str] = []
        critical_gaps = [g for g in gaps if g.category == RiskCategory.CRITICAL]
        high_gaps = [g for g in gaps if g.category == RiskCategory.HIGH]

        if critical_gaps:
            recommendations.append(
                f"URGENT: Address {len(critical_gaps)} critical gap(s) immediately — "
                f"{critical_gaps[0].description}"
            )
        if high_gaps:
            recommendations.append(
                f"HIGH PRIORITY: Remediate {len(high_gaps)} high-risk gap(s) within 7 days"
            )
        if overall_score < 70.0:
            low_domains = [d for d, s in domain_scores.items() if s < 65.0]
            if low_domains:
                recommendations.append(
                    f"Focus investment on weakest domains: {', '.join(low_domains)}"
                )
        recommendations.append(f"Overall posture score: {overall_score}/100 — trend: {trend}")

        return PostureReport(
            overall_score=overall_score,
            domain_scores=domain_scores,
            gaps=gaps,
            trend=trend,
            recommendations=recommendations,
        )
