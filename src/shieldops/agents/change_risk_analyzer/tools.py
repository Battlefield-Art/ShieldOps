"""Change Risk Analyzer Agent — Tool functions for change risk assessment."""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import (
    ApprovalDecision,
    BlastRadiusPrediction,
    ChangeRecommendation,
    ChangeRequest,
    ChangeType,
    RiskAssessment,
    RiskLevel,
)

logger = structlog.get_logger()

# Weighted risk factors — each maps to a score contribution (0-1 scale)
RISK_FACTORS: dict[str, float] = {
    "friday_deploy": 0.15,
    "late_night_deploy": 0.10,
    "database_migration": 0.25,
    "large_diff_500_lines": 0.12,
    "large_diff_1000_lines": 0.20,
    "production_environment": 0.18,
    "multi_service_change": 0.14,
    "no_rollback_plan": 0.20,
    "new_author_first_deploy": 0.08,
    "infrastructure_change": 0.16,
    "config_change_secrets": 0.22,
    "no_tests_added": 0.10,
    "breaking_api_change": 0.18,
    "high_traffic_window": 0.12,
}

# Service dependency graph for blast radius prediction
_SERVICE_DEPENDENCIES: dict[str, list[str]] = {
    "api-gateway": ["auth-service", "billing-service", "user-service"],
    "auth-service": ["user-service", "redis-cache"],
    "billing-service": ["payment-processor", "database-primary"],
    "user-service": ["database-primary", "redis-cache"],
    "payment-processor": ["external-payment-api"],
    "database-primary": ["database-replica"],
    "redis-cache": [],
    "notification-service": ["email-provider", "sms-provider"],
    "search-service": ["elasticsearch", "database-primary"],
    "analytics-service": ["kafka", "clickhouse"],
    "worker-service": ["kafka", "redis-cache", "database-primary"],
}

# User estimates per service
_SERVICE_USER_IMPACT: dict[str, int] = {
    "api-gateway": 100_000,
    "auth-service": 100_000,
    "billing-service": 50_000,
    "user-service": 80_000,
    "payment-processor": 30_000,
    "database-primary": 100_000,
    "database-replica": 20_000,
    "redis-cache": 60_000,
    "notification-service": 40_000,
    "search-service": 25_000,
    "analytics-service": 5_000,
    "worker-service": 10_000,
}

# Historical failure rates by change type
_HISTORICAL_FAILURE_RATES: dict[ChangeType, float] = {
    ChangeType.DEPLOYMENT: 0.05,
    ChangeType.CONFIG_CHANGE: 0.03,
    ChangeType.INFRASTRUCTURE: 0.08,
    ChangeType.DATABASE_MIGRATION: 0.12,
    ChangeType.FEATURE_FLAG: 0.01,
    ChangeType.ROLLBACK: 0.02,
}


class ChangeRiskAnalyzerToolkit:
    """Tools for pre-deployment change risk analysis."""

    def __init__(
        self,
        git_client: Any | None = None,
        deployment_db: Any | None = None,
        incident_db: Any | None = None,
    ) -> None:
        self._git_client = git_client
        self._deployment_db = deployment_db
        self._incident_db = incident_db

    async def analyze_change_diff(
        self,
        changes: list[dict[str, Any]],
    ) -> list[ChangeRequest]:
        """Enrich raw change data with diff analysis.

        Parses change metadata and constructs ChangeRequest objects
        with enriched information from git diff analysis.
        """
        logger.info(
            "change_risk_analyzer.analyze_change_diff",
            change_count=len(changes),
        )

        if self._git_client is not None:
            try:
                raw = await self._git_client.analyze_diffs(changes)
                return [ChangeRequest(**r) for r in raw]
            except Exception:
                logger.exception("change_risk_analyzer.analyze_change_diff.error")

        # Build ChangeRequest objects from raw data or generate mock
        results: list[ChangeRequest] = []
        for change in changes:
            if isinstance(change, ChangeRequest):
                results.append(change)
                continue

            change_id = (
                change.get("id", "")
                or hashlib.sha256(f"{change.get('title', '')}:{time.time()}".encode()).hexdigest()[
                    :12
                ]
            )

            results.append(
                ChangeRequest(
                    id=change_id,
                    title=change.get("title", "Untitled change"),
                    change_type=ChangeType(change.get("change_type", ChangeType.DEPLOYMENT.value)),
                    author=change.get("author", "unknown"),
                    repository=change.get("repository", ""),
                    files_changed=change.get("files_changed", 15),
                    lines_added=change.get("lines_added", 200),
                    lines_removed=change.get("lines_removed", 80),
                    services_affected=change.get(
                        "services_affected",
                        list(_SERVICE_DEPENDENCIES.keys())[:2],
                    ),
                    environment=change.get("environment", "staging"),
                    scheduled_at=change.get("scheduled_at", time.time()),
                )
            )
        return results

    async def assess_risk(
        self,
        changes: list[ChangeRequest],
    ) -> list[RiskAssessment]:
        """Score risk for each change using historical patterns and weighted factors.

        Evaluates change attributes against known risk indicators such as
        deployment timing, diff size, environment, and change type.
        """
        logger.info(
            "change_risk_analyzer.assess_risk",
            change_count=len(changes),
        )

        if self._deployment_db is not None:
            try:
                raw = await self._deployment_db.assess_risk([c.model_dump() for c in changes])
                return [RiskAssessment(**r) for r in raw]
            except Exception:
                logger.exception("change_risk_analyzer.assess_risk.error")

        assessments: list[RiskAssessment] = []
        for change in changes:
            factors: list[str] = []
            score = 0.0

            # Time-based factors
            scheduled = datetime.fromtimestamp(change.scheduled_at or time.time(), tz=UTC)
            if scheduled.weekday() == 4:  # Friday
                factors.append("Friday deployment")
                score += RISK_FACTORS["friday_deploy"]
            if scheduled.hour >= 20 or scheduled.hour <= 5:
                factors.append("Late-night deployment window")
                score += RISK_FACTORS["late_night_deploy"]

            # Change type factors
            if change.change_type == ChangeType.DATABASE_MIGRATION:
                factors.append("Database migration — schema changes carry rollback risk")
                score += RISK_FACTORS["database_migration"]
            if change.change_type == ChangeType.INFRASTRUCTURE:
                factors.append("Infrastructure change — potential for cascading failures")
                score += RISK_FACTORS["infrastructure_change"]

            # Diff size factors
            total_lines = change.lines_added + change.lines_removed
            if total_lines > 1000:
                factors.append(f"Very large diff ({total_lines} lines)")
                score += RISK_FACTORS["large_diff_1000_lines"]
            elif total_lines > 500:
                factors.append(f"Large diff ({total_lines} lines)")
                score += RISK_FACTORS["large_diff_500_lines"]

            # Environment factors
            if change.environment == "production":
                factors.append("Direct production deployment")
                score += RISK_FACTORS["production_environment"]

            # Multi-service factors
            if len(change.services_affected) > 2:
                factors.append(f"Multi-service change ({len(change.services_affected)} services)")
                score += RISK_FACTORS["multi_service_change"]

            # Clamp score to 0-1
            score = min(1.0, max(0.0, score))

            # Derive risk level from score
            if score >= 0.7:
                risk_level = RiskLevel.CRITICAL
            elif score >= 0.5:
                risk_level = RiskLevel.HIGH
            elif score >= 0.3:
                risk_level = RiskLevel.MEDIUM
            elif score >= 0.15:
                risk_level = RiskLevel.LOW
            else:
                risk_level = RiskLevel.MINIMAL

            # Historical failure rate
            base_rate = _HISTORICAL_FAILURE_RATES.get(change.change_type, 0.05)
            historical_rate = round(base_rate * (1 + score), 4)

            assessment_id = hashlib.sha256(
                f"assess:{change.id}:{time.time()}".encode()
            ).hexdigest()[:12]

            assessments.append(
                RiskAssessment(
                    id=assessment_id,
                    change_id=change.id,
                    risk_level=risk_level,
                    risk_score=round(score, 4),
                    risk_factors=factors,
                    historical_failure_rate=historical_rate,
                    similar_changes_count=42,
                    confidence=round(0.72 + score * 0.24, 4),
                )
            )
        return assessments

    async def predict_blast_radius(
        self,
        changes: list[ChangeRequest],
    ) -> list[BlastRadiusPrediction]:
        """Predict the blast radius and downstream impact of each change.

        Uses service dependency graphs to trace cascading failure paths
        and estimate user impact, data risk, and recovery time.
        """
        logger.info(
            "change_risk_analyzer.predict_blast_radius",
            change_count=len(changes),
        )

        if self._incident_db is not None:
            try:
                raw = await self._incident_db.predict_blast_radius(
                    [c.model_dump() for c in changes]
                )
                return [BlastRadiusPrediction(**r) for r in raw]
            except Exception:
                logger.exception("change_risk_analyzer.predict_blast_radius.error")

        predictions: list[BlastRadiusPrediction] = []
        for change in changes:
            # Walk the dependency graph to find all affected services
            affected: set[str] = set(change.services_affected)
            frontier = list(change.services_affected)
            visited: set[str] = set()

            while frontier:
                svc = frontier.pop(0)
                if svc in visited:
                    continue
                visited.add(svc)
                deps = _SERVICE_DEPENDENCIES.get(svc, [])
                for dep in deps:
                    affected.add(dep)
                    if dep not in visited:
                        frontier.append(dep)

            # Estimate user impact
            user_estimate = sum(_SERVICE_USER_IMPACT.get(svc, 1_000) for svc in affected)

            # Identify data at risk
            data_risks: list[str] = []
            if "database-primary" in affected:
                data_risks.append("Primary database — customer records at risk")
            if "redis-cache" in affected:
                data_risks.append("Cache layer — session data at risk")
            if "payment-processor" in affected:
                data_risks.append("Payment data — PCI compliance implications")
            if "auth-service" in affected:
                data_risks.append("Auth tokens — security credential exposure")

            # Cascading failures
            cascading: list[str] = []
            for svc in affected:
                if svc not in change.services_affected:
                    cascading.append(
                        f"{svc} — downstream dependency of {', '.join(change.services_affected)}"
                    )

            # Recovery time estimate (minutes)
            base_recovery = 15
            if change.change_type == ChangeType.DATABASE_MIGRATION:
                base_recovery = 45
            elif change.change_type == ChangeType.INFRASTRUCTURE:
                base_recovery = 30
            recovery_time = base_recovery + (len(affected) * 5)

            prediction_id = hashlib.sha256(f"blast:{change.id}:{time.time()}".encode()).hexdigest()[
                :12
            ]

            predictions.append(
                BlastRadiusPrediction(
                    id=prediction_id,
                    change_id=change.id,
                    affected_services=sorted(affected),
                    affected_users_estimate=user_estimate,
                    data_at_risk=data_risks,
                    recovery_time_estimate_min=recovery_time,
                    cascading_failures=cascading,
                )
            )
        return predictions

    async def generate_recommendations(
        self,
        assessments: list[RiskAssessment],
        predictions: list[BlastRadiusPrediction],
    ) -> list[ChangeRecommendation]:
        """Generate approval/review/block recommendations.

        Combines risk assessment scores with blast radius predictions
        to determine the appropriate approval gate for each change.
        """
        logger.info(
            "change_risk_analyzer.generate_recommendations",
            assessment_count=len(assessments),
        )

        # Index predictions by change_id
        pred_map: dict[str, BlastRadiusPrediction] = {p.change_id: p for p in predictions}

        recommendations: list[ChangeRecommendation] = []
        for assessment in assessments:
            pred = pred_map.get(assessment.change_id)

            # Determine approval decision
            if assessment.risk_level == RiskLevel.CRITICAL:
                decision = ApprovalDecision.BLOCK
                reviewers = ["vp-engineering", "sre-lead", "security-lead"]
            elif assessment.risk_level == RiskLevel.HIGH:
                decision = ApprovalDecision.REQUIRE_SENIOR_REVIEW
                reviewers = ["sre-lead", "team-lead"]
            elif assessment.risk_level == RiskLevel.MEDIUM:
                decision = ApprovalDecision.REQUIRE_REVIEW
                reviewers = ["team-lead"]
            elif assessment.risk_level == RiskLevel.LOW:
                decision = ApprovalDecision.AUTO_APPROVE
                reviewers = []
            else:
                decision = ApprovalDecision.AUTO_APPROVE
                reviewers = []

            # Override: block if blast radius is very wide
            if pred and len(pred.affected_services) > 6:
                decision = ApprovalDecision.BLOCK
                if "sre-lead" not in reviewers:
                    reviewers.append("sre-lead")

            # Build reasoning
            reasoning_parts = [
                f"Risk score: {assessment.risk_score:.2f} ({assessment.risk_level.value})",
            ]
            if assessment.risk_factors:
                reasoning_parts.append(f"Key factors: {', '.join(assessment.risk_factors[:3])}")
            if pred:
                reasoning_parts.append(
                    f"Blast radius: {len(pred.affected_services)} services, "
                    f"~{pred.affected_users_estimate:,} users impacted"
                )

            # Rollback plan
            rollback_plan = (
                "Revert to previous deployment version via CI/CD pipeline. "
                "Estimated rollback time: "
                f"{pred.recovery_time_estimate_min if pred else 15} minutes."
            )

            # Canary suggestion — suggest for medium+ risk in production
            canary = assessment.risk_score >= 0.3

            # Monitoring requirements
            monitoring: list[str] = ["Error rate dashboard"]
            if assessment.risk_score >= 0.3:
                monitoring.append("P99 latency alerts")
            if pred and "database-primary" in pred.affected_services:
                monitoring.append("Database connection pool monitoring")
            if pred and "payment-processor" in pred.affected_services:
                monitoring.append("Payment success rate tracking")
            if canary:
                monitoring.append("Canary vs baseline comparison")

            rec_id = hashlib.sha256(
                f"rec:{assessment.change_id}:{time.time()}".encode()
            ).hexdigest()[:12]

            recommendations.append(
                ChangeRecommendation(
                    id=rec_id,
                    change_id=assessment.change_id,
                    approval_decision=decision,
                    reasoning=". ".join(reasoning_parts),
                    required_reviewers=reviewers,
                    rollback_plan=rollback_plan,
                    canary_suggested=canary,
                    monitoring_requirements=monitoring,
                )
            )
        return recommendations
