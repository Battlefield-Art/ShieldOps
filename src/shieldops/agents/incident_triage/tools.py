"""Tool functions for the Incident Triage Agent."""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_triage.models import (
    EnrichmentResult,
    IncidentCategory,
    IncidentSeverity,
    IncomingIncident,
    RoutingDecision,
    SeverityClassification,
    TriageConfidence,
)

logger = structlog.get_logger()

# Keyword patterns used for heuristic severity classification
SEVERITY_KEYWORDS: dict[IncidentSeverity, list[str]] = {
    IncidentSeverity.SEV1: [
        "data breach",
        "ransomware",
        "total outage",
        "complete failure",
        "production down",
        "exfiltration",
        "root compromise",
        "all customers affected",
    ],
    IncidentSeverity.SEV2: [
        "partial outage",
        "degraded",
        "high error rate",
        "security incident",
        "unauthorized access",
        "service down",
        "major impact",
    ],
    IncidentSeverity.SEV3: [
        "elevated latency",
        "intermittent errors",
        "slow response",
        "minor security",
        "config drift",
        "capacity warning",
    ],
    IncidentSeverity.SEV4: [
        "warning",
        "threshold exceeded",
        "certificate expiring",
        "disk usage high",
        "minor anomaly",
        "informational",
    ],
    IncidentSeverity.SEV5: [
        "cosmetic",
        "low priority",
        "scheduled maintenance",
        "known issue",
        "documentation",
    ],
}

CATEGORY_KEYWORDS: dict[IncidentCategory, list[str]] = {
    IncidentCategory.SECURITY_BREACH: [
        "breach",
        "unauthorized",
        "malware",
        "ransomware",
        "exfiltration",
        "intrusion",
        "compromise",
        "phishing",
    ],
    IncidentCategory.AVAILABILITY: [
        "outage",
        "down",
        "unreachable",
        "timeout",
        "failure",
        "unavailable",
        "crash",
    ],
    IncidentCategory.PERFORMANCE: [
        "latency",
        "slow",
        "degraded",
        "high cpu",
        "memory leak",
        "throughput",
        "bottleneck",
    ],
    IncidentCategory.DATA_LOSS: [
        "data loss",
        "corruption",
        "deleted",
        "missing data",
        "backup failure",
        "replication lag",
    ],
    IncidentCategory.COMPLIANCE: [
        "compliance",
        "audit",
        "regulatory",
        "policy violation",
        "gdpr",
        "hipaa",
        "pci",
        "sox",
    ],
    IncidentCategory.CONFIGURATION: [
        "config",
        "misconfiguration",
        "drift",
        "wrong setting",
        "deployment",
        "rollback",
    ],
}

# Team routing based on category
TEAM_ROUTING: dict[IncidentCategory, str] = {
    IncidentCategory.SECURITY_BREACH: "security-ops",
    IncidentCategory.AVAILABILITY: "platform-sre",
    IncidentCategory.PERFORMANCE: "platform-sre",
    IncidentCategory.DATA_LOSS: "data-engineering",
    IncidentCategory.COMPLIANCE: "governance-risk-compliance",
    IncidentCategory.CONFIGURATION: "devops",
}

# Estimated TTM (time to mitigate) in minutes by severity
TTM_ESTIMATES: dict[IncidentSeverity, int] = {
    IncidentSeverity.SEV1: 15,
    IncidentSeverity.SEV2: 30,
    IncidentSeverity.SEV3: 60,
    IncidentSeverity.SEV4: 240,
    IncidentSeverity.SEV5: 480,
}


class IncidentTriageToolkit:
    """Toolkit for incident triage — classification, enrichment, dedup, and routing."""

    def __init__(
        self,
        incident_db: Any | None = None,
        change_db: Any | None = None,
        oncall_service: Any | None = None,
    ) -> None:
        self._incident_db = incident_db
        self._change_db = change_db
        self._oncall_service = oncall_service

    def _text_fingerprint(self, text: str) -> str:
        """Generate a fingerprint for deduplication."""
        normalized = " ".join(text.lower().split())
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def _match_keywords(
        self,
        text: str,
        keyword_map: dict[Any, list[str]],
    ) -> tuple[Any, float]:
        """Match text against keyword patterns, returning best match and score."""
        text_lower = text.lower()
        best_key = None
        best_score = 0.0

        for key, keywords in keyword_map.items():
            hits = sum(1 for kw in keywords if kw in text_lower)
            if hits > best_score:
                best_score = hits
                best_key = key

        # Normalize score to 0-1 range
        if best_key is not None:
            max_possible = len(keyword_map[best_key])
            best_score = best_score / max_possible if max_possible > 0 else 0.0

        return best_key, best_score

    async def classify_severity(
        self,
        incidents: list[IncomingIncident],
    ) -> list[SeverityClassification]:
        """Classify severity for each incident using NLP keyword + historical patterns."""
        classifications: list[SeverityClassification] = []

        for incident in incidents:
            combined_text = f"{incident.title} {incident.description}"

            # Keyword-based severity
            severity_match, sev_score = self._match_keywords(combined_text, SEVERITY_KEYWORDS)
            severity = severity_match or IncidentSeverity.SEV4

            # Map raw_severity hint if provided
            raw_map: dict[str, IncidentSeverity] = {
                "critical": IncidentSeverity.SEV1,
                "high": IncidentSeverity.SEV2,
                "medium": IncidentSeverity.SEV3,
                "low": IncidentSeverity.SEV4,
                "info": IncidentSeverity.SEV5,
            }
            if incident.raw_severity.lower() in raw_map and sev_score < 0.3:
                severity = raw_map[incident.raw_severity.lower()]

            # Category classification
            category_match, cat_score = self._match_keywords(combined_text, CATEGORY_KEYWORDS)
            category = category_match or IncidentCategory.CONFIGURATION

            # Confidence based on combined scores
            avg_score = (sev_score + cat_score) / 2
            if avg_score >= 0.4:
                confidence = TriageConfidence.HIGH
            elif avg_score >= 0.2:
                confidence = TriageConfidence.MEDIUM
            elif avg_score >= 0.1:
                confidence = TriageConfidence.LOW
            else:
                confidence = TriageConfidence.UNCERTAIN

            # Simulate historical lookup
            historical_count = 0
            if self._incident_db is not None:
                try:
                    historical_count = await self._incident_db.count_similar(incident.title)
                except Exception:
                    logger.debug("historical_lookup_failed", incident_id=incident.id)

            reasoning = (
                f"Keyword severity={severity.value} (score={sev_score:.2f}), "
                f"category={category.value} (score={cat_score:.2f}), "
                f"raw_severity={incident.raw_severity}, "
                f"historical_similar={historical_count}"
            )

            classifications.append(
                SeverityClassification(
                    id=f"cls-{uuid4().hex[:12]}",
                    incident_id=incident.id,
                    severity=severity,
                    category=category,
                    confidence=confidence,
                    reasoning=reasoning,
                    historical_similar=historical_count,
                )
            )

            logger.info(
                "incident_triage.classified",
                incident_id=incident.id,
                severity=severity.value,
                category=category.value,
                confidence=confidence.value,
            )

        return classifications

    async def enrich_context(
        self,
        incidents: list[IncomingIncident],
    ) -> list[EnrichmentResult]:
        """Enrich incidents with customer impact, blast radius, related changes."""
        enrichments: list[EnrichmentResult] = []

        for incident in incidents:
            # Estimate affected customers from service count
            service_count = len(incident.affected_services)
            affected_customers = service_count * 500  # heuristic

            # Blast radius heuristic
            if service_count >= 5:
                blast_radius = "critical — multi-service cascade"
            elif service_count >= 3:
                blast_radius = "high — cross-service impact"
            elif service_count >= 1:
                blast_radius = "medium — single-service impact"
            else:
                blast_radius = "low — isolated"

            # Related changes lookup
            related_changes: list[str] = []
            if self._change_db is not None:
                try:
                    related_changes = await self._change_db.recent_changes(
                        services=incident.affected_services,
                        window_hours=4,
                    )
                except Exception:
                    logger.debug("change_lookup_failed", incident_id=incident.id)

            # Related incidents lookup
            related_incidents: list[str] = []
            if self._incident_db is not None:
                try:
                    related_incidents = await self._incident_db.find_related(incident.id)
                except Exception:
                    logger.debug("related_lookup_failed", incident_id=incident.id)

            # On-call team lookup
            on_call_team = ""
            if self._oncall_service is not None:
                try:
                    on_call_team = await self._oncall_service.current_oncall(
                        incident.affected_services
                    )
                except Exception:
                    logger.debug("oncall_lookup_failed", incident_id=incident.id)

            enrichments.append(
                EnrichmentResult(
                    id=f"enr-{uuid4().hex[:12]}",
                    incident_id=incident.id,
                    affected_customers=affected_customers,
                    blast_radius=blast_radius,
                    related_changes=related_changes,
                    related_incidents=related_incidents,
                    runbook_url="",
                    on_call_team=on_call_team,
                )
            )

            logger.info(
                "incident_triage.enriched",
                incident_id=incident.id,
                affected_customers=affected_customers,
                blast_radius=blast_radius,
            )

        return enrichments

    async def deduplicate_incidents(
        self,
        incidents: list[IncomingIncident],
    ) -> tuple[list[IncomingIncident], int]:
        """Merge duplicate/related incidents based on text fingerprinting."""
        seen_fingerprints: dict[str, IncomingIncident] = {}
        deduplicated: list[IncomingIncident] = []
        merged_count = 0

        for incident in incidents:
            fp = self._text_fingerprint(f"{incident.title}{incident.source}")

            if fp in seen_fingerprints:
                # Merge alerts and affected services into existing
                existing = seen_fingerprints[fp]
                existing.alerts.extend(incident.alerts)
                for svc in incident.affected_services:
                    if svc not in existing.affected_services:
                        existing.affected_services.append(svc)
                merged_count += 1
                logger.info(
                    "incident_triage.deduplicated",
                    merged_id=incident.id,
                    into_id=existing.id,
                )
            else:
                seen_fingerprints[fp] = incident
                deduplicated.append(incident)

        logger.info(
            "incident_triage.dedup_complete",
            original=len(incidents),
            deduplicated=len(deduplicated),
            merged=merged_count,
        )

        return deduplicated, merged_count

    async def route_incidents(
        self,
        classifications: list[SeverityClassification],
        enrichments: list[EnrichmentResult],
    ) -> list[RoutingDecision]:
        """Route incidents to appropriate teams based on classification and enrichment."""
        enrichment_map: dict[str, EnrichmentResult] = {e.incident_id: e for e in enrichments}
        decisions: list[RoutingDecision] = []

        for cls in classifications:
            enrichment = enrichment_map.get(cls.incident_id)

            # Team assignment based on category
            assigned_team = TEAM_ROUTING.get(cls.category, "platform-sre")

            # Override with on-call team if available
            if enrichment and enrichment.on_call_team:
                assigned_team = enrichment.on_call_team

            # Escalation required for SEV1/SEV2 or uncertain confidence
            escalation_required = (
                cls.severity
                in (
                    IncidentSeverity.SEV1,
                    IncidentSeverity.SEV2,
                )
                or cls.confidence == TriageConfidence.UNCERTAIN
            )

            # Auto-remediation possible for low severity config/perf issues
            auto_remediation_possible = (
                cls.severity in (IncidentSeverity.SEV4, IncidentSeverity.SEV5)
                and cls.category in (IncidentCategory.CONFIGURATION, IncidentCategory.PERFORMANCE)
                and cls.confidence in (TriageConfidence.HIGH, TriageConfidence.MEDIUM)
            )

            estimated_ttm = TTM_ESTIMATES.get(cls.severity, 60)

            routing_reason = (
                f"Category={cls.category.value} -> team={assigned_team}, "
                f"severity={cls.severity.value} -> escalation={escalation_required}, "
                f"auto_remediation={auto_remediation_possible}, "
                f"est_ttm={estimated_ttm}min"
            )

            decisions.append(
                RoutingDecision(
                    id=f"rte-{uuid4().hex[:12]}",
                    incident_id=cls.incident_id,
                    assigned_team=assigned_team,
                    escalation_required=escalation_required,
                    auto_remediation_possible=auto_remediation_possible,
                    estimated_ttm_minutes=estimated_ttm,
                    routing_reason=routing_reason,
                )
            )

            logger.info(
                "incident_triage.routed",
                incident_id=cls.incident_id,
                assigned_team=assigned_team,
                escalation=escalation_required,
            )

        return decisions
