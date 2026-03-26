"""Tool functions for the AI Triage Accelerator Agent."""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ai_triage_accelerator.models import (
    Classification,
    ClassificationResult,
    ConfidenceScore,
    EnrichmentData,
    RoutingAction,
    RoutingDecision,
)

logger = structlog.get_logger()

# Keyword patterns for heuristic classification
MALICIOUS_KEYWORDS: list[str] = [
    "ransomware",
    "c2 beacon",
    "exfiltration",
    "lateral movement",
    "privilege escalation",
    "rootkit",
    "backdoor",
    "cryptominer",
    "command and control",
    "data theft",
]

TRUE_POSITIVE_KEYWORDS: list[str] = [
    "unauthorized access",
    "brute force",
    "credential stuffing",
    "port scan",
    "exploit attempt",
    "sql injection",
    "xss",
    "phishing",
    "malware detected",
    "anomalous behavior",
]

BENIGN_KEYWORDS: list[str] = [
    "scheduled scan",
    "maintenance window",
    "planned deployment",
    "test environment",
    "known safe",
    "whitelisted",
    "approved change",
    "health check",
    "synthetic monitor",
    "canary deployment",
]

FALSE_POSITIVE_KEYWORDS: list[str] = [
    "scanner noise",
    "duplicate alert",
    "stale indicator",
    "misconfigured rule",
    "threshold too low",
    "known good",
    "vendor update",
    "network scan internal",
    "auto-scaling event",
    "dns resolution normal",
]

# Threat intel IOC reputation patterns
IOC_SEVERITY: dict[str, float] = {
    "known_apt": 0.95,
    "known_malware": 0.90,
    "suspicious_ip": 0.60,
    "tor_exit_node": 0.70,
    "vpn_endpoint": 0.30,
    "cdn_ip": 0.10,
    "internal_ip": 0.05,
}

# Team routing based on classification
TEAM_ROUTING: dict[Classification, str] = {
    Classification.MALICIOUS: "soc-tier3",
    Classification.TRUE_POSITIVE: "soc-tier2",
    Classification.SUSPICIOUS: "soc-tier1",
    Classification.FALSE_POSITIVE: "auto-close",
    Classification.BENIGN: "auto-close",
}

# Resolution time estimates in minutes
RESOLUTION_ESTIMATES: dict[RoutingDecision, int] = {
    RoutingDecision.AUTO_CLOSE: 0,
    RoutingDecision.AUTO_REMEDIATE: 5,
    RoutingDecision.ANALYST_REVIEW: 30,
    RoutingDecision.ESCALATE_URGENT: 15,
}


class AITriageAcceleratorToolkit:
    """Toolkit for AI-accelerated triage operations."""

    def __init__(
        self,
        siem_client: Any | None = None,
        threat_intel_client: Any | None = None,
        identity_graph_client: Any | None = None,
        asset_inventory: Any | None = None,
    ) -> None:
        self._siem = siem_client
        self._threat_intel = threat_intel_client
        self._identity_graph = identity_graph_client
        self._asset_inventory = asset_inventory

    def _text_fingerprint(self, text: str) -> str:
        """Generate fingerprint for dedup."""
        normalized = " ".join(text.lower().split())
        return hashlib.sha256(
            normalized.encode(),
        ).hexdigest()[:16]

    def _match_keyword_score(
        self,
        text: str,
        keywords: list[str],
    ) -> float:
        """Score text against keyword list (0-1)."""
        text_lower = text.lower()
        hits = sum(1 for kw in keywords if kw in text_lower)
        return min(hits / max(len(keywords), 1), 1.0)

    async def batch_classify(
        self,
        alerts: list[dict[str, Any]],
    ) -> list[ClassificationResult]:
        """Classify a batch of alerts using heuristics."""
        results: list[ClassificationResult] = []

        for alert in alerts:
            alert_id = alert.get("id", f"alert-{uuid4().hex[:8]}")
            text = f"{alert.get('title', '')} {alert.get('description', '')}"

            # Score against each classification
            mal_score = self._match_keyword_score(
                text,
                MALICIOUS_KEYWORDS,
            )
            tp_score = self._match_keyword_score(
                text,
                TRUE_POSITIVE_KEYWORDS,
            )
            ben_score = self._match_keyword_score(
                text,
                BENIGN_KEYWORDS,
            )
            fp_score = self._match_keyword_score(
                text,
                FALSE_POSITIVE_KEYWORDS,
            )

            # Determine classification from highest score
            scores = {
                Classification.MALICIOUS: mal_score,
                Classification.TRUE_POSITIVE: tp_score,
                Classification.BENIGN: ben_score,
                Classification.FALSE_POSITIVE: fp_score,
            }
            best_cls = max(scores, key=scores.get)  # type: ignore[arg-type]
            best_score = scores[best_cls]

            # Default to suspicious if no strong signal
            if best_score < 0.1:
                best_cls = Classification.SUSPICIOUS
                best_score = 0.3

            # Extract indicators
            indicators: list[str] = []
            for field in ("src_ip", "dst_ip", "domain", "hash"):
                val = alert.get(field)
                if val:
                    indicators.append(f"{field}={val}")

            reasoning = (
                f"Heuristic: {best_cls.value} "
                f"(score={best_score:.2f}), "
                f"indicators={len(indicators)}"
            )

            results.append(
                ClassificationResult(
                    id=f"cls-{uuid4().hex[:12]}",
                    alert_id=alert_id,
                    classification=best_cls,
                    confidence=best_score,
                    reasoning=reasoning,
                    indicators=indicators,
                )
            )

            logger.info(
                "ai_triage.classified",
                alert_id=alert_id,
                classification=best_cls.value,
                confidence=f"{best_score:.2f}",
            )

        return results

    async def enrich_alerts(
        self,
        alerts: list[dict[str, Any]],
        classifications: list[ClassificationResult],
    ) -> list[EnrichmentData]:
        """Enrich alerts with threat intel, identity, assets."""
        cls_map = {c.alert_id: c for c in classifications}
        enrichments: list[EnrichmentData] = []

        for alert in alerts:
            alert_id = alert.get("id", "")
            cls = cls_map.get(alert_id)
            sources: list[str] = []

            # Threat intel lookup
            threat_hits: list[dict[str, Any]] = []
            if self._threat_intel is not None:
                try:
                    iocs = cls.indicators if cls else []
                    threat_hits = await self._threat_intel.lookup(iocs)
                    sources.append("threat_intel")
                except Exception:
                    logger.debug(
                        "threat_intel_failed",
                        alert_id=alert_id,
                    )
            else:
                # Heuristic: check IOC patterns
                for ioc_type, sev in IOC_SEVERITY.items():
                    desc = alert.get("description", "").lower()
                    if ioc_type.replace("_", " ") in desc:
                        threat_hits.append(
                            {"type": ioc_type, "severity": sev},
                        )
                if threat_hits:
                    sources.append("threat_intel_heuristic")

            # Identity graph lookup
            identity_ctx: dict[str, Any] = {}
            if self._identity_graph is not None:
                try:
                    user = alert.get("user", "")
                    identity_ctx = await self._identity_graph.resolve(user)
                    sources.append("identity_graph")
                except Exception:
                    logger.debug(
                        "identity_graph_failed",
                        alert_id=alert_id,
                    )

            # Asset criticality
            asset_crit = "medium"
            if self._asset_inventory is not None:
                try:
                    host = alert.get("host", "")
                    asset_crit = await self._asset_inventory.criticality(
                        host,
                    )
                    sources.append("asset_inventory")
                except Exception:
                    logger.debug(
                        "asset_lookup_failed",
                        alert_id=alert_id,
                    )
            else:
                # Heuristic asset criticality
                host = alert.get("host", "").lower()
                if any(k in host for k in ("prod", "db", "auth", "api")):
                    asset_crit = "critical"
                elif any(k in host for k in ("staging", "internal")):
                    asset_crit = "high"

            # Historical alert count (heuristic)
            historical = 0
            if self._siem is not None:
                try:
                    historical = await self._siem.count_similar(
                        alert.get("title", ""),
                    )
                    sources.append("siem")
                except Exception:
                    logger.debug(
                        "siem_lookup_failed",
                        alert_id=alert_id,
                    )

            enrichments.append(
                EnrichmentData(
                    id=f"enr-{uuid4().hex[:12]}",
                    alert_id=alert_id,
                    threat_intel_hits=threat_hits,
                    identity_context=identity_ctx,
                    asset_criticality=asset_crit,
                    historical_alerts=historical,
                    enrichment_sources=sources,
                )
            )

            logger.info(
                "ai_triage.enriched",
                alert_id=alert_id,
                threat_hits=len(threat_hits),
                asset_criticality=asset_crit,
                sources=sources,
            )

        return enrichments

    async def score_confidence(
        self,
        classifications: list[ClassificationResult],
        enrichments: list[EnrichmentData],
    ) -> list[ConfidenceScore]:
        """Compute confidence scores with transparent reasoning."""
        enr_map = {e.alert_id: e for e in enrichments}
        scores: list[ConfidenceScore] = []

        for cls in classifications:
            enr = enr_map.get(cls.alert_id)
            reasoning: list[str] = []

            # Classification confidence weight (40%)
            cls_weight = cls.confidence * 0.4
            reasoning.append(
                f"Classification confidence: {cls.confidence:.2f} * 0.4 = {cls_weight:.2f}",
            )

            # Enrichment weight (35%)
            enr_weight = 0.0
            if enr:
                ti_boost = min(
                    len(enr.threat_intel_hits) * 0.1,
                    0.35,
                )
                if enr.asset_criticality == "critical":
                    ti_boost = min(ti_boost + 0.1, 0.35)
                enr_weight = ti_boost
                reasoning.append(
                    f"Enrichment boost: "
                    f"threat_hits={len(enr.threat_intel_hits)}"
                    f", asset={enr.asset_criticality}"
                    f" -> {enr_weight:.2f}",
                )

            # Historical weight (25%)
            hist_weight = 0.0
            if enr and enr.historical_alerts > 0:
                # More historical = more confident
                hist_weight = min(
                    enr.historical_alerts * 0.05,
                    0.25,
                )
                reasoning.append(
                    f"Historical: {enr.historical_alerts} similar -> {hist_weight:.2f}",
                )

            overall = min(
                cls_weight + enr_weight + hist_weight,
                1.0,
            )
            reasoning.append(
                f"Overall: {overall:.2f}",
            )

            scores.append(
                ConfidenceScore(
                    id=f"conf-{uuid4().hex[:12]}",
                    alert_id=cls.alert_id,
                    overall_score=overall,
                    classification_weight=cls_weight,
                    enrichment_weight=enr_weight,
                    historical_weight=hist_weight,
                    reasoning_chain=reasoning,
                )
            )

            logger.info(
                "ai_triage.confidence_scored",
                alert_id=cls.alert_id,
                overall=f"{overall:.2f}",
            )

        return scores

    async def route_alerts(
        self,
        classifications: list[ClassificationResult],
        confidence_scores: list[ConfidenceScore],
    ) -> list[RoutingAction]:
        """Route alerts based on classification + confidence."""
        conf_map = {c.alert_id: c for c in confidence_scores}
        actions: list[RoutingAction] = []

        for cls in classifications:
            conf = conf_map.get(cls.alert_id)
            score = conf.overall_score if conf else 0.5

            # Determine routing decision
            if (
                cls.classification
                in (
                    Classification.FALSE_POSITIVE,
                    Classification.BENIGN,
                )
                and score > 0.95
            ):
                decision = RoutingDecision.AUTO_CLOSE
                auto_action = "closed_as_benign"
            elif cls.classification in (Classification.TRUE_POSITIVE,) and score > 0.85:
                decision = RoutingDecision.AUTO_REMEDIATE
                auto_action = "playbook_triggered"
            elif cls.classification in (Classification.MALICIOUS,) or score < 0.5:
                decision = RoutingDecision.ESCALATE_URGENT
                auto_action = ""
            else:
                decision = RoutingDecision.ANALYST_REVIEW
                auto_action = ""

            team = TEAM_ROUTING.get(
                cls.classification,
                "soc-tier1",
            )
            est_min = RESOLUTION_ESTIMATES.get(decision, 30)

            reason = (
                f"cls={cls.classification.value}, conf={score:.2f} -> {decision.value}, team={team}"
            )

            actions.append(
                RoutingAction(
                    id=f"rte-{uuid4().hex[:12]}",
                    alert_id=cls.alert_id,
                    decision=decision,
                    confidence=score,
                    assigned_team=team,
                    estimated_resolution_min=est_min,
                    routing_reason=reason,
                    auto_action_taken=auto_action,
                )
            )

            logger.info(
                "ai_triage.routed",
                alert_id=cls.alert_id,
                decision=decision.value,
                confidence=f"{score:.2f}",
                team=team,
            )

        return actions
