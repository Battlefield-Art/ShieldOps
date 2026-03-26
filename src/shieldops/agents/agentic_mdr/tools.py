"""Tool functions for the Agentic MDR Agent."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()

# Severity ordering for comparisons
_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


class AgenticMDRToolkit:
    """Toolkit bridging Agentic MDR to vendor connectors.

    Supports multi-vendor alert ingestion, cross-vendor
    correlation, confidence-based triage, containment /
    remediation execution, and closed-loop learning.
    """

    def __init__(
        self,
        crowdstrike_client: Any | None = None,
        defender_client: Any | None = None,
        wiz_client: Any | None = None,
        splunk_client: Any | None = None,
        elastic_client: Any | None = None,
        threat_intel: Any | None = None,
        policy_engine: Any | None = None,
        metrics_recorder: Any | None = None,
        learning_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._crowdstrike = crowdstrike_client
        self._defender = defender_client
        self._wiz = wiz_client
        self._splunk = splunk_client
        self._elastic = elastic_client
        self._threat_intel = threat_intel
        self._policy_engine = policy_engine
        self._metrics_recorder = metrics_recorder
        self._learning_store = learning_store
        self._repository = repository
        # In-memory triage feedback ledger
        self._feedback_ledger: list[dict[str, Any]] = []

    # ----------------------------------------------------------
    # Multi-vendor alert ingestion
    # ----------------------------------------------------------

    async def ingest_alerts(
        self,
        vendors: list[str],
        time_range_minutes: int = 60,
        raw_alerts: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Pull alerts from each configured vendor source."""
        all_alerts: list[dict[str, Any]] = []

        # If caller supplies raw alerts, normalize them
        if raw_alerts:
            for raw in raw_alerts:
                all_alerts.append(self._normalize(raw.get("vendor", "unknown"), raw))
            return all_alerts

        for vendor in vendors:
            try:
                fetched = await self._fetch_vendor(vendor, time_range_minutes)
                for raw in fetched:
                    all_alerts.append(self._normalize(vendor, raw))
            except Exception as exc:
                logger.warning(
                    "agentic_mdr.ingest_failed",
                    vendor=vendor,
                    error=str(exc),
                )
        return all_alerts

    async def _fetch_vendor(self, vendor: str, time_range_minutes: int) -> list[dict[str, Any]]:
        """Dispatch to vendor-specific connector."""
        if vendor == "crowdstrike" and self._crowdstrike:
            return await self._crowdstrike.get_detections(
                time_range_minutes=time_range_minutes,
            )
        if vendor == "defender" and self._defender:
            return await self._defender.get_alerts(
                time_range_minutes=time_range_minutes,
            )
        if vendor == "wiz" and self._wiz:
            return await self._wiz.get_issues(
                severity="HIGH",
            )
        if vendor == "splunk" and self._splunk:
            return await self._splunk.get_notable_events(
                time_range_minutes=time_range_minutes,
            )
        if vendor == "elastic" and self._elastic:
            return await self._elastic.get_alerts(
                time_range_minutes=time_range_minutes,
            )
        return []

    # ----------------------------------------------------------
    # Normalization
    # ----------------------------------------------------------

    def _normalize(self, vendor: str, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize raw vendor alert to unified schema."""
        alert_id = f"mdr-{uuid4().hex[:12]}"
        if vendor == "crowdstrike":
            return {
                "alert_id": alert_id,
                "vendor": "crowdstrike",
                "original_id": raw.get("detection_id", ""),
                "severity": raw.get("max_severity_displayname", "medium").lower(),
                "title": raw.get("description", ""),
                "description": raw.get("description", ""),
                "timestamp": raw.get("created_timestamp", ""),
                "source_ip": raw.get("device", {}).get("external_ip", ""),
                "hostname": raw.get("device", {}).get("hostname", ""),
                "user": raw.get("device", {}).get("assigned_to_name", ""),
                "mitre_technique": raw.get("technique_id", ""),
                "confidence": raw.get("confidence", 0) / 100.0,
                "raw_data": raw,
            }
        if vendor == "defender":
            return {
                "alert_id": alert_id,
                "vendor": "defender",
                "original_id": raw.get("alertId", ""),
                "severity": raw.get("severity", "medium").lower(),
                "title": raw.get("title", ""),
                "description": raw.get("description", ""),
                "timestamp": raw.get("createdDateTime", ""),
                "source_ip": raw.get("evidence", {}).get("ipAddress", ""),
                "hostname": raw.get("evidence", {}).get("deviceDnsName", ""),
                "user": raw.get("evidence", {}).get("userAccount", {}).get("accountName", ""),
                "mitre_technique": (
                    raw.get("mitreTechniques", [""])[0] if raw.get("mitreTechniques") else ""
                ),
                "confidence": (0.8 if raw.get("severity") == "high" else 0.5),
                "raw_data": raw,
            }
        if vendor == "splunk":
            return {
                "alert_id": alert_id,
                "vendor": "splunk",
                "original_id": raw.get("event_id", ""),
                "severity": raw.get("urgency", "medium").lower(),
                "title": raw.get("search_name", ""),
                "description": raw.get("description", ""),
                "timestamp": raw.get("_time", ""),
                "source_ip": raw.get("src", ""),
                "destination_ip": raw.get("dest", ""),
                "hostname": raw.get("host", ""),
                "user": raw.get("user", ""),
                "mitre_technique": raw.get("mitre_technique_id", ""),
                "confidence": float(raw.get("confidence", 0.5)),
                "raw_data": raw,
            }
        if vendor == "elastic":
            return {
                "alert_id": alert_id,
                "vendor": "elastic",
                "original_id": raw.get("_id", ""),
                "severity": raw.get("signal", {}).get("rule", {}).get("severity", "medium"),
                "title": raw.get("signal", {}).get("rule", {}).get("name", ""),
                "description": raw.get("signal", {}).get("rule", {}).get("description", ""),
                "timestamp": raw.get("@timestamp", ""),
                "source_ip": raw.get("source", {}).get("ip", ""),
                "hostname": raw.get("host", {}).get("name", ""),
                "user": raw.get("user", {}).get("name", ""),
                "mitre_technique": (
                    raw.get("signal", {})
                    .get("rule", {})
                    .get("threat", [{}])[0]
                    .get("technique", [{}])[0]
                    .get("id", "")
                    if raw.get("signal", {}).get("rule", {}).get("threat")
                    else ""
                ),
                "confidence": float(raw.get("signal", {}).get("rule", {}).get("risk_score", 50))
                / 100.0,
                "raw_data": raw,
            }
        # Generic fallback
        return {
            "alert_id": alert_id,
            "vendor": vendor,
            "original_id": raw.get("id", ""),
            "severity": raw.get("severity", "medium").lower(),
            "title": raw.get("title", ""),
            "description": raw.get("description", ""),
            "timestamp": raw.get("timestamp", ""),
            "source_ip": raw.get("source_ip", ""),
            "hostname": raw.get("hostname", ""),
            "user": raw.get("user", ""),
            "mitre_technique": raw.get("mitre_technique", ""),
            "confidence": float(raw.get("confidence", 0.5)),
            "raw_data": raw,
        }

    # ----------------------------------------------------------
    # Cross-vendor signal correlation
    # ----------------------------------------------------------

    async def correlate_signals(
        self,
        alerts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Correlate alerts across vendors by entity."""
        logger.info(
            "agentic_mdr.correlate",
            alert_count=len(alerts),
        )
        entity_map: dict[str, list[dict[str, Any]]] = {}
        for alert in alerts:
            keys: list[str] = []
            if alert.get("source_ip"):
                keys.append(f"ip:{alert['source_ip']}")
            if alert.get("hostname"):
                keys.append(f"host:{alert['hostname']}")
            if alert.get("user"):
                keys.append(f"user:{alert['user']}")
            for key in keys:
                entity_map.setdefault(key, []).append(alert)

        findings: list[dict[str, Any]] = []
        for entity, group in entity_map.items():
            if len(group) < 2:
                continue
            vendors = list({a.get("vendor", "") for a in group})
            max_sev = max(
                (a.get("severity", "low") for a in group),
                key=lambda s: _SEV_ORDER.index(s) if s in _SEV_ORDER else 0,
            )
            findings.append(
                {
                    "finding_id": f"find-{uuid4().hex[:12]}",
                    "alert_ids": [a.get("alert_id", "") for a in group],
                    "vendors_correlated": vendors,
                    "description": (
                        f"Correlated {len(group)} alerts for {entity} across {', '.join(vendors)}"
                    ),
                    "severity": max_sev,
                    "mitre_techniques": [
                        a.get("mitre_technique", "") for a in group if a.get("mitre_technique")
                    ],
                    "affected_assets": sorted(
                        {a.get("hostname", "") for a in group if a.get("hostname")}
                    ),
                    "ioc_indicators": sorted(
                        {a.get("source_ip", "") for a in group if a.get("source_ip")}
                    ),
                    "confidence": min(1.0, 0.5 + 0.15 * len(vendors)),
                }
            )
        return findings

    # ----------------------------------------------------------
    # Response execution
    # ----------------------------------------------------------

    async def execute_containment(
        self,
        vendor: str,
        target: str,
        action: str,
    ) -> dict[str, Any]:
        """Contain a threat via the appropriate vendor."""
        logger.info(
            "agentic_mdr.contain",
            vendor=vendor,
            target=target,
        )
        if self._policy_engine:
            pol = await self._policy_engine.evaluate(
                action=action,
                target=target,
                vendor=vendor,
            )
            if not pol.get("allowed", True):
                return {
                    "status": "blocked",
                    "reason": pol.get("reason", "policy_denied"),
                }

        if vendor == "crowdstrike" and self._crowdstrike:
            return await self._crowdstrike.contain_host(hostname=target, action=action)
        if vendor == "defender" and self._defender:
            return await self._defender.isolate_device(device_name=target, action=action)
        return {
            "status": "simulated",
            "vendor": vendor,
            "action": action,
            "target": target,
        }

    async def execute_remediation(
        self,
        vendor: str,
        target: str,
        action: str,
    ) -> dict[str, Any]:
        """Remediate via the appropriate vendor."""
        logger.info(
            "agentic_mdr.remediate",
            vendor=vendor,
            target=target,
        )
        if self._policy_engine:
            pol = await self._policy_engine.evaluate(
                action=action,
                target=target,
                vendor=vendor,
            )
            if not pol.get("allowed", True):
                return {
                    "status": "blocked",
                    "reason": pol.get("reason", "policy_denied"),
                }
        return {
            "status": "simulated",
            "vendor": vendor,
            "action": action,
            "target": target,
        }

    # ----------------------------------------------------------
    # Enrichment
    # ----------------------------------------------------------

    async def enrich_with_threat_intel(self, indicators: list[str]) -> dict[str, Any]:
        """Enrich IOCs via threat intel feeds."""
        logger.info(
            "agentic_mdr.enrich",
            indicator_count=len(indicators),
        )
        if self._threat_intel:
            return await self._threat_intel.enrich(indicators)
        return {
            "ioc_matches": [],
            "threat_feeds": [],
            "reputation_scores": {},
            "related_campaigns": [],
        }

    # ----------------------------------------------------------
    # Closed-loop learning
    # ----------------------------------------------------------

    async def record_feedback(
        self,
        alert_id: str,
        original_decision: str,
        actual_outcome: str,
        accuracy_delta: float,
    ) -> dict[str, Any]:
        """Record triage feedback for closed-loop learning.

        Each resolved incident feeds back to improve
        future triage accuracy.
        """
        feedback = {
            "improvement_id": f"imp-{uuid4().hex[:12]}",
            "source_alert_id": alert_id,
            "original_decision": original_decision,
            "actual_outcome": actual_outcome,
            "triage_accuracy_delta": accuracy_delta,
            "rule_update": "",
        }

        # Derive rule adjustments from outcome
        if original_decision == "suppress" and actual_outcome == "true_positive":
            feedback["rule_update"] = "RAISE: suppressed alert was true positive"
            feedback["triage_accuracy_delta"] = -0.1
        elif original_decision == "escalate" and actual_outcome == "false_positive":
            feedback["rule_update"] = "LOWER: escalated alert was false positive"
            feedback["triage_accuracy_delta"] = 0.05

        self._feedback_ledger.append(feedback)

        if self._learning_store:
            await self._learning_store.save(feedback)

        logger.info(
            "agentic_mdr.feedback",
            alert_id=alert_id,
            delta=feedback["triage_accuracy_delta"],
        )
        return feedback

    def get_feedback_ledger(
        self,
    ) -> list[dict[str, Any]]:
        """Return all recorded feedback entries."""
        return list(self._feedback_ledger)

    # ----------------------------------------------------------
    # Metrics
    # ----------------------------------------------------------

    async def record_metric(self, name: str, value: float) -> None:
        """Record an MDR metric."""
        logger.info(
            "agentic_mdr.metric",
            metric=name,
            value=value,
        )
        if self._metrics_recorder:
            await self._metrics_recorder.record(name, value)
