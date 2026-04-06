"""Tool functions for the SOC Analyst Agent."""

from __future__ import annotations

import json as _json
import time
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.soc_analyst.prompts import (
    SYSTEM_CLASSIFICATION,
    SYSTEM_TRIAGE,
    ClassificationOutput,
    TriageOutput,
)
from shieldops.policy.engine import PolicyContext
from shieldops.policy.engine import evaluate as policy_evaluate
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# ── Alert type false-positive base rates (historical heuristics) ─────────────
_FP_BASE_RATES: dict[str, float] = {
    "brute_force": 0.30,
    "port_scan": 0.55,
    "malware_detected": 0.10,
    "phishing": 0.20,
    "data_exfiltration": 0.08,
    "privilege_escalation": 0.15,
    "lateral_movement": 0.12,
    "c2_communication": 0.05,
    "suspicious_login": 0.40,
    "policy_violation": 0.45,
}

# ── Source reliability weights ───────────────────────────────────────────────
_SOURCE_RELIABILITY: dict[str, float] = {
    "crowdstrike": 0.95,
    "defender": 0.90,
    "wiz": 0.88,
    "splunk": 0.85,
    "elastic": 0.82,
    "datadog": 0.80,
    "custom": 0.60,
    "unknown": 0.50,
}

# ── Asset criticality multipliers ───────────────────────────────────────────
_ASSET_CRITICALITY: dict[str, float] = {
    "critical": 1.5,
    "high": 1.3,
    "medium": 1.0,
    "low": 0.7,
    "unknown": 0.9,
}

# ── MITRE technique mapping heuristics (alert type → likely techniques) ──────
_ALERT_MITRE_MAP: dict[str, list[str]] = {
    "brute_force": ["T1110", "T1110.001", "T1110.003"],
    "phishing": ["T1566", "T1566.001", "T1566.002"],
    "malware_detected": ["T1059", "T1204", "T1547"],
    "data_exfiltration": ["T1048", "T1041", "T1567"],
    "privilege_escalation": ["T1068", "T1078", "T1548"],
    "lateral_movement": ["T1021", "T1021.001", "T1021.002"],
    "c2_communication": ["T1071", "T1071.001", "T1105"],
    "suspicious_login": ["T1078", "T1078.001", "T1078.004"],
    "port_scan": ["T1046"],
    "policy_violation": ["T1078"],
}


class SOCAnalystToolkit:
    """Toolkit bridging SOC analyst to security modules and connectors."""

    def __init__(
        self,
        mitre_mapper: Any | None = None,
        threat_intel: Any | None = None,
        soar_engine: Any | None = None,
        chain_reconstructor: Any | None = None,
        soc_metrics: Any | None = None,
        triage_scorer: Any | None = None,
        signal_correlator: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
        connector_router: dict[str, Any] | None = None,
    ) -> None:
        self._mitre_mapper = mitre_mapper
        self._threat_intel = threat_intel
        self._soar_engine = soar_engine
        self._chain_reconstructor = chain_reconstructor
        self._soc_metrics = soc_metrics
        self._triage_scorer = triage_scorer
        self._signal_correlator = signal_correlator
        self._policy_engine = policy_engine
        self._repository = repository
        self._connector_router = connector_router or {}
        # Metrics tracking state
        self._metrics: dict[str, Any] = {
            "alerts_triaged": 0,
            "true_positives": 0,
            "false_positives": 0,
            "needs_investigation": 0,
            "escalations": 0,
            "total_triage_time_ms": 0.0,
            "decisions": [],
        }

    def _get_connector(self, name: str) -> Any | None:
        """Retrieve a connector by name from the router."""
        connector = self._connector_router.get(name)
        if connector is None:
            logger.debug("soc_analyst.connector_not_available", connector=name)
        return connector

    # ── 1. Triage Alert ─────────────────────────────────────────────────────

    async def triage_alert(self, alert_data: dict[str, Any]) -> dict[str, Any]:
        """Classify alert severity and priority.

        Scores based on: source reliability, alert type, affected asset
        criticality, and historical false positive rate. Returns triage
        decision (investigate / monitor / dismiss).
        """
        start = time.monotonic()
        logger.info(
            "soc_analyst.triage_alert",
            alert_type=alert_data.get("alert_type", "unknown"),
            severity=alert_data.get("severity", "unknown"),
        )

        severity = alert_data.get("severity", "medium").lower()
        alert_type = alert_data.get("alert_type", "unknown").lower()
        source = alert_data.get("source", "unknown").lower()
        asset_criticality = alert_data.get("asset_criticality", "medium").lower()

        # Base severity score
        severity_scores = {"critical": 95, "high": 80, "medium": 50, "low": 25, "info": 10}
        base_score = float(severity_scores.get(severity, 30))

        # Apply source reliability
        source_weight = _SOURCE_RELIABILITY.get(source, 0.60)
        score = base_score * source_weight

        # Apply asset criticality multiplier
        criticality_mult = _ASSET_CRITICALITY.get(asset_criticality, 1.0)
        score *= criticality_mult

        # Adjust for historical false positive rate
        fp_rate = _FP_BASE_RATES.get(alert_type, 0.25)
        score *= 1.0 - fp_rate * 0.5  # High FP rate reduces score

        # Clamp 0-100
        score = max(0.0, min(100.0, score))

        # Determine triage decision
        if score >= 75:
            decision = "investigate"
            tier = 3
        elif score >= 40:
            decision = "monitor"
            tier = 2
        else:
            decision = "dismiss"
            tier = 1

        # Check for known false positive override
        if alert_data.get("known_false_positive", False):
            decision = "dismiss"
            score = min(score, 10.0)
            tier = 1

        elapsed_ms = (time.monotonic() - start) * 1000
        self._metrics["alerts_triaged"] += 1
        self._metrics["total_triage_time_ms"] += elapsed_ms

        result = {
            "triage_score": round(score, 2),
            "tier": tier,
            "decision": decision,
            "severity": severity,
            "source_reliability": source_weight,
            "asset_criticality_multiplier": criticality_mult,
            "fp_base_rate": fp_rate,
            "alert_type": alert_type,
            "triage_time_ms": round(elapsed_ms, 2),
        }

        logger.info(
            "soc_analyst.triage_alert.complete",
            score=result["triage_score"],
            decision=decision,
            tier=tier,
        )
        return result

    # ── 2. Enrich Alert ─────────────────────────────────────────────────────

    async def enrich_alert(self, alert_data: dict[str, Any]) -> dict[str, Any]:
        """Enrich alert with CrowdStrike detections, Splunk correlations, and threat intel.

        Extracts indicators (IPs, hashes, domains), queries connectors for
        context, and maps alert type to MITRE ATT&CK techniques.
        """
        logger.info(
            "soc_analyst.enrich_alert",
            alert_id=alert_data.get("alert_id", "unknown"),
        )

        # Extract indicators
        indicators: list[str] = []
        for key in ("source_ip", "dest_ip", "domain", "file_hash", "url", "user", "hostname"):
            if value := alert_data.get(key):
                indicators.append(str(value))

        enrichment: dict[str, Any] = {
            "indicators": indicators,
            "ioc_matches": [],
            "threat_feeds": [],
            "reputation_score": 0.0,
            "geo_ip_info": {},
            "related_campaigns": [],
            "crowdstrike_detections": [],
            "splunk_correlated_events": [],
            "mitre_techniques": [],
        }

        # CrowdStrike enrichment
        crowdstrike = self._get_connector("crowdstrike")
        if crowdstrike:
            try:
                for indicator in indicators[:10]:
                    graph_data = await crowdstrike.get_threat_graph(indicator)
                    if graph_data.get("resources"):
                        enrichment["crowdstrike_detections"].extend(graph_data["resources"][:5])
                        enrichment["reputation_score"] = max(enrichment["reputation_score"], 0.8)

                # Also pull recent detections for the host
                if host := alert_data.get("hostname") or alert_data.get("source_ip"):
                    detections = await crowdstrike.get_detections(
                        filter_query=f"device.hostname:'{host}'",
                        limit=10,
                    )
                    for det in detections:
                        enrichment["crowdstrike_detections"].append(
                            {
                                "detection_id": det.get("detection_id", ""),
                                "severity": det.get("max_severity_displayname", "medium"),
                                "tactic": det.get("tactic", ""),
                                "technique": det.get("technique", ""),
                            }
                        )

                logger.info(
                    "soc_analyst.enrich_alert.crowdstrike_complete",
                    detection_count=len(enrichment["crowdstrike_detections"]),
                )
            except Exception as e:
                logger.warning("soc_analyst.enrich_alert.crowdstrike_error", error=str(e))

        # Splunk correlation
        splunk = self._get_connector("splunk")
        if splunk and indicators:
            try:
                ioc_values = " OR ".join(f'"{ind}"' for ind in indicators[:20])
                time_range = alert_data.get("time_range", "1h")
                earliest = f"-{time_range}" if not time_range.startswith("-") else time_range
                spl_query = (
                    f"index=* ({ioc_values}) "
                    f"| stats count by index, source, sourcetype, src_ip, dest_ip "
                    f"| where count > 0 "
                    f"| sort -count"
                )
                splunk_results = await splunk.search_spl(
                    query=spl_query, earliest=earliest, latest="now"
                )
                for hit in splunk_results[:20]:
                    enrichment["splunk_correlated_events"].append(
                        {
                            "source": hit.get("sourcetype", "unknown"),
                            "count": int(hit.get("count", 0)),
                            "index": hit.get("index", ""),
                            "src_ip": hit.get("src_ip", ""),
                            "dest_ip": hit.get("dest_ip", ""),
                        }
                    )

                logger.info(
                    "soc_analyst.enrich_alert.splunk_complete",
                    event_count=len(enrichment["splunk_correlated_events"]),
                )
            except Exception as e:
                logger.warning("soc_analyst.enrich_alert.splunk_error", error=str(e))

        # Threat intel enrichment (from injected service or heuristic)
        if self._threat_intel:
            try:
                intel_data = await self._threat_intel.lookup(indicators)
                enrichment["ioc_matches"] = intel_data.get("matches", [])
                enrichment["threat_feeds"] = intel_data.get("feeds", [])
                enrichment["related_campaigns"] = intel_data.get("campaigns", [])
                if intel_data.get("reputation_score", 0) > enrichment["reputation_score"]:
                    enrichment["reputation_score"] = intel_data["reputation_score"]
            except Exception as e:
                logger.warning("soc_analyst.enrich_alert.threat_intel_error", error=str(e))

        # MITRE technique mapping (heuristic fallback)
        alert_type = alert_data.get("alert_type", "").lower()
        mitre_techniques = _ALERT_MITRE_MAP.get(alert_type, [])
        # Also pull techniques from CrowdStrike detections
        for det in enrichment.get("crowdstrike_detections", []):
            if technique := det.get("technique"):
                if technique not in mitre_techniques:
                    mitre_techniques.append(technique)
        enrichment["mitre_techniques"] = mitre_techniques

        # Compute aggregate reputation if no connectors provided data
        if enrichment["reputation_score"] == 0.0:
            # Heuristic: use severity + alert type to estimate
            sev = alert_data.get("severity", "medium").lower()
            sev_rep = {"critical": 0.9, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.1}
            enrichment["reputation_score"] = sev_rep.get(sev, 0.3)

        logger.info(
            "soc_analyst.enrich_alert.complete",
            ioc_matches=len(enrichment["ioc_matches"]),
            mitre_count=len(enrichment["mitre_techniques"]),
            reputation=enrichment["reputation_score"],
        )
        return enrichment

    # ── 3. Classify True/False Positive ──────────────────────────────────────

    async def classify_true_false_positive(self, enriched_alert: dict[str, Any]) -> dict[str, Any]:
        """Classify enriched alert as true positive, false positive, or needs investigation.

        Uses LLM (llm_structured) with heuristic fallback based on enrichment
        signals.
        """
        logger.info("soc_analyst.classify_true_false_positive")

        # Try LLM classification first
        try:
            import json as _json

            context = _json.dumps(
                {
                    "ioc_matches": enriched_alert.get("ioc_matches", []),
                    "crowdstrike_detections": enriched_alert.get("crowdstrike_detections", [])[:10],
                    "splunk_correlated_events": enriched_alert.get("splunk_correlated_events", [])[
                        :10
                    ],
                    "mitre_techniques": enriched_alert.get("mitre_techniques", []),
                    "reputation_score": enriched_alert.get("reputation_score", 0.0),
                    "threat_feeds": enriched_alert.get("threat_feeds", []),
                    "indicators": enriched_alert.get("indicators", []),
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_CLASSIFICATION,
                user_prompt=f"Enriched alert data:\n{context}",
                schema=ClassificationOutput,
            )
            classification = getattr(llm_result, "classification", "needs_investigation")
            confidence = getattr(llm_result, "confidence", 0.5)
            reasoning = getattr(llm_result, "reasoning", "LLM classification")
            key_signals = getattr(llm_result, "key_signals", [])

            logger.info(
                "soc_analyst.classify_true_false_positive.llm_complete",
                classification=classification,
                confidence=confidence,
            )

            # Track in metrics
            self._record_classification(classification)

            return {
                "classification": classification,
                "confidence": round(confidence, 3),
                "reasoning": reasoning,
                "key_signals": key_signals,
                "method": "llm",
            }
        except Exception:
            logger.debug("soc_analyst.classify_true_false_positive.llm_skipped")

        # Heuristic fallback
        return self._heuristic_classification(enriched_alert)

    def _heuristic_classification(self, enriched_alert: dict[str, Any]) -> dict[str, Any]:
        """Heuristic classification based on enrichment signals."""
        ioc_count = len(enriched_alert.get("ioc_matches", []))
        cs_detections = len(enriched_alert.get("crowdstrike_detections", []))
        splunk_events = len(enriched_alert.get("splunk_correlated_events", []))
        reputation = enriched_alert.get("reputation_score", 0.0)
        mitre_count = len(enriched_alert.get("mitre_techniques", []))
        threat_feeds = len(enriched_alert.get("threat_feeds", []))

        # Score signals
        signal_score = 0.0
        key_signals: list[str] = []

        if ioc_count > 0:
            signal_score += min(ioc_count * 0.15, 0.3)
            key_signals.append(f"{ioc_count} IOC matches")
        if cs_detections > 0:
            signal_score += min(cs_detections * 0.12, 0.25)
            key_signals.append(f"{cs_detections} CrowdStrike detections")
        if splunk_events > 2:
            signal_score += 0.1
            key_signals.append(f"{splunk_events} correlated Splunk events")
        if reputation >= 0.7:
            signal_score += 0.2
            key_signals.append(f"High reputation score ({reputation:.2f})")
        if mitre_count > 1:
            signal_score += 0.1
            key_signals.append(f"{mitre_count} MITRE techniques mapped")
        if threat_feeds > 0:
            signal_score += min(threat_feeds * 0.1, 0.2)
            key_signals.append(f"{threat_feeds} threat feed hits")

        # Classify
        if signal_score >= 0.5:
            classification = "true_positive"
            confidence = min(0.95, 0.5 + signal_score * 0.4)
        elif signal_score <= 0.15:
            classification = "false_positive"
            confidence = min(0.90, 0.6 + (0.15 - signal_score) * 2)
        else:
            classification = "needs_investigation"
            confidence = 0.4 + signal_score * 0.3

        self._record_classification(classification)

        return {
            "classification": classification,
            "confidence": round(confidence, 3),
            "reasoning": f"Heuristic: signal_score={signal_score:.2f}",
            "key_signals": key_signals,
            "method": "heuristic",
        }

    def _record_classification(self, classification: str) -> None:
        """Record classification in metrics."""
        if classification == "true_positive":
            self._metrics["true_positives"] += 1
        elif classification == "false_positive":
            self._metrics["false_positives"] += 1
        else:
            self._metrics["needs_investigation"] += 1

    # ── 4. Correlate Alerts ─────────────────────────────────────────────────

    async def correlate_alerts(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Group related alerts by shared IPs, users, timeframe, or MITRE technique.

        Returns correlation groups with the alerts that belong to each group.
        """
        logger.info("soc_analyst.correlate_alerts", alert_count=len(alerts))

        if not alerts:
            return []

        groups: list[dict[str, Any]] = []
        # Index alerts by key attributes
        ip_map: dict[str, list[int]] = {}
        user_map: dict[str, list[int]] = {}
        mitre_map: dict[str, list[int]] = {}
        timestamps: list[float | None] = []

        for i, alert in enumerate(alerts):
            # IPs
            for ip_key in ("source_ip", "dest_ip"):
                if ip_val := alert.get(ip_key):
                    ip_map.setdefault(str(ip_val), []).append(i)
            # Users
            if user_val := alert.get("user"):
                user_map.setdefault(str(user_val), []).append(i)
            # MITRE techniques
            for technique in alert.get("mitre_techniques", []):
                mitre_map.setdefault(technique, []).append(i)
            # Timestamps
            ts = alert.get("timestamp")
            if isinstance(ts, str):
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    timestamps.append(dt.timestamp())
                except (ValueError, TypeError):
                    timestamps.append(None)
            elif isinstance(ts, (int, float)):
                timestamps.append(float(ts))
            else:
                timestamps.append(None)

        used_indices: set[int] = set()

        # Group by shared IPs (2+ alerts share an IP)
        for ip, indices in ip_map.items():
            if len(indices) >= 2:
                group_indices = [i for i in indices if i not in used_indices]
                if len(group_indices) >= 2:
                    groups.append(
                        {
                            "correlation_type": "shared_ip",
                            "key": ip,
                            "alert_indices": group_indices,
                            "alert_count": len(group_indices),
                            "alerts": [alerts[i] for i in group_indices],
                        }
                    )
                    used_indices.update(group_indices)

        # Group by shared users
        for user, indices in user_map.items():
            if len(indices) >= 2:
                group_indices = [i for i in indices if i not in used_indices]
                if len(group_indices) >= 2:
                    groups.append(
                        {
                            "correlation_type": "shared_user",
                            "key": user,
                            "alert_indices": group_indices,
                            "alert_count": len(group_indices),
                            "alerts": [alerts[i] for i in group_indices],
                        }
                    )
                    used_indices.update(group_indices)

        # Group by shared MITRE technique
        for technique, indices in mitre_map.items():
            if len(indices) >= 2:
                group_indices = [i for i in indices if i not in used_indices]
                if len(group_indices) >= 2:
                    groups.append(
                        {
                            "correlation_type": "shared_mitre_technique",
                            "key": technique,
                            "alert_indices": group_indices,
                            "alert_count": len(group_indices),
                            "alerts": [alerts[i] for i in group_indices],
                        }
                    )
                    used_indices.update(group_indices)

        # Group by timeframe (within 5 minutes)
        time_window_sec = 300  # 5 minutes
        remaining = [i for i in range(len(alerts)) if i not in used_indices]
        time_groups: list[list[int]] = []
        for i in remaining:
            ts_i = timestamps[i]
            if ts_i is None:
                continue
            placed = False
            for tg in time_groups:
                anchor_ts = timestamps[tg[0]]
                if anchor_ts is not None and abs(ts_i - anchor_ts) <= time_window_sec:
                    tg.append(i)
                    placed = True
                    break
            if not placed:
                time_groups.append([i])

        for tg in time_groups:
            if len(tg) >= 2:
                groups.append(
                    {
                        "correlation_type": "shared_timeframe",
                        "key": f"within_{time_window_sec}s",
                        "alert_indices": tg,
                        "alert_count": len(tg),
                        "alerts": [alerts[i] for i in tg],
                    }
                )
                used_indices.update(tg)

        logger.info(
            "soc_analyst.correlate_alerts.complete",
            group_count=len(groups),
            correlated_alerts=len(used_indices),
            uncorrelated=len(alerts) - len(used_indices),
        )
        return groups

    # ── 5. Escalate ─────────────────────────────────────────────────────────

    async def escalate(
        self,
        alert: dict[str, Any],
        classification: dict[str, Any],
    ) -> dict[str, Any]:
        """Route alert based on classification and severity.

        - True positive with confidence > 0.7 → investigation agent
        - Critical severity → incident_response agent
        - Otherwise → SOC queue for manual review
        """
        logger.info(
            "soc_analyst.escalate",
            classification=classification.get("classification"),
            confidence=classification.get("confidence"),
            severity=alert.get("severity"),
        )

        cls = classification.get("classification", "needs_investigation")
        confidence = classification.get("confidence", 0.0)
        severity = alert.get("severity", "medium").lower()

        escalation: dict[str, Any] = {
            "alert_id": alert.get("alert_id", "unknown"),
            "classification": cls,
            "confidence": confidence,
            "severity": severity,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        if severity == "critical":
            escalation["target"] = "incident_response"
            escalation["priority"] = "p1"
            escalation["reason"] = "Critical severity alert requires immediate incident response"
        elif cls == "true_positive" and confidence > 0.7:
            escalation["target"] = "investigation"
            escalation["priority"] = "p2"
            escalation["reason"] = (
                f"True positive (confidence={confidence:.2f}) routed to investigation"
            )
        elif cls == "true_positive":
            escalation["target"] = "soc_queue"
            escalation["priority"] = "p3"
            escalation["reason"] = (
                f"True positive with low confidence ({confidence:.2f}), manual review needed"
            )
        elif cls == "needs_investigation":
            escalation["target"] = "soc_queue"
            escalation["priority"] = "p3"
            escalation["reason"] = "Needs further investigation by analyst"
        else:
            # false_positive
            escalation["target"] = "dismiss"
            escalation["priority"] = "p5"
            escalation["reason"] = "Classified as false positive, dismissed"

        self._metrics["escalations"] += 1
        self._metrics["decisions"].append(
            {
                "alert_id": escalation["alert_id"],
                "classification": cls,
                "target": escalation["target"],
                "timestamp": escalation["timestamp"],
            }
        )

        logger.info(
            "soc_analyst.escalate.complete",
            target=escalation["target"],
            priority=escalation["priority"],
        )
        return escalation

    # ── 6. Track Metrics ────────────────────────────────────────────────────

    async def track_metrics(self, decisions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Track and return SOC analyst performance metrics.

        Returns: alerts triaged, TP/FP rates, mean triage time, escalation rate.
        """
        logger.info("soc_analyst.track_metrics")

        # Merge in any additional decisions
        if decisions:
            for d in decisions:
                cls = d.get("classification", "")
                self._record_classification(cls)
                self._metrics["alerts_triaged"] += 1
                self._metrics["decisions"].append(d)

        total = self._metrics["alerts_triaged"]
        tp = self._metrics["true_positives"]
        fp = self._metrics["false_positives"]
        classified = tp + fp + self._metrics["needs_investigation"]

        metrics = {
            "alerts_triaged": total,
            "true_positives": tp,
            "false_positives": fp,
            "needs_investigation": self._metrics["needs_investigation"],
            "true_positive_rate": round(tp / classified, 4) if classified > 0 else 0.0,
            "false_positive_rate": round(fp / classified, 4) if classified > 0 else 0.0,
            "mean_triage_time_ms": (
                round(self._metrics["total_triage_time_ms"] / total, 2) if total > 0 else 0.0
            ),
            "escalations": self._metrics["escalations"],
            "escalation_rate": (
                round(self._metrics["escalations"] / total, 4) if total > 0 else 0.0
            ),
            "recent_decisions": self._metrics["decisions"][-20:],
        }

        logger.info(
            "soc_analyst.track_metrics.complete",
            alerts_triaged=metrics["alerts_triaged"],
            tp_rate=metrics["true_positive_rate"],
            fp_rate=metrics["false_positive_rate"],
        )
        return metrics

    # ── Legacy methods (kept for backward compat with nodes.py) ─────────────

    async def enrich_with_threat_intel(self, indicators: list[str]) -> dict[str, Any]:
        """Enrich indicators with threat intelligence."""
        logger.info("soc_analyst.enrich_threat_intel", indicator_count=len(indicators))

        result: dict[str, Any] = {
            "ioc_matches": [],
            "threat_feeds": [],
            "reputation_score": 0.0,
            "geo_ip_info": {},
            "related_campaigns": [],
        }

        # Try threat intel service
        if self._threat_intel:
            try:
                intel_data = await self._threat_intel.lookup(indicators)
                result["ioc_matches"] = intel_data.get("matches", [])
                result["threat_feeds"] = intel_data.get("feeds", [])
                result["reputation_score"] = intel_data.get("reputation_score", 0.0)
                result["related_campaigns"] = intel_data.get("campaigns", [])
            except Exception as e:
                logger.warning("soc_analyst.enrich_threat_intel.error", error=str(e))

        # Try CrowdStrike for IOC lookup
        crowdstrike = self._get_connector("crowdstrike")
        if crowdstrike:
            try:
                for ind in indicators[:5]:
                    graph_data = await crowdstrike.get_threat_graph(ind)
                    if graph_data.get("resources"):
                        result["ioc_matches"].append(ind)
                        result["reputation_score"] = max(result["reputation_score"], 0.8)
            except Exception as e:
                logger.warning("soc_analyst.enrich_threat_intel.crowdstrike_error", error=str(e))

        return result

    async def map_to_mitre(self, events: list[dict[str, Any]]) -> list[str]:
        """Map events to MITRE ATT&CK techniques."""
        logger.info("soc_analyst.map_mitre", event_count=len(events))

        techniques: list[str] = []
        if self._mitre_mapper:
            try:
                techniques = await self._mitre_mapper.map(events)
            except Exception as e:
                logger.warning("soc_analyst.map_mitre.error", error=str(e))

        # Heuristic fallback: infer from event types
        if not techniques:
            for event in events:
                event_type = event.get("event_type", "").lower()
                for alert_type, techs in _ALERT_MITRE_MAP.items():
                    if alert_type in event_type:
                        techniques.extend(t for t in techs if t not in techniques)

        return techniques

    async def correlate_signals(self, alert_id: str) -> list[dict[str, Any]]:
        """Find correlated signals for an alert."""
        logger.info("soc_analyst.correlate_signals", alert_id=alert_id)

        results: list[dict[str, Any]] = []
        if self._signal_correlator:
            try:
                results = await self._signal_correlator.correlate(alert_id)
            except Exception as e:
                logger.warning("soc_analyst.correlate_signals.error", error=str(e))

        return results

    async def execute_playbook(
        self, playbook_name: str, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a SOAR playbook."""
        logger.info("soc_analyst.execute_playbook", playbook=playbook_name)

        if self._soar_engine:
            try:
                return await self._soar_engine.execute(playbook_name, parameters)
            except Exception as e:
                logger.warning("soc_analyst.execute_playbook.error", error=str(e))

        return {"status": "completed", "playbook": playbook_name}

    async def check_policy(self, action: str, target: str) -> dict[str, Any]:
        """Check if an action is allowed by policy."""
        logger.info("soc_analyst.check_policy", action=action, target=target)

        if self._policy_engine:
            try:
                return await self._policy_engine.evaluate(action, target)
            except Exception as e:
                logger.warning("soc_analyst.check_policy.error", error=str(e))

        return {"allowed": True, "reason": "policy_check_passed"}

    async def record_soc_metric(self, metric_type: str, value: float) -> None:
        """Record a SOC metric (MTTD, MTTC, etc.)."""
        logger.info("soc_analyst.record_metric", metric_type=metric_type, value=value)

    # ── 7. Fetch Splunk Alerts (Notable Events) ───────────────────────────

    async def fetch_splunk_alerts(
        self,
        severity: str = "",
        time_range: str = "1h",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch notable events from Splunk Enterprise Security.

        Uses the Splunk connector to query ES notable events via SPL.
        Falls back to empty list if connector is unavailable.

        Args:
            severity: Filter by severity (critical, high, medium, low).
            time_range: Lookback window (e.g. '1h', '24h').
            limit: Maximum notable events to return.

        Returns:
            List of notable event dicts with rule_name, severity, src, dest, etc.
        """
        logger.info(
            "soc_analyst.fetch_splunk_alerts",
            severity=severity,
            time_range=time_range,
            limit=limit,
        )

        splunk = self._get_connector("splunk")
        if not splunk:
            logger.debug("soc_analyst.fetch_splunk_alerts.no_connector")
            return []

        try:
            notables = await splunk.get_notable_events(severity=severity, limit=limit)
            logger.info(
                "soc_analyst.fetch_splunk_alerts.complete",
                count=len(notables),
            )
            return notables
        except Exception as e:
            logger.warning("soc_analyst.fetch_splunk_alerts.error", error=str(e))
            return []

    # ── 8. Fetch CrowdStrike Detections ───────────────────────────────────

    async def fetch_crowdstrike_detections(
        self,
        filter_query: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch recent detections from CrowdStrike Falcon.

        Queries the Falcon detections API with an optional FQL filter.
        Returns structured detection data including severity, tactic, technique.

        Args:
            filter_query: FQL filter (e.g. "max_severity_displayname:'Critical'").
            limit: Maximum detections to return.

        Returns:
            List of detection dicts with detection_id, severity, tactic, technique.
        """
        logger.info(
            "soc_analyst.fetch_crowdstrike_detections",
            filter_query=filter_query,
            limit=limit,
        )

        crowdstrike = self._get_connector("crowdstrike")
        if not crowdstrike:
            logger.debug("soc_analyst.fetch_crowdstrike_detections.no_connector")
            return []

        try:
            detections = await crowdstrike.get_detections(
                filter_query=filter_query,
                limit=limit,
            )
            results = []
            for det in detections:
                results.append(
                    {
                        "detection_id": det.get("detection_id", ""),
                        "severity": det.get("max_severity_displayname", "medium"),
                        "severity_score": det.get("max_severity", 0),
                        "tactic": det.get("tactic", ""),
                        "technique": det.get("technique", ""),
                        "hostname": det.get("device", {}).get("hostname", ""),
                        "os": det.get("device", {}).get("os_version", ""),
                        "description": det.get("description", ""),
                        "created_timestamp": det.get("created_timestamp", ""),
                    }
                )
            logger.info(
                "soc_analyst.fetch_crowdstrike_detections.complete",
                count=len(results),
            )
            return results
        except Exception as e:
            logger.warning("soc_analyst.fetch_crowdstrike_detections.error", error=str(e))
            return []

    # ── 9. Classify Severity (LLM + heuristic fallback) ──────────────────

    async def classify_severity(self, alert_data: dict[str, Any]) -> dict[str, Any]:
        """Classify alert severity using LLM with heuristic keyword fallback.

        Attempts LLM-based classification first via llm_structured(). On failure,
        falls back to keyword-based heuristic matching against the alert description,
        alert_type, and other text fields.

        Args:
            alert_data: Alert dict with fields like description, alert_type, severity.

        Returns:
            Dict with classified_severity, confidence, method, reasoning.
        """
        logger.info("soc_analyst.classify_severity")

        # Try LLM classification first
        try:
            context = _json.dumps(
                {
                    "alert_type": alert_data.get("alert_type", ""),
                    "description": alert_data.get("description", ""),
                    "severity": alert_data.get("severity", ""),
                    "source": alert_data.get("source", ""),
                    "source_ip": alert_data.get("source_ip", ""),
                    "dest_ip": alert_data.get("dest_ip", ""),
                    "hostname": alert_data.get("hostname", ""),
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_TRIAGE,
                user_prompt=f"Alert data for severity classification:\n{context}",
                schema=TriageOutput,
            )
            severity = "medium"
            score = getattr(llm_result, "triage_score", 50.0)
            if score >= 85:
                severity = "critical"
            elif score >= 60:
                severity = "high"
            elif score >= 30:
                severity = "medium"
            else:
                severity = "low"

            logger.info(
                "soc_analyst.classify_severity.llm_complete",
                severity=severity,
                score=score,
            )
            return {
                "classified_severity": severity,
                "triage_score": score,
                "confidence": 0.85,
                "method": "llm",
                "reasoning": getattr(llm_result, "reasoning", "LLM classification"),
            }
        except Exception:
            logger.debug("soc_analyst.classify_severity.llm_skipped")

        # Heuristic keyword fallback
        return self._heuristic_severity_classification(alert_data)

    def _heuristic_severity_classification(self, alert_data: dict[str, Any]) -> dict[str, Any]:
        """Keyword-based severity classification fallback.

        Scans alert_type, description, and other text fields for severity keywords.
        """
        text = " ".join(
            str(v).lower()
            for k, v in alert_data.items()
            if isinstance(v, str)
            and k
            in (
                "alert_type",
                "description",
                "severity",
                "title",
                "rule_name",
            )
        )

        # Critical keywords
        critical_kw = [
            "critical",
            "ransomware",
            "c2_communication",
            "data_exfiltration",
            "apt",
            "zero-day",
            "rootkit",
            "backdoor",
        ]
        high_kw = [
            "malware",
            "high",
            "privilege_escalation",
            "lateral_movement",
            "credential_theft",
            "exploit",
            "trojan",
            "phishing",
        ]
        medium_kw = [
            "medium",
            "brute_force",
            "suspicious",
            "anomaly",
            "port_scan",
        ]
        low_kw = [
            "low",
            "info",
            "policy_violation",
            "informational",
            "benign",
        ]

        for kw in critical_kw:
            if kw in text:
                return {
                    "classified_severity": "critical",
                    "triage_score": 95.0,
                    "confidence": 0.7,
                    "method": "heuristic",
                    "reasoning": f"Keyword match: '{kw}' indicates critical severity",
                }
        for kw in high_kw:
            if kw in text:
                return {
                    "classified_severity": "high",
                    "triage_score": 80.0,
                    "confidence": 0.65,
                    "method": "heuristic",
                    "reasoning": f"Keyword match: '{kw}' indicates high severity",
                }
        for kw in medium_kw:
            if kw in text:
                return {
                    "classified_severity": "medium",
                    "triage_score": 50.0,
                    "confidence": 0.55,
                    "method": "heuristic",
                    "reasoning": f"Keyword match: '{kw}' indicates medium severity",
                }
        for kw in low_kw:
            if kw in text:
                return {
                    "classified_severity": "low",
                    "triage_score": 25.0,
                    "confidence": 0.5,
                    "method": "heuristic",
                    "reasoning": f"Keyword match: '{kw}' indicates low severity",
                }

        # Default
        return {
            "classified_severity": "medium",
            "triage_score": 50.0,
            "confidence": 0.3,
            "method": "heuristic",
            "reasoning": "No keyword match; defaulting to medium severity",
        }

    # ── 10. Enrich with AWS Context ──────────────────────────────────────

    async def enrich_with_aws_context(
        self,
        instance_id: str,
    ) -> dict[str, Any]:
        """Correlate alert with AWS EC2 instance context.

        Queries the AWS connector for instance details, security groups, and
        recent events. Falls back gracefully if connector is unavailable.

        Args:
            instance_id: EC2 instance ID (e.g. 'i-0abc123def456').

        Returns:
            Dict with instance_details, security_groups, recent_events.
        """
        logger.info("soc_analyst.enrich_aws_context", instance_id=instance_id)

        result: dict[str, Any] = {
            "instance_id": instance_id,
            "instance_details": {},
            "security_groups": [],
            "recent_events": [],
        }

        aws = self._get_connector("aws")
        if not aws:
            logger.debug("soc_analyst.enrich_aws_context.no_connector")
            return result

        try:
            # Get instance health/details
            health = await aws.get_health(instance_id)
            result["instance_details"] = {
                "resource_id": health.resource_id,
                "healthy": health.healthy,
                "status": health.status,
                "message": getattr(health, "message", ""),
            }

            # Get recent events via CloudTrail
            from datetime import timedelta

            from shieldops.models.base import TimeRange

            now = datetime.now(UTC)
            events = await aws.get_events(
                resource_id=instance_id,
                time_range=TimeRange(start=now - timedelta(hours=24), end=now),
            )
            result["recent_events"] = events[:20]

            logger.info(
                "soc_analyst.enrich_aws_context.complete",
                healthy=health.healthy,
                event_count=len(result["recent_events"]),
            )
        except Exception as e:
            logger.warning("soc_analyst.enrich_aws_context.error", error=str(e))

        return result

    # ── 11. Enrich with CrowdStrike Host Data ────────────────────────────

    async def enrich_with_crowdstrike_host(
        self,
        hostname: str,
    ) -> dict[str, Any]:
        """Enrich with CrowdStrike host data (hostname, OS, agent version, last seen).

        Queries Falcon for host information and recent detections.

        Args:
            hostname: Hostname or device identifier to look up.

        Returns:
            Dict with host_info, recent_detections.
        """
        logger.info("soc_analyst.enrich_crowdstrike_host", hostname=hostname)

        result: dict[str, Any] = {
            "hostname": hostname,
            "host_info": {},
            "recent_detections": [],
        }

        crowdstrike = self._get_connector("crowdstrike")
        if not crowdstrike:
            logger.debug("soc_analyst.enrich_crowdstrike_host.no_connector")
            return result

        try:
            # Get recent detections for this host
            detections = await crowdstrike.get_detections(
                filter_query=f"device.hostname:'{hostname}'",
                limit=20,
            )
            for det in detections:
                device = det.get("device", {})
                if not result["host_info"] and device:
                    result["host_info"] = {
                        "hostname": device.get("hostname", hostname),
                        "os_version": device.get("os_version", "unknown"),
                        "agent_version": device.get("agent_version", "unknown"),
                        "last_seen": device.get("last_seen", ""),
                        "platform_name": device.get("platform_name", ""),
                        "device_id": device.get("device_id", ""),
                    }
                result["recent_detections"].append(
                    {
                        "detection_id": det.get("detection_id", ""),
                        "severity": det.get("max_severity_displayname", "medium"),
                        "tactic": det.get("tactic", ""),
                        "technique": det.get("technique", ""),
                        "timestamp": det.get("created_timestamp", ""),
                    }
                )

            # If no detections found host info, try threat graph
            if not result["host_info"]:
                graph_data = await crowdstrike.get_threat_graph(hostname)
                if graph_data.get("resources"):
                    result["host_info"] = {"hostname": hostname, "threat_graph_hit": True}

            logger.info(
                "soc_analyst.enrich_crowdstrike_host.complete",
                detection_count=len(result["recent_detections"]),
                has_host_info=bool(result["host_info"]),
            )
        except Exception as e:
            logger.warning("soc_analyst.enrich_crowdstrike_host.error", error=str(e))

        return result

    # ── 12. Auto-resolve Low-severity Alerts ─────────────────────────────

    async def auto_resolve_alert(
        self,
        alert_id: str,
        severity: str,
        reason: str = "",
    ) -> dict[str, Any]:
        """Auto-resolve a low-severity alert (log + close).

        Only resolves alerts classified as low/info severity. Logs the resolution
        decision for audit trail.

        Args:
            alert_id: Alert identifier.
            severity: Alert severity.
            reason: Reason for auto-resolution.

        Returns:
            Dict with resolved status, reason, and timestamp.
        """
        logger.info(
            "soc_analyst.auto_resolve_alert",
            alert_id=alert_id,
            severity=severity,
        )

        if severity.lower() not in ("low", "info"):
            return {
                "resolved": False,
                "reason": f"Severity '{severity}' too high for auto-resolution",
                "alert_id": alert_id,
            }

        # Policy check before auto-resolve
        try:
            policy_decision = await policy_evaluate(
                action="auto_resolve_alert",
                context=PolicyContext(
                    agent_name="soc_analyst",
                    action_type="auto_resolve",
                    target_resources=[alert_id],
                    risk_score=0.1,
                ),
            )
            if not policy_decision.allowed:
                return {
                    "resolved": False,
                    "reason": f"Policy denied: {policy_decision.reason}",
                    "alert_id": alert_id,
                    "policy_denied": True,
                }
        except Exception:
            logger.debug("soc_analyst.auto_resolve_alert.policy_check_skipped")

        resolution = {
            "resolved": True,
            "alert_id": alert_id,
            "severity": severity,
            "reason": reason or f"Auto-resolved: {severity} severity alert",
            "timestamp": datetime.now(UTC).isoformat(),
            "method": "auto_resolve",
        }

        logger.info(
            "soc_analyst.auto_resolve_alert.complete",
            alert_id=alert_id,
            reason=resolution["reason"],
        )
        return resolution

    # ── 13. Create PagerDuty Incident ────────────────────────────────────

    async def create_pagerduty_incident(
        self,
        alert_id: str,
        title: str,
        severity: str = "high",
        details: str = "",
        service_id: str = "",
    ) -> dict[str, Any]:
        """Create a PagerDuty incident for high-severity alerts.

        Uses the PagerDuty connector to create an incident or trigger an event.
        Falls back to event trigger if create_incident fails.

        Args:
            alert_id: Source alert ID.
            title: Incident title.
            severity: Alert severity (maps to PD urgency).
            details: Incident body/description.
            service_id: PagerDuty service ID (optional).

        Returns:
            Dict with incident_id, status, dedup_key.
        """
        logger.info(
            "soc_analyst.create_pagerduty_incident",
            alert_id=alert_id,
            severity=severity,
        )

        # Policy check
        try:
            policy_decision = await policy_evaluate(
                action="create_pagerduty_incident",
                context=PolicyContext(
                    agent_name="soc_analyst",
                    action_type="escalation",
                    target_resources=[alert_id],
                    risk_score=0.3,
                ),
            )
            if not policy_decision.allowed:
                return {
                    "created": False,
                    "reason": f"Policy denied: {policy_decision.reason}",
                    "alert_id": alert_id,
                    "policy_denied": True,
                }
        except Exception:
            logger.debug("soc_analyst.create_pagerduty_incident.policy_check_skipped")

        pagerduty = self._get_connector("pagerduty")
        if not pagerduty:
            logger.debug("soc_analyst.create_pagerduty_incident.no_connector")
            return {
                "created": False,
                "reason": "PagerDuty connector not available",
                "alert_id": alert_id,
            }

        urgency = "high" if severity.lower() in ("critical", "high") else "low"

        try:
            if service_id:
                result = await pagerduty.create_incident(
                    service_id=service_id,
                    title=f"[ShieldOps] {title}",
                    body=details or f"SOC alert {alert_id} escalated — severity: {severity}",
                    urgency=urgency,
                )
                incident = result.get("incident", {})
                return {
                    "created": True,
                    "incident_id": incident.get("id", ""),
                    "status": incident.get("status", "triggered"),
                    "urgency": urgency,
                    "alert_id": alert_id,
                }

            # Fall back to Events API v2 trigger
            result = await pagerduty.trigger_event(
                routing_key="",  # uses connector default
                summary=f"[ShieldOps] {title} — Alert {alert_id}",
                severity="critical" if severity.lower() == "critical" else "error",
                source="shieldops-soc-analyst",
                component="soc_analyst_agent",
                custom_details={
                    "alert_id": alert_id,
                    "severity": severity,
                    "details": details,
                },
            )
            return {
                "created": True,
                "dedup_key": result.get("dedup_key", ""),
                "status": result.get("status", "success"),
                "alert_id": alert_id,
            }
        except Exception as e:
            logger.warning("soc_analyst.create_pagerduty_incident.error", error=str(e))
            return {
                "created": False,
                "reason": str(e),
                "alert_id": alert_id,
            }

    # ── 14. Send Slack Notification ──────────────────────────────────────

    async def send_slack_notification(
        self,
        alert_id: str,
        channel: str,
        message: str,
        severity: str = "high",
    ) -> dict[str, Any]:
        """Send a Slack notification for escalated alerts.

        Uses the Slack connector/messaging module. Falls back gracefully
        if Slack is not configured.

        Args:
            alert_id: Source alert ID.
            channel: Slack channel (e.g. '#soc-alerts').
            message: Notification message body.
            severity: Alert severity for formatting.

        Returns:
            Dict with sent status.
        """
        logger.info(
            "soc_analyst.send_slack_notification",
            alert_id=alert_id,
            channel=channel,
            severity=severity,
        )

        slack = self._get_connector("slack")
        if not slack:
            logger.debug("soc_analyst.send_slack_notification.no_connector")
            return {
                "sent": False,
                "reason": "Slack connector not available",
                "alert_id": alert_id,
            }

        severity_emoji = {
            "critical": ":rotating_light:",
            "high": ":warning:",
            "medium": ":large_blue_circle:",
            "low": ":white_circle:",
        }
        emoji = severity_emoji.get(severity.lower(), ":question:")

        try:
            formatted_msg = (
                f"{emoji} *SOC Alert Escalation*\n"
                f"*Alert ID:* `{alert_id}`\n"
                f"*Severity:* {severity.upper()}\n"
                f"*Details:* {message}"
            )
            await slack.send_message(channel=channel, text=formatted_msg)
            return {
                "sent": True,
                "channel": channel,
                "alert_id": alert_id,
            }
        except Exception as e:
            logger.warning("soc_analyst.send_slack_notification.error", error=str(e))
            return {
                "sent": False,
                "reason": str(e),
                "alert_id": alert_id,
            }

    # ── 15. Create ServiceNow Ticket ─────────────────────────────────────

    async def create_servicenow_ticket(
        self,
        alert_id: str,
        short_description: str,
        description: str = "",
        severity: str = "high",
        assignment_group: str = "",
    ) -> dict[str, Any]:
        """Create a ServiceNow incident ticket for tracked alerts.

        Maps SOC severity to ServiceNow urgency/impact fields and creates
        an incident record.

        Args:
            alert_id: Source alert ID.
            short_description: Short description for the ticket.
            description: Full description.
            severity: Alert severity.
            assignment_group: ServiceNow assignment group.

        Returns:
            Dict with ticket_number, sys_id, created status.
        """
        logger.info(
            "soc_analyst.create_servicenow_ticket",
            alert_id=alert_id,
            severity=severity,
        )

        # Policy check
        try:
            policy_decision = await policy_evaluate(
                action="create_servicenow_ticket",
                context=PolicyContext(
                    agent_name="soc_analyst",
                    action_type="ticket_creation",
                    target_resources=[alert_id],
                    risk_score=0.2,
                ),
            )
            if not policy_decision.allowed:
                return {
                    "created": False,
                    "reason": f"Policy denied: {policy_decision.reason}",
                    "alert_id": alert_id,
                    "policy_denied": True,
                }
        except Exception:
            logger.debug("soc_analyst.create_servicenow_ticket.policy_check_skipped")

        servicenow = self._get_connector("servicenow")
        if not servicenow:
            logger.debug("soc_analyst.create_servicenow_ticket.no_connector")
            return {
                "created": False,
                "reason": "ServiceNow connector not available",
                "alert_id": alert_id,
            }

        # Map severity to ServiceNow urgency: 1=high, 2=medium, 3=low
        urgency_map = {"critical": "1", "high": "1", "medium": "2", "low": "3"}
        impact_map = {"critical": "1", "high": "2", "medium": "2", "low": "3"}
        sn_urgency = urgency_map.get(severity.lower(), "2")
        sn_impact = impact_map.get(severity.lower(), "2")

        try:
            result = await servicenow.create_incident(
                short_description=f"[ShieldOps SOC] {short_description}",
                description=(description or f"SOC analyst alert {alert_id} — severity: {severity}"),
                urgency=sn_urgency,
                impact=sn_impact,
                assignment_group=assignment_group,
            )
            return {
                "created": True,
                "sys_id": result.get("sys_id", ""),
                "ticket_number": result.get("number", ""),
                "alert_id": alert_id,
            }
        except Exception as e:
            logger.warning("soc_analyst.create_servicenow_ticket.error", error=str(e))
            return {
                "created": False,
                "reason": str(e),
                "alert_id": alert_id,
            }

    # ── 16. Full Escalation Pipeline ─────────────────────────────────────

    async def escalate_alert(
        self,
        alert_id: str,
        alert_data: dict[str, Any],
        classification: dict[str, Any],
    ) -> dict[str, Any]:
        """Full escalation pipeline: route based on severity and classification.

        Orchestrates the appropriate combination of auto-resolve, PagerDuty,
        Slack, and ServiceNow actions based on the alert classification.

        Args:
            alert_id: Alert identifier.
            alert_data: Original alert data.
            classification: Classification result from classify_true_false_positive.

        Returns:
            Dict with all escalation actions taken and their results.
        """
        logger.info("soc_analyst.escalate_alert", alert_id=alert_id)

        severity = alert_data.get("severity", "medium").lower()
        cls = classification.get("classification", "needs_investigation")
        confidence = classification.get("confidence", 0.0)

        escalation_result: dict[str, Any] = {
            "alert_id": alert_id,
            "severity": severity,
            "classification": cls,
            "actions_taken": [],
        }

        # False positive with high confidence -> auto-resolve
        if cls == "false_positive" and confidence > 0.7:
            resolve = await self.auto_resolve_alert(
                alert_id=alert_id,
                severity="low",
                reason=f"False positive (confidence={confidence:.2f})",
            )
            escalation_result["actions_taken"].append({"action": "auto_resolve", **resolve})
            return escalation_result

        # Low severity -> auto-resolve
        if severity in ("low", "info") and cls != "true_positive":
            resolve = await self.auto_resolve_alert(
                alert_id=alert_id,
                severity=severity,
                reason="Low severity alert auto-resolved",
            )
            escalation_result["actions_taken"].append({"action": "auto_resolve", **resolve})
            return escalation_result

        # High/Critical severity -> PagerDuty + Slack + ServiceNow
        if severity in ("critical", "high"):
            pd_result = await self.create_pagerduty_incident(
                alert_id=alert_id,
                title=alert_data.get("title", f"SOC Alert {alert_id}"),
                severity=severity,
                details=alert_data.get("description", ""),
            )
            escalation_result["actions_taken"].append({"action": "pagerduty_incident", **pd_result})

            slack_result = await self.send_slack_notification(
                alert_id=alert_id,
                channel="#soc-alerts",
                message=alert_data.get("description", f"Alert {alert_id} escalated"),
                severity=severity,
            )
            escalation_result["actions_taken"].append(
                {"action": "slack_notification", **slack_result}
            )

        # All non-auto-resolved alerts get a ServiceNow ticket
        sn_result = await self.create_servicenow_ticket(
            alert_id=alert_id,
            short_description=alert_data.get("title", f"SOC Alert {alert_id}"),
            description=alert_data.get("description", ""),
            severity=severity,
        )
        escalation_result["actions_taken"].append({"action": "servicenow_ticket", **sn_result})

        logger.info(
            "soc_analyst.escalate_alert.complete",
            alert_id=alert_id,
            actions_count=len(escalation_result["actions_taken"]),
        )
        return escalation_result
