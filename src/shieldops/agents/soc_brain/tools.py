"""Tool functions for the SOC Brain Agent."""

from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()


class SOCBrainToolkit:
    """Toolkit bridging SOC Brain to vendor connectors and security engines."""

    def __init__(
        self,
        crowdstrike_client: Any | None = None,
        defender_client: Any | None = None,
        wiz_client: Any | None = None,
        threat_intel: Any | None = None,
        mitre_mapper: Any | None = None,
        soar_engine: Any | None = None,
        policy_engine: Any | None = None,
        situation_store: Any | None = None,
        metrics_recorder: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._crowdstrike = crowdstrike_client
        self._defender = defender_client
        self._wiz = wiz_client
        self._threat_intel = threat_intel
        self._mitre_mapper = mitre_mapper
        self._soar_engine = soar_engine
        self._policy_engine = policy_engine
        self._situation_store = situation_store
        self._metrics_recorder = metrics_recorder
        self._repository = repository

    async def ingest_from_crowdstrike(
        self, filter_query: str = "", time_range_minutes: int = 60
    ) -> list[dict[str, Any]]:
        """Pull recent detections from CrowdStrike Falcon."""
        logger.info(
            "soc_brain.ingest_crowdstrike",
            filter_query=filter_query,
            time_range_minutes=time_range_minutes,
        )
        if self._crowdstrike:
            return await self._crowdstrike.get_detections(
                filter_query=filter_query,
                time_range_minutes=time_range_minutes,
            )
        return []

    async def ingest_from_defender(self, time_range_minutes: int = 60) -> list[dict[str, Any]]:
        """Pull recent alerts from Microsoft Defender."""
        logger.info(
            "soc_brain.ingest_defender",
            time_range_minutes=time_range_minutes,
        )
        if self._defender:
            return await self._defender.get_alerts(
                time_range_minutes=time_range_minutes,
            )
        return []

    async def ingest_from_wiz(self, severity: str = "HIGH") -> list[dict[str, Any]]:
        """Pull recent issues from Wiz cloud security."""
        logger.info("soc_brain.ingest_wiz", severity=severity)
        if self._wiz:
            return await self._wiz.get_issues(severity=severity)
        return []

    async def normalize_event(self, vendor: str, raw_event: dict[str, Any]) -> dict[str, Any]:
        """Normalize a raw vendor event to the common schema."""
        logger.info("soc_brain.normalize_event", vendor=vendor)
        event_id = f"evt-{uuid4().hex[:12]}"

        # Vendor-specific field mapping
        if vendor == "crowdstrike":
            return {
                "event_id": event_id,
                "vendor": "crowdstrike",
                "original_id": raw_event.get("detection_id", ""),
                "event_type": raw_event.get("tactic", "unknown"),
                "severity": raw_event.get("max_severity_displayname", "medium").lower(),
                "timestamp": raw_event.get("created_timestamp", ""),
                "source_ip": raw_event.get("device", {}).get("external_ip", ""),
                "hostname": raw_event.get("device", {}).get("hostname", ""),
                "user": raw_event.get("device", {}).get("assigned_to_name", ""),
                "description": raw_event.get("description", ""),
                "mitre_technique": raw_event.get("technique_id", ""),
                "confidence": raw_event.get("confidence", 0) / 100.0,
                "raw_data": raw_event,
            }
        elif vendor == "defender":
            return {
                "event_id": event_id,
                "vendor": "defender",
                "original_id": raw_event.get("alertId", ""),
                "event_type": raw_event.get("category", "unknown"),
                "severity": raw_event.get("severity", "medium").lower(),
                "timestamp": raw_event.get("createdDateTime", ""),
                "source_ip": raw_event.get("evidence", {}).get("ipAddress", ""),
                "hostname": raw_event.get("evidence", {}).get("deviceDnsName", ""),
                "user": raw_event.get("evidence", {}).get("userAccount", {}).get("accountName", ""),
                "description": raw_event.get("title", ""),
                "mitre_technique": raw_event.get("mitreTechniques", [""])[0]
                if raw_event.get("mitreTechniques")
                else "",
                "confidence": 0.8 if raw_event.get("severity") == "high" else 0.5,
                "raw_data": raw_event,
            }
        elif vendor == "wiz":
            return {
                "event_id": event_id,
                "vendor": "wiz",
                "original_id": raw_event.get("id", ""),
                "event_type": raw_event.get("type", "misconfiguration"),
                "severity": raw_event.get("severity", "medium").lower(),
                "timestamp": raw_event.get("createdAt", ""),
                "source_ip": "",
                "hostname": raw_event.get("entitySnapshot", {}).get("name", ""),
                "user": "",
                "description": raw_event.get("title", ""),
                "mitre_technique": "",
                "confidence": 0.9 if raw_event.get("severity") == "CRITICAL" else 0.6,
                "raw_data": raw_event,
            }
        else:
            return {
                "event_id": event_id,
                "vendor": vendor,
                "original_id": raw_event.get("id", ""),
                "event_type": raw_event.get("type", "unknown"),
                "severity": raw_event.get("severity", "medium").lower(),
                "timestamp": raw_event.get("timestamp", ""),
                "description": raw_event.get("description", ""),
                "raw_data": raw_event,
            }

    async def correlate_events(
        self,
        events: list[dict[str, Any]],
        time_window_minutes: int = 30,
    ) -> list[dict[str, Any]]:
        """Cross-vendor correlation by entity (IP, hostname, user)."""
        logger.info(
            "soc_brain.correlate_events",
            event_count=len(events),
            time_window=time_window_minutes,
        )
        # Group by shared entities
        entity_groups: dict[str, list[dict[str, Any]]] = {}
        for event in events:
            keys = []
            if event.get("source_ip"):
                keys.append(f"ip:{event['source_ip']}")
            if event.get("hostname"):
                keys.append(f"host:{event['hostname']}")
            if event.get("user"):
                keys.append(f"user:{event['user']}")
            for key in keys:
                entity_groups.setdefault(key, []).append(event)

        # Build correlations from multi-event groups
        correlations: list[dict[str, Any]] = []
        for entity_key, group in entity_groups.items():
            if len(group) < 2:
                continue
            vendors = list({e.get("vendor", "") for e in group})
            if len(vendors) < 2:
                # Single-vendor correlation is less interesting but still valid
                pass
            finding_id = f"find-{uuid4().hex[:12]}"
            correlations.append(
                {
                    "finding_id": finding_id,
                    "event_ids": [e.get("event_id", "") for e in group],
                    "vendors": vendors,
                    "correlation_type": "entity_match",
                    "description": f"Multiple events for {entity_key} across {', '.join(vendors)}",
                    "severity": max(
                        (e.get("severity", "low") for e in group),
                        key=lambda s: (
                            ["info", "low", "medium", "high", "critical"].index(s)
                            if s in ["info", "low", "medium", "high", "critical"]
                            else 0
                        ),
                    ),
                    "confidence": min(1.0, 0.5 + 0.15 * len(vendors)),
                    "mitre_techniques": [
                        e.get("mitre_technique", "") for e in group if e.get("mitre_technique")
                    ],
                    "affected_assets": list(
                        {e.get("hostname", "") for e in group if e.get("hostname")}
                    ),
                }
            )

        return correlations

    async def create_situation(
        self,
        findings: list[dict[str, Any]],
        severity: str,
        title: str = "",
        description: str = "",
    ) -> dict[str, Any]:
        """Create an actionable situation from correlated findings."""
        situation_id = f"sit-{uuid4().hex[:12]}"
        logger.info(
            "soc_brain.create_situation",
            situation_id=situation_id,
            finding_count=len(findings),
            severity=severity,
        )
        all_vendors: set[str] = set()
        all_assets: set[str] = set()
        all_techniques: list[str] = []
        total_events = 0
        for f in findings:
            all_vendors.update(f.get("vendors", []))
            all_assets.update(f.get("affected_assets", []))
            all_techniques.extend(f.get("mitre_techniques", []))
            total_events += len(f.get("event_ids", []))

        situation = {
            "situation_id": situation_id,
            "title": title,
            "description": description,
            "severity": severity,
            "status": "new",
            "finding_ids": [f.get("finding_id", "") for f in findings],
            "vendor_sources": sorted(all_vendors),
            "mitre_techniques": list(set(all_techniques)),
            "affected_assets": sorted(all_assets),
            "correlated_event_count": total_events,
            "created_at": "",
            "updated_at": "",
        }

        if self._situation_store:
            await self._situation_store.save(situation)

        return situation

    async def execute_containment(
        self,
        vendor: str,
        target: str,
        action: str,
    ) -> dict[str, Any]:
        """Execute containment via the appropriate vendor connector."""
        logger.info(
            "soc_brain.execute_containment",
            vendor=vendor,
            target=target,
            action=action,
        )
        # Check policy first
        if self._policy_engine:
            policy_result = await self._policy_engine.evaluate(
                action=action, target=target, vendor=vendor
            )
            if not policy_result.get("allowed", True):
                return {
                    "status": "blocked",
                    "reason": policy_result.get("reason", "policy_denied"),
                }

        if vendor == "crowdstrike" and self._crowdstrike:
            return await self._crowdstrike.contain_host(hostname=target, action=action)
        elif vendor == "defender" and self._defender:
            return await self._defender.isolate_device(device_name=target, action=action)
        elif vendor == "wiz" and self._wiz:
            return await self._wiz.remediate_issue(resource=target, action=action)

        return {"status": "simulated", "vendor": vendor, "action": action, "target": target}

    async def execute_remediation(
        self,
        vendor: str,
        target: str,
        action: str,
    ) -> dict[str, Any]:
        """Execute remediation via the appropriate vendor connector."""
        logger.info(
            "soc_brain.execute_remediation",
            vendor=vendor,
            target=target,
            action=action,
        )
        if self._policy_engine:
            policy_result = await self._policy_engine.evaluate(
                action=action, target=target, vendor=vendor
            )
            if not policy_result.get("allowed", True):
                return {
                    "status": "blocked",
                    "reason": policy_result.get("reason", "policy_denied"),
                }

        return {"status": "simulated", "vendor": vendor, "action": action, "target": target}

    async def enrich_with_threat_intel(self, indicators: list[str]) -> dict[str, Any]:
        """Enrich indicators with threat intelligence."""
        logger.info("soc_brain.enrich_threat_intel", indicator_count=len(indicators))
        if self._threat_intel:
            return await self._threat_intel.enrich(indicators)
        return {
            "ioc_matches": [],
            "threat_feeds": [],
            "reputation_scores": {},
            "related_campaigns": [],
        }

    async def record_metric(self, metric_type: str, value: float) -> None:
        """Record a SOC metric (MTTD, MTTA, MTTR)."""
        logger.info("soc_brain.record_metric", metric_type=metric_type, value=value)
        if self._metrics_recorder:
            await self._metrics_recorder.record(metric_type, value)
