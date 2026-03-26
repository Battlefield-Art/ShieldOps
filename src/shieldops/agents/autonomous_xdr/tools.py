"""Tool functions for the Autonomous XDR Agent.

Multi-vendor telemetry ingestion, OCSF normalization,
cross-domain correlation, MITRE campaign mapping, and
automated investigation — all vendor-neutral.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.autonomous_xdr.models import (
    CampaignDetection,
    CampaignSeverity,
    CrossDomainCorrelation,
    InvestigationResult,
    NormalizedAlert,
    SignalDomain,
    TelemetrySignal,
)

logger = structlog.get_logger()

# ── Vendor catalogue ───────────────────────────────────────

VENDOR_SOURCES: dict[str, dict[str, Any]] = {
    "crowdstrike_falcon": {
        "domain": SignalDomain.ENDPOINT,
        "event_types": [
            "process_creation",
            "dns_request",
            "file_write",
            "network_connection",
            "credential_access",
        ],
        "ocsf_class": "security_finding",
    },
    "microsoft_defender": {
        "domain": SignalDomain.ENDPOINT,
        "event_types": [
            "alert",
            "device_event",
            "email_event",
            "identity_event",
        ],
        "ocsf_class": "security_finding",
    },
    "sentinelone": {
        "domain": SignalDomain.ENDPOINT,
        "event_types": [
            "threat_detected",
            "behavioral_indicator",
            "lateral_movement",
        ],
        "ocsf_class": "security_finding",
    },
    "carbon_black": {
        "domain": SignalDomain.ENDPOINT,
        "event_types": [
            "process_event",
            "netconn_event",
            "filemod_event",
        ],
        "ocsf_class": "security_finding",
    },
    "wiz": {
        "domain": SignalDomain.CLOUD,
        "event_types": [
            "cloud_misconfiguration",
            "vulnerability",
            "toxic_combination",
            "attack_path",
        ],
        "ocsf_class": "cloud_finding",
    },
    "prisma_cloud": {
        "domain": SignalDomain.CLOUD,
        "event_types": [
            "policy_violation",
            "anomaly",
            "runtime_alert",
        ],
        "ocsf_class": "cloud_finding",
    },
    "okta": {
        "domain": SignalDomain.IDENTITY,
        "event_types": [
            "auth_failure",
            "mfa_bypass",
            "session_hijack",
            "privilege_grant",
        ],
        "ocsf_class": "identity_activity",
    },
    "entra_id": {
        "domain": SignalDomain.IDENTITY,
        "event_types": [
            "sign_in_anomaly",
            "risky_user",
            "conditional_access_failure",
            "service_principal_abuse",
        ],
        "ocsf_class": "identity_activity",
    },
    "palo_alto_ngfw": {
        "domain": SignalDomain.NETWORK,
        "event_types": [
            "threat_log",
            "traffic_log",
            "url_filtering",
        ],
        "ocsf_class": "network_activity",
    },
    "proofpoint": {
        "domain": SignalDomain.EMAIL,
        "event_types": [
            "phishing_detected",
            "malicious_attachment",
            "bec_attempt",
        ],
        "ocsf_class": "email_activity",
    },
}

# ── MITRE ATT&CK technique-to-tactic mapping ──────────────

MITRE_KILL_CHAIN: dict[str, dict[str, str]] = {
    "T1566": {
        "name": "Phishing",
        "tactic": "initial_access",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "initial_access",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "execution",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "persistence",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "privilege_escalation",
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "lateral_movement",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "command_and_control",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "exfiltration",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "impact",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "credential_access",
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "persistence",
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "privilege_escalation",
    },
}

# Kill chain ordering for campaign severity assessment
KILL_CHAIN_ORDER = [
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "credential_access",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]


class AutonomousXDRToolkit:
    """Vendor-neutral XDR toolkit.

    Ingests from 10+ vendor sources, normalizes to OCSF,
    correlates across domains, maps MITRE campaigns, and
    runs automated investigations with blast radius.
    """

    def __init__(
        self,
        repository: Any | None = None,
    ) -> None:
        self._repository = repository

    # ── Multi-Vendor Telemetry Ingestion ───────────────

    async def collect_telemetry(
        self,
        domains: list[str] | None = None,
        vendors: list[str] | None = None,
        time_range_hours: int = 24,
    ) -> list[TelemetrySignal]:
        """Ingest telemetry from multiple vendor sources.

        Simulates collection from 6+ vendors across all
        domains. Production wiring calls real connector APIs.
        """
        target_domains = domains or [d.value for d in SignalDomain]
        target_vendors = vendors or list(VENDOR_SOURCES.keys())

        signals: list[TelemetrySignal] = []
        now = datetime.now(UTC)

        for vendor_name in target_vendors:
            meta = VENDOR_SOURCES.get(vendor_name)
            if not meta:
                continue
            domain_val = meta["domain"]
            if domain_val.value not in target_domains:
                continue

            for evt in meta["event_types"]:
                sig = TelemetrySignal(
                    id=f"sig-{uuid4().hex[:8]}",
                    vendor=vendor_name,
                    domain=domain_val,
                    event_type=evt,
                    severity=self._infer_severity(evt),
                    raw_data={
                        "vendor": vendor_name,
                        "event": evt,
                        "time_range_h": time_range_hours,
                    },
                    source_ip=f"10.0.{hash(vendor_name) % 255}.{hash(evt) % 255}",
                    dest_ip="10.0.1.100",
                    user=f"user-{hash(evt) % 100:03d}",
                    asset=f"asset-{hash(vendor_name) % 50:03d}",
                    timestamp=now,
                )
                signals.append(sig)

        logger.info(
            "autonomous_xdr.telemetry_collected",
            signal_count=len(signals),
            vendor_count=len({s.vendor for s in signals}),
            domain_count=len({s.domain.value for s in signals}),
        )
        return signals

    # ── OCSF Normalization ─────────────────────────────

    async def normalize_to_ocsf(
        self,
        signals: list[TelemetrySignal],
    ) -> list[NormalizedAlert]:
        """Normalize raw vendor signals to OCSF schema.

        Maps each vendor's proprietary format to a unified
        OCSF (Open Cybersecurity Schema Framework) model
        for vendor-neutral correlation.
        """
        alerts: list[NormalizedAlert] = []

        for sig in signals:
            vendor_meta = VENDOR_SOURCES.get(sig.vendor, {})
            ocsf_class = vendor_meta.get("ocsf_class", "unknown")
            technique = self._map_to_mitre(sig.event_type)
            tactic = ""
            if technique and technique in MITRE_KILL_CHAIN:
                tactic = MITRE_KILL_CHAIN[technique]["tactic"]

            entities = [
                e
                for e in [
                    sig.source_ip,
                    sig.dest_ip,
                    sig.user,
                    sig.asset,
                ]
                if e
            ]

            alert = NormalizedAlert(
                id=f"alert-{uuid4().hex[:8]}",
                original_signal_id=sig.id,
                vendor=sig.vendor,
                domain=sig.domain,
                ocsf_category="security",
                ocsf_class=ocsf_class,
                severity=sig.severity,
                confidence=self._severity_confidence(sig.severity),
                mitre_technique=technique,
                mitre_tactic=tactic,
                entities=entities,
                description=(f"{sig.vendor}: {sig.event_type}"),
                timestamp=sig.timestamp,
            )
            alerts.append(alert)

        logger.info(
            "autonomous_xdr.ocsf_normalized",
            alert_count=len(alerts),
        )
        return alerts

    # ── Cross-Domain Correlation ───────────────────────

    async def correlate_cross_domain(
        self,
        alerts: list[NormalizedAlert],
    ) -> list[CrossDomainCorrelation]:
        """Correlate alerts across domains via shared entities.

        Finds cross-domain links that single-vendor XDR
        cannot see: endpoint alert + identity anomaly +
        cloud finding = coordinated campaign.
        """
        # Group alerts by entity for overlap detection
        entity_map: dict[str, list[NormalizedAlert]] = {}
        for alert in alerts:
            for entity in alert.entities:
                entity_map.setdefault(entity, []).append(alert)

        correlations: list[CrossDomainCorrelation] = []

        for entity, linked in entity_map.items():
            domains = list({a.domain.value for a in linked})
            if len(domains) < 2:
                continue

            vendors = list({a.vendor for a in linked})
            alert_ids = [a.id for a in linked[:10]]
            tactics = [a.mitre_tactic for a in linked if a.mitre_tactic]
            phase = self._highest_kill_chain(tactics)

            score = min(
                1.0,
                len(domains) * 0.25 + len(vendors) * 0.15 + len(alert_ids) * 0.05,
            )

            corr = CrossDomainCorrelation(
                id=f"corr-{uuid4().hex[:8]}",
                alert_ids=alert_ids,
                domains_involved=domains,
                vendors_involved=vendors,
                shared_entities=[entity],
                correlation_score=round(score, 3),
                kill_chain_phase=phase,
                description=(
                    f"Cross-domain: {entity} seen in {', '.join(domains)} via {', '.join(vendors)}"
                ),
            )
            correlations.append(corr)

        logger.info(
            "autonomous_xdr.correlations_found",
            correlation_count=len(correlations),
        )
        return correlations

    # ── Campaign Detection ─────────────────────────────

    async def detect_campaigns(
        self,
        correlations: list[CrossDomainCorrelation],
        alerts: list[NormalizedAlert],
    ) -> list[CampaignDetection]:
        """Detect multi-stage attack campaigns.

        Groups correlations by kill chain progression
        and identifies coordinated campaigns spanning
        multiple MITRE techniques and domains.
        """
        if not correlations:
            return []

        # Group corrs by kill chain phase
        phase_groups: dict[str, list[CrossDomainCorrelation]] = {}
        for c in correlations:
            phase_groups.setdefault(c.kill_chain_phase, []).append(c)

        # Detect campaigns from phase chains
        campaigns: list[CampaignDetection] = []
        phases_present = [p for p in KILL_CHAIN_ORDER if p in phase_groups]

        if len(phases_present) >= 2:
            all_corr_ids: list[str] = []
            all_assets: set[str] = set()
            all_users: set[str] = set()
            techniques: set[str] = set()

            for phase in phases_present:
                for c in phase_groups[phase]:
                    all_corr_ids.append(c.id)
                    for e in c.shared_entities:
                        if e.startswith("asset-"):
                            all_assets.add(e)
                        elif e.startswith("user-"):
                            all_users.add(e)

            # Gather techniques from alerts
            alert_map = {a.id: a for a in alerts}
            for c in correlations:
                for aid in c.alert_ids:
                    a = alert_map.get(aid)
                    if a and a.mitre_technique:
                        techniques.add(a.mitre_technique)

            severity = self._campaign_severity(phases_present, len(correlations))

            campaign = CampaignDetection(
                id=f"campaign-{uuid4().hex[:8]}",
                name=self._campaign_name(phases_present),
                severity=severity,
                correlation_ids=all_corr_ids[:20],
                mitre_techniques=sorted(techniques),
                kill_chain_stages=phases_present,
                affected_assets=sorted(all_assets)[:20],
                affected_users=sorted(all_users)[:20],
                blast_radius=len(all_assets) + len(all_users),
                confidence=min(
                    1.0,
                    len(phases_present) * 0.2 + len(correlations) * 0.1,
                ),
                description=(
                    f"Multi-stage campaign across "
                    f"{len(phases_present)} kill chain "
                    f"phases: {', '.join(phases_present)}"
                ),
            )
            campaigns.append(campaign)

        logger.info(
            "autonomous_xdr.campaigns_detected",
            campaign_count=len(campaigns),
        )
        return campaigns

    # ── Automated Investigation ────────────────────────

    async def auto_investigate(
        self,
        campaign: CampaignDetection,
        correlations: list[CrossDomainCorrelation],
    ) -> InvestigationResult:
        """Run automated investigation on a campaign.

        Traces entry point, lateral path, and assesses
        blast radius without human intervention.
        """
        # Determine entry point from earliest kill chain
        entry = "unknown"
        if campaign.kill_chain_stages:
            entry = campaign.kill_chain_stages[0]

        # Build lateral path from kill chain
        lateral: list[str] = []
        for stage in campaign.kill_chain_stages:
            lateral.append(
                f"{stage} -> "
                f"{len([c for c in correlations if c.kill_chain_phase == stage])} correlations"
            )

        # Gather all shared entities
        compromised_assets = list(campaign.affected_assets)
        compromised_ids = list(campaign.affected_users)

        # Blast radius assessment
        total = len(compromised_assets) + len(compromised_ids)
        if total > 20:
            blast = "critical — widespread compromise"
        elif total > 10:
            blast = "high — significant lateral spread"
        elif total > 5:
            blast = "medium — contained spread"
        else:
            blast = "low — limited scope"

        actions = self._recommend_actions(campaign)

        urgency = "immediate"
        if campaign.severity == CampaignSeverity.HIGH:
            urgency = "high"
        elif campaign.severity == CampaignSeverity.MEDIUM:
            urgency = "medium"
        elif campaign.severity in (
            CampaignSeverity.LOW,
            CampaignSeverity.INFO,
        ):
            urgency = "low"

        result = InvestigationResult(
            id=f"inv-{uuid4().hex[:8]}",
            campaign_id=campaign.id,
            root_cause=(
                f"Multi-domain attack via {entry} spanning {len(campaign.kill_chain_stages)} phases"
            ),
            entry_point=entry,
            lateral_path=lateral,
            compromised_assets=compromised_assets,
            compromised_identities=compromised_ids,
            blast_radius_assessment=blast,
            recommended_actions=actions,
            containment_urgency=urgency,
            evidence=[
                {
                    "type": "correlation",
                    "id": cid,
                }
                for cid in campaign.correlation_ids[:5]
            ],
        )

        logger.info(
            "autonomous_xdr.investigation_complete",
            campaign_id=campaign.id,
            blast_radius=blast,
            urgency=urgency,
        )
        return result

    # ── Response Execution ─────────────────────────────

    async def execute_response(
        self,
        investigation: InvestigationResult,
    ) -> list[dict[str, Any]]:
        """Execute automated response actions.

        Applies containment based on investigation
        urgency. Production wiring calls real connectors.
        """
        responses: list[dict[str, Any]] = []

        for i, action in enumerate(investigation.recommended_actions[:5]):
            resp = {
                "id": f"resp-{uuid4().hex[:8]}",
                "action": action,
                "status": "executed",
                "target": (
                    investigation.compromised_assets[i]
                    if i < len(investigation.compromised_assets)
                    else "global"
                ),
                "timestamp": datetime.now(UTC).isoformat(),
            }
            responses.append(resp)

        logger.info(
            "autonomous_xdr.responses_executed",
            response_count=len(responses),
        )
        return responses

    async def record_metric(
        self,
        metric_type: str,
        value: float,
    ) -> None:
        """Record an autonomous XDR metric."""
        logger.info(
            "autonomous_xdr.metric",
            metric_type=metric_type,
            value=value,
        )

    # ── Private helpers ────────────────────────────────

    @staticmethod
    def _infer_severity(event_type: str) -> str:
        """Infer severity from event type name."""
        critical_kw = [
            "credential_access",
            "mfa_bypass",
            "session_hijack",
            "exfiltration",
            "ransomware",
            "service_principal_abuse",
        ]
        high_kw = [
            "lateral_movement",
            "privilege_grant",
            "threat_detected",
            "phishing",
            "bec_attempt",
            "attack_path",
            "risky_user",
        ]
        for kw in critical_kw:
            if kw in event_type:
                return "critical"
        for kw in high_kw:
            if kw in event_type:
                return "high"
        return "medium"

    @staticmethod
    def _severity_confidence(severity: str) -> float:
        """Map severity to base confidence."""
        return {
            "critical": 0.95,
            "high": 0.80,
            "medium": 0.60,
            "low": 0.40,
            "info": 0.20,
        }.get(severity, 0.50)

    @staticmethod
    def _map_to_mitre(event_type: str) -> str:
        """Map event type to MITRE technique ID."""
        mapping: dict[str, str] = {
            "phishing_detected": "T1566",
            "credential_access": "T1110",
            "mfa_bypass": "T1078",
            "lateral_movement": "T1021",
            "dns_request": "T1071",
            "file_write": "T1059",
            "process_creation": "T1059",
            "network_connection": "T1071",
            "privilege_grant": "T1078",
            "session_hijack": "T1078",
            "auth_failure": "T1110",
            "sign_in_anomaly": "T1078",
            "service_principal_abuse": "T1136",
            "attack_path": "T1068",
            "malicious_attachment": "T1566",
            "bec_attempt": "T1566",
        }
        return mapping.get(event_type, "")

    @staticmethod
    def _highest_kill_chain(
        tactics: list[str],
    ) -> str:
        """Return the highest kill chain phase."""
        if not tactics:
            return "unknown"
        for phase in reversed(KILL_CHAIN_ORDER):
            if phase in tactics:
                return phase
        return tactics[0] if tactics else "unknown"

    @staticmethod
    def _campaign_severity(
        phases: list[str],
        corr_count: int,
    ) -> CampaignSeverity:
        """Assess campaign severity from phases."""
        late_phases = {
            "exfiltration",
            "impact",
            "command_and_control",
        }
        if any(p in late_phases for p in phases):
            return CampaignSeverity.CRITICAL
        if len(phases) >= 4 or corr_count >= 10:
            return CampaignSeverity.HIGH
        if len(phases) >= 2:
            return CampaignSeverity.MEDIUM
        return CampaignSeverity.LOW

    @staticmethod
    def _campaign_name(phases: list[str]) -> str:
        """Generate a descriptive campaign name."""
        if "impact" in phases:
            return "Destructive Multi-Stage Campaign"
        if "exfiltration" in phases:
            return "Data Exfiltration Campaign"
        if "lateral_movement" in phases:
            return "Lateral Movement Campaign"
        if "privilege_escalation" in phases:
            return "Privilege Escalation Campaign"
        return "Multi-Domain Intrusion Campaign"

    @staticmethod
    def _recommend_actions(
        campaign: CampaignDetection,
    ) -> list[str]:
        """Generate containment recommendations."""
        actions: list[str] = []
        if campaign.affected_users:
            actions.append("Disable compromised user accounts")
            actions.append("Force MFA re-enrollment for affected identities")
        if campaign.affected_assets:
            actions.append("Isolate affected endpoints from network")
        if "exfiltration" in campaign.kill_chain_stages:
            actions.append("Block exfiltration channels (DNS, HTTP tunnels)")
        if "persistence" in campaign.kill_chain_stages:
            actions.append("Remove persistence mechanisms (scheduled tasks, new accounts)")
        actions.append("Rotate all credentials for affected scope")
        actions.append("Deploy enhanced monitoring on affected segments")
        return actions
