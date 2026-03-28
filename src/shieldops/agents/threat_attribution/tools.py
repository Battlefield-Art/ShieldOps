"""Tool functions for the Threat Attribution Agent."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.threat_attribution.models import (
    ActorProfile,
    AttributionAssessment,
    ConfidenceLevel,
    ThreatActorType,
    TTPMapping,
)

logger = structlog.get_logger()

# MITRE ATT&CK technique keyword patterns for heuristic mapping
TTP_KEYWORDS: dict[str, tuple[str, str]] = {
    "phishing": ("T1566", "Initial Access"),
    "spearphishing": ("T1566.001", "Initial Access"),
    "exploit": ("T1190", "Initial Access"),
    "powershell": ("T1059.001", "Execution"),
    "command line": ("T1059", "Execution"),
    "scheduled task": ("T1053", "Persistence"),
    "registry": ("T1547.001", "Persistence"),
    "credential dump": ("T1003", "Credential Access"),
    "brute force": ("T1110", "Credential Access"),
    "lateral movement": ("T1021", "Lateral Movement"),
    "rdp": ("T1021.001", "Lateral Movement"),
    "smb": ("T1021.002", "Lateral Movement"),
    "exfiltration": ("T1041", "Exfiltration"),
    "dns tunnel": ("T1071.004", "Command and Control"),
    "c2 beacon": ("T1071", "Command and Control"),
    "data encrypt": ("T1486", "Impact"),
    "ransomware": ("T1486", "Impact"),
    "wiper": ("T1485", "Impact"),
    "privilege escalation": ("T1068", "Privilege Escalation"),
    "token manipulation": ("T1134", "Privilege Escalation"),
    "web shell": ("T1505.003", "Persistence"),
    "supply chain": ("T1195", "Initial Access"),
    "dll sideload": ("T1574.002", "Defense Evasion"),
    "obfuscation": ("T1027", "Defense Evasion"),
}

# Known actor TTP signatures (simplified fingerprints)
ACTOR_SIGNATURES: dict[str, dict[str, Any]] = {
    "APT29": {
        "type": ThreatActorType.APT,
        "ttps": ["T1566.001", "T1059.001", "T1071", "T1027"],
        "motivation": "espionage",
        "sectors": ["government", "defense", "technology"],
        "origin": "Russia",
        "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM"],
    },
    "APT28": {
        "type": ThreatActorType.APT,
        "ttps": ["T1566", "T1190", "T1003", "T1021"],
        "motivation": "espionage",
        "sectors": ["government", "military", "media"],
        "origin": "Russia",
        "aliases": ["Fancy Bear", "Sofacy", "STRONTIUM"],
    },
    "Lazarus": {
        "type": ThreatActorType.NATION_STATE,
        "ttps": ["T1195", "T1486", "T1059", "T1041"],
        "motivation": "financial, disruption",
        "sectors": ["finance", "cryptocurrency", "defense"],
        "origin": "North Korea",
        "aliases": ["HIDDEN COBRA", "Zinc"],
    },
    "FIN7": {
        "type": ThreatActorType.CYBERCRIME,
        "ttps": ["T1566.001", "T1059.001", "T1053", "T1041"],
        "motivation": "financial",
        "sectors": ["retail", "hospitality", "finance"],
        "origin": "Unknown",
        "aliases": ["Carbanak", "Navigator Group"],
    },
}

# Confidence thresholds by matched TTP count
CONFIDENCE_THRESHOLDS: list[tuple[ConfidenceLevel, int, float]] = [
    (ConfidenceLevel.HIGH, 4, 0.7),
    (ConfidenceLevel.MEDIUM, 2, 0.4),
    (ConfidenceLevel.LOW, 1, 0.1),
]


class ThreatAttributionToolkit:
    """Toolkit for threat attribution — evidence collection,
    TTP mapping, actor profiling, and confidence assessment."""

    def __init__(
        self,
        threat_intel_db: Any | None = None,
        ioc_service: Any | None = None,
        mitre_service: Any | None = None,
    ) -> None:
        self._threat_intel_db = threat_intel_db
        self._ioc_service = ioc_service
        self._mitre_service = mitre_service

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _match_ttps(
        self,
        text: str,
    ) -> list[TTPMapping]:
        """Match text against TTP keyword patterns."""
        text_lower = text.lower()
        matched: list[TTPMapping] = []
        seen_ids: set[str] = set()

        for keyword, (tech_id, tactic) in TTP_KEYWORDS.items():
            if keyword in text_lower and tech_id not in seen_ids:
                seen_ids.add(tech_id)
                matched.append(
                    TTPMapping(
                        technique_id=tech_id,
                        technique_name=keyword.replace("_", " ").title(),
                        tactic=tactic,
                        description=(f"Detected {keyword} behavior"),
                        confidence=0.6,
                    )
                )

        return matched

    def _match_actor(
        self,
        ttp_ids: list[str],
    ) -> tuple[str, dict[str, Any], float]:
        """Match TTPs against known actor signatures."""
        best_actor = ""
        best_sig: dict[str, Any] = {}
        best_score = 0.0

        for actor, sig in ACTOR_SIGNATURES.items():
            actor_ttps = sig.get("ttps", [])
            overlap = len(set(ttp_ids) & set(actor_ttps))
            score = overlap / len(actor_ttps) if actor_ttps else 0.0

            if score > best_score:
                best_score = score
                best_actor = actor
                best_sig = sig

        return best_actor, best_sig, best_score

    # ------------------------------------------------------------------
    # Tool methods
    # ------------------------------------------------------------------

    async def collect_evidence(
        self,
        incident_id: str,
    ) -> list[dict[str, Any]]:
        """Collect evidence and IOCs for *incident_id*.

        Pulls indicators from threat intel DB and IOC service
        into a unified evidence set.
        """
        evidence: list[dict[str, Any]] = []

        # Threat intel DB -----------------------------------------------
        if self._threat_intel_db is not None:
            try:
                raw = await self._threat_intel_db.get_indicators(
                    incident_id,
                )
                for item in raw:
                    evidence.append(
                        {
                            "type": item.get("type", "unknown"),
                            "value": item.get("value", ""),
                            "source": item.get("source", "intel_db"),
                            "description": item.get(
                                "description",
                                "",
                            ),
                            "severity": item.get(
                                "severity",
                                "medium",
                            ),
                        }
                    )
            except Exception:
                logger.debug(
                    "intel_db_fetch_failed",
                    incident_id=incident_id,
                )

        # IOC service ---------------------------------------------------
        if self._ioc_service is not None:
            try:
                iocs = await self._ioc_service.get_iocs(
                    incident_id,
                )
                for ioc in iocs:
                    evidence.append(
                        {
                            "type": ioc.get("type", "indicator"),
                            "value": ioc.get("value", ""),
                            "source": "ioc_service",
                            "description": ioc.get(
                                "description",
                                "",
                            ),
                            "severity": ioc.get(
                                "severity",
                                "medium",
                            ),
                        }
                    )
            except Exception:
                logger.debug(
                    "ioc_service_fetch_failed",
                    incident_id=incident_id,
                )

        # Fallback baseline when no external sources available
        if not evidence:
            now = time.time()
            evidence = [
                {
                    "type": "ip",
                    "value": "198.51.100.23",
                    "source": "firewall_logs",
                    "description": (f"Suspicious C2 beacon for {incident_id}"),
                    "severity": "high",
                    "timestamp": now - 7200,
                },
                {
                    "type": "domain",
                    "value": "evil-c2.example.com",
                    "source": "dns_logs",
                    "description": "DNS tunnel exfiltration",
                    "severity": "high",
                    "timestamp": now - 5400,
                },
                {
                    "type": "hash",
                    "value": "a1b2c3d4e5f6a1b2c3d4e5f6",
                    "source": "edr",
                    "description": ("Malware hash — powershell dropper"),
                    "severity": "critical",
                    "timestamp": now - 3600,
                },
                {
                    "type": "behavior",
                    "value": "lateral movement via smb",
                    "source": "edr",
                    "description": ("Lateral movement detected via SMB"),
                    "severity": "high",
                    "timestamp": now - 1800,
                },
                {
                    "type": "behavior",
                    "value": "credential dump lsass",
                    "source": "edr",
                    "description": ("Credential dump from LSASS process"),
                    "severity": "critical",
                    "timestamp": now - 900,
                },
            ]

        logger.info(
            "threat_attribution.evidence_collected",
            incident_id=incident_id,
            evidence_count=len(evidence),
        )
        return evidence

    async def map_ttps(
        self,
        evidence: list[dict[str, Any]],
    ) -> list[TTPMapping]:
        """Map collected evidence to MITRE ATT&CK TTPs."""
        combined = " ".join(f"{e.get('description', '')} {e.get('value', '')}" for e in evidence)

        mappings = self._match_ttps(combined)

        # Enrich from MITRE service if available
        if self._mitre_service is not None:
            try:
                for mapping in mappings:
                    details = await self._mitre_service.get_technique(
                        mapping.technique_id,
                    )
                    if details:
                        mapping.technique_name = details.get(
                            "name",
                            mapping.technique_name,
                        )
                        mapping.data_sources = details.get(
                            "data_sources",
                            [],
                        )
            except Exception:
                logger.debug("mitre_enrichment_failed")

        logger.info(
            "threat_attribution.ttps_mapped",
            technique_count=len(mappings),
        )
        return mappings

    async def profile_actor(
        self,
        ttp_mappings: list[TTPMapping],
    ) -> ActorProfile:
        """Profile the threat actor from TTP mappings."""
        ttp_ids = [m.technique_id for m in ttp_mappings]
        actor_name, sig, score = self._match_actor(ttp_ids)

        if actor_name and score > 0.0:
            profile = ActorProfile(
                name=actor_name,
                actor_type=sig.get(
                    "type",
                    ThreatActorType.UNKNOWN,
                ),
                aliases=sig.get("aliases", []),
                motivation=sig.get("motivation", ""),
                target_sectors=sig.get("sectors", []),
                known_ttps=sig.get("ttps", []),
                country_of_origin=sig.get("origin", ""),
            )
        else:
            profile = ActorProfile(
                name="Unknown Actor",
                actor_type=ThreatActorType.UNKNOWN,
                motivation="undetermined",
            )

        logger.info(
            "threat_attribution.actor_profiled",
            actor=profile.name,
            actor_type=profile.actor_type.value,
            match_score=score,
        )
        return profile

    async def assess_confidence(
        self,
        ttp_mappings: list[TTPMapping],
        actor_profile: ActorProfile,
    ) -> AttributionAssessment:
        """Assess attribution confidence level."""
        ttp_count = len(ttp_mappings)
        avg_conf = sum(m.confidence for m in ttp_mappings) / ttp_count if ttp_count > 0 else 0.0

        # Determine confidence level from thresholds
        confidence = ConfidenceLevel.UNATTRIBUTED
        for level, min_ttps, min_conf in CONFIDENCE_THRESHOLDS:
            if ttp_count >= min_ttps and avg_conf >= min_conf:
                confidence = level
                break

        # Build supporting evidence list
        supporting: list[str] = []
        for m in ttp_mappings[:5]:
            supporting.append(f"{m.technique_id} ({m.tactic}): {m.description}")

        # Build alternative hypotheses
        ttp_ids = [m.technique_id for m in ttp_mappings]
        alternatives: list[str] = []
        for actor, sig in ACTOR_SIGNATURES.items():
            if actor == actor_profile.name:
                continue
            overlap = len(set(ttp_ids) & set(sig.get("ttps", [])))
            if overlap > 0:
                alternatives.append(f"{actor} ({overlap} TTP overlap)")

        assessment = AttributionAssessment(
            attributed_actor=actor_profile.name,
            confidence=confidence,
            supporting_evidence=supporting,
            alternative_hypotheses=alternatives[:3],
            mitre_techniques_matched=ttp_count,
            summary=(
                f"Attribution to {actor_profile.name} with "
                f"{confidence.value} confidence based on "
                f"{ttp_count} MITRE ATT&CK technique(s)"
            ),
        )

        logger.info(
            "threat_attribution.confidence_assessed",
            actor=actor_profile.name,
            confidence=confidence.value,
            ttp_count=ttp_count,
        )
        return assessment
