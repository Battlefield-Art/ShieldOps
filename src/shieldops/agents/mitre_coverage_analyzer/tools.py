"""MITRE Coverage Analyzer Agent — Tool functions."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from .models import (
    CoverageGap,
    CoverageLevel,
    CoverageMatrix,
    DetectionRule,
    MITREMapping,
    MITRETactic,
    RuleRecommendation,
)

logger = structlog.get_logger()

# Representative MITRE ATT&CK technique catalog (subset)
_TECHNIQUE_CATALOG: list[dict[str, str]] = [
    {"id": "T1566", "name": "Phishing", "tactic": "initial_access"},
    {"id": "T1190", "name": "Exploit Public-Facing App", "tactic": "initial_access"},
    {"id": "T1059", "name": "Command and Scripting", "tactic": "execution"},
    {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "execution"},
    {"id": "T1547", "name": "Boot or Logon Autostart", "tactic": "persistence"},
    {"id": "T1136", "name": "Create Account", "tactic": "persistence"},
    {"id": "T1548", "name": "Abuse Elevation Control", "tactic": "privilege_escalation"},
    {"id": "T1068", "name": "Exploitation for Priv Esc", "tactic": "privilege_escalation"},
    {"id": "T1070", "name": "Indicator Removal", "tactic": "defense_evasion"},
    {"id": "T1027", "name": "Obfuscated Files", "tactic": "defense_evasion"},
    {"id": "T1003", "name": "OS Credential Dumping", "tactic": "credential_access"},
    {"id": "T1110", "name": "Brute Force", "tactic": "credential_access"},
    {"id": "T1083", "name": "File and Dir Discovery", "tactic": "discovery"},
    {"id": "T1018", "name": "Remote System Discovery", "tactic": "discovery"},
    {"id": "T1021", "name": "Remote Services", "tactic": "lateral_movement"},
    {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "lateral_movement"},
    {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
    {"id": "T1119", "name": "Automated Collection", "tactic": "collection"},
    {"id": "T1041", "name": "Exfil Over C2 Channel", "tactic": "exfiltration"},
    {"id": "T1048", "name": "Exfil Over Alt Protocol", "tactic": "exfiltration"},
    {"id": "T1071", "name": "Application Layer Proto", "tactic": "command_and_control"},
    {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command_and_control"},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "impact"},
    {"id": "T1489", "name": "Service Stop", "tactic": "impact"},
]


class MITRECoverageAnalyzerToolkit:
    """Toolkit for MITRE ATT&CK coverage analysis."""

    def __init__(
        self,
        siem_client: Any | None = None,
        edr_client: Any | None = None,
        mitre_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._siem_client = siem_client
        self._edr_client = edr_client
        self._mitre_db = mitre_db
        self._repository = repository

    async def inventory_detections(
        self,
        tenant_id: str,
    ) -> list[DetectionRule]:
        """Collect detection rules from SIEM and EDR."""
        logger.info(
            "mitre_coverage.inventory_detections",
            tenant_id=tenant_id,
        )
        if self._siem_client is not None:
            try:
                return await self._siem_client.list_rules(
                    tenant_id,
                )
            except Exception:
                logger.warning(
                    "mitre_coverage.siem_fallback",
                )

        # Return representative detection rules
        return [
            DetectionRule(
                id=f"det-{uuid4().hex[:8]}",
                name="Phishing Email Detection",
                source="siem",
                query="index=email subject=*urgent* attachment=*",
                severity="high",
                data_sources=["email_logs"],
                tags={"mitre": "T1566"},
            ),
            DetectionRule(
                id=f"det-{uuid4().hex[:8]}",
                name="PowerShell Execution",
                source="edr",
                query="process_name=powershell.exe",
                severity="medium",
                data_sources=["process_logs"],
                tags={"mitre": "T1059"},
            ),
            DetectionRule(
                id=f"det-{uuid4().hex[:8]}",
                name="Brute Force Login",
                source="siem",
                query="event=login_failed count>10",
                severity="high",
                data_sources=["auth_logs"],
                tags={"mitre": "T1110"},
            ),
            DetectionRule(
                id=f"det-{uuid4().hex[:8]}",
                name="Credential Dumping",
                source="edr",
                query="process=lsass.exe access=read",
                severity="critical",
                data_sources=["process_logs", "sysmon"],
                tags={"mitre": "T1003"},
            ),
            DetectionRule(
                id=f"det-{uuid4().hex[:8]}",
                name="Lateral Movement via RDP",
                source="siem",
                query="event=rdp_login src!=internal",
                severity="high",
                data_sources=["network_logs", "auth_logs"],
                tags={"mitre": "T1021"},
            ),
            DetectionRule(
                id=f"det-{uuid4().hex[:8]}",
                name="Data Exfiltration DNS",
                source="siem",
                query="dns_query_length>100 entropy>4.0",
                severity="critical",
                data_sources=["dns_logs"],
                tags={"mitre": "T1048"},
            ),
        ]

    async def map_to_mitre(
        self,
        rules: list[DetectionRule],
    ) -> list[MITREMapping]:
        """Map detection rules to MITRE ATT&CK techniques."""
        logger.info(
            "mitre_coverage.map_to_mitre",
            rule_count=len(rules),
        )
        mappings: list[MITREMapping] = []
        catalog_map = {t["id"]: t for t in _TECHNIQUE_CATALOG}

        for rule in rules:
            tech_id = rule.tags.get("mitre", "")
            if tech_id and tech_id in catalog_map:
                tech = catalog_map[tech_id]
                mappings.append(
                    MITREMapping(
                        rule_id=rule.id,
                        technique_id=tech_id,
                        technique_name=tech["name"],
                        tactic=MITRETactic(tech["tactic"]),
                        coverage=CoverageLevel.FULL,
                        confidence=0.85,
                    )
                )
            else:
                mappings.append(
                    MITREMapping(
                        rule_id=rule.id,
                        technique_id="unknown",
                        technique_name="Unmapped",
                        coverage=CoverageLevel.PARTIAL,
                        confidence=0.3,
                    )
                )
        return mappings

    async def calculate_coverage(
        self,
        mappings: list[MITREMapping],
    ) -> list[CoverageMatrix]:
        """Build a coverage matrix per tactic/technique."""
        logger.info(
            "mitre_coverage.calculate_coverage",
            mapping_count=len(mappings),
        )
        # Build lookup of covered techniques
        covered: dict[str, list[str]] = {}
        for m in mappings:
            if m.technique_id != "unknown":
                covered.setdefault(
                    m.technique_id,
                    [],
                ).append(m.rule_id)

        matrix: list[CoverageMatrix] = []
        for tech in _TECHNIQUE_CATALOG:
            rule_ids = covered.get(tech["id"], [])
            if len(rule_ids) >= 2:
                level = CoverageLevel.FULL
            elif len(rule_ids) == 1:
                level = CoverageLevel.PARTIAL
            else:
                level = CoverageLevel.NONE

            matrix.append(
                CoverageMatrix(
                    tactic=MITRETactic(tech["tactic"]),
                    technique_id=tech["id"],
                    technique_name=tech["name"],
                    coverage=level,
                    rule_count=len(rule_ids),
                    rule_ids=rule_ids,
                )
            )
        return matrix

    async def identify_gaps(
        self,
        matrix: list[CoverageMatrix],
    ) -> list[CoverageGap]:
        """Identify uncovered or partially covered techniques."""
        logger.info(
            "mitre_coverage.identify_gaps",
            matrix_size=len(matrix),
        )
        risk_weights = {
            MITRETactic.INITIAL_ACCESS: 0.9,
            MITRETactic.EXECUTION: 0.85,
            MITRETactic.PERSISTENCE: 0.8,
            MITRETactic.PRIVILEGE_ESCALATION: 0.9,
            MITRETactic.DEFENSE_EVASION: 0.85,
            MITRETactic.CREDENTIAL_ACCESS: 0.9,
            MITRETactic.DISCOVERY: 0.5,
            MITRETactic.LATERAL_MOVEMENT: 0.85,
            MITRETactic.COLLECTION: 0.6,
            MITRETactic.EXFILTRATION: 0.95,
            MITRETactic.COMMAND_AND_CONTROL: 0.8,
            MITRETactic.IMPACT: 0.95,
        }

        gaps: list[CoverageGap] = []
        for entry in matrix:
            if entry.coverage != CoverageLevel.FULL:
                weight = risk_weights.get(
                    entry.tactic,
                    0.5,
                )
                score = weight
                score = weight * 1.0 if entry.coverage == CoverageLevel.NONE else weight * 0.5

                gaps.append(
                    CoverageGap(
                        technique_id=entry.technique_id,
                        technique_name=entry.technique_name,
                        tactic=entry.tactic,
                        current_coverage=entry.coverage,
                        risk_score=round(score, 2),
                        reason=(
                            "No detection rules"
                            if entry.coverage == CoverageLevel.NONE
                            else "Partial coverage only"
                        ),
                    )
                )

        gaps.sort(
            key=lambda g: g.risk_score,
            reverse=True,
        )
        return gaps

    async def recommend_rules(
        self,
        gaps: list[CoverageGap],
    ) -> list[RuleRecommendation]:
        """Generate detection rule recommendations."""
        logger.info(
            "mitre_coverage.recommend_rules",
            gap_count=len(gaps),
        )
        recommendations: list[RuleRecommendation] = []
        for gap in gaps[:10]:
            recommendations.append(
                RuleRecommendation(
                    gap_technique_id=gap.technique_id,
                    gap_technique_name=gap.technique_name,
                    recommended_rule_name=(f"Detect {gap.technique_name}"),
                    recommended_query=(f"# Query for {gap.technique_id}"),
                    data_sources_needed=[
                        "process_logs",
                        "network_logs",
                    ],
                    estimated_effort="medium",
                    priority=(
                        "critical"
                        if gap.risk_score >= 0.9
                        else "high"
                        if gap.risk_score >= 0.7
                        else "medium"
                    ),
                )
            )
        return recommendations
