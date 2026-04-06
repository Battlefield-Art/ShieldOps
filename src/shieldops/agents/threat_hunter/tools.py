"""Tool functions for the Threat Hunter Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.policy.engine import PolicyContext
from shieldops.policy.engine import evaluate as policy_evaluate

logger = structlog.get_logger()

# Common MITRE ATT&CK technique reference for hunt mapping
MITRE_TECHNIQUE_MAP: dict[str, dict[str, str]] = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversary uses command-line interfaces or scripting languages.",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversary uses PowerShell for execution.",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Execution, Persistence",
        "description": "Adversary uses task scheduling for persistence or execution.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversary uses application layer protocols for C2.",
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversary uses HTTP/S for C2 communication.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "description": "Adversary uses compromised valid credentials.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversary attempts to brute-force credentials.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversary dumps OS credentials from memory or files.",
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversary dumps LSASS process memory for credentials.",
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversary uses remote services for lateral movement.",
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Adversary uses RDP for lateral movement.",
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Adversary uses SMB shares for lateral movement.",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversary exfiltrates data over non-standard protocols.",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversary encrypts data to deny access (ransomware).",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Adversary injects code into processes.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversary obfuscates payloads to evade detection.",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversary persists via autostart mechanisms.",
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversary uses registry run keys for persistence.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversary exploits vulnerable internet-facing applications.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversary sends phishing messages to gain access.",
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversary sends targeted emails with malicious attachments.",
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversary manipulates accounts to maintain access.",
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversary removes indicators to cover tracks.",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversary disables or modifies security tools.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversary transfers tools into the environment.",
    },
    "T1036": {
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "description": "Adversary disguises artifacts as legitimate files.",
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "description": "Adversary uses signed binaries to proxy malicious execution.",
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "Execution, Persistence",
        "description": "Adversary creates scheduled tasks for persistence.",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversary creates or modifies system services.",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Adversary gathers system information.",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Adversary enumerates files and directories.",
    },
    "T1057": {
        "name": "Process Discovery",
        "tactic": "Discovery",
        "description": "Adversary discovers running processes.",
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "tactic": "Discovery",
        "description": "Adversary discovers active network connections.",
    },
}

# SPL query templates for behavioral analysis
SPL_TEMPLATES: dict[str, str] = {
    "anomalous_auth": (
        "index=security sourcetype=WinEventLog:Security EventCode=4625 OR EventCode=4624 "
        "| stats count by src_ip, user, EventCode "
        "| where count > 10 "
        "| sort -count"
    ),
    "lateral_movement": (
        "index=security sourcetype=WinEventLog:Security "
        "(EventCode=4624 Logon_Type=3 OR EventCode=4648) "
        "| stats dc(dest) as unique_targets by src_ip, user "
        "| where unique_targets > 3 "
        "| sort -unique_targets"
    ),
    "suspicious_process": (
        "index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational "
        "EventCode=1 "
        '(ParentImage="*\\\\cmd.exe" OR ParentImage="*\\\\powershell.exe") '
        "| stats count by ParentImage, Image, CommandLine "
        "| sort -count"
    ),
    "data_exfiltration": (
        "index=network sourcetype=firewall "
        "| stats sum(bytes_out) as total_bytes by src_ip, dest_ip "
        "| where total_bytes > 104857600 "
        "| sort -total_bytes"
    ),
    "persistence_mechanisms": (
        "index=sysmon EventCode=13 "
        'TargetObject="*\\\\CurrentVersion\\\\Run*" '
        "| stats count by Image, TargetObject, Details "
        "| sort -count"
    ),
    "dns_anomalies": (
        "index=dns "
        "| stats count dc(query) as unique_queries avg(query_length) as avg_len by src_ip "
        "| where unique_queries > 100 OR avg_len > 50 "
        "| sort -unique_queries"
    ),
    "privilege_escalation": (
        "index=security sourcetype=WinEventLog:Security "
        "(EventCode=4672 OR EventCode=4673 OR EventCode=4674) "
        "| stats count by user, PrivilegeList "
        "| sort -count"
    ),
    "command_and_control": (
        "index=proxy OR index=network "
        "| stats count dc(dest) as unique_dests avg(bytes_out) as avg_bytes by src_ip "
        "| where count > 100 AND avg_bytes < 1024 "
        "| sort -count"
    ),
}


class ThreatHunterToolkit:
    """Toolkit bridging the threat hunter to security modules and connectors."""

    def __init__(
        self,
        mitre_mapper: Any | None = None,
        threat_intel: Any | None = None,
        ioc_scanner: Any | None = None,
        behavior_analyzer: Any | None = None,
        hunt_metrics: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
        connector_router: dict[str, Any] | None = None,
    ) -> None:
        self._mitre_mapper = mitre_mapper
        self._threat_intel = threat_intel
        self._ioc_scanner = ioc_scanner
        self._behavior_analyzer = behavior_analyzer
        self._hunt_metrics = hunt_metrics
        self._policy_engine = policy_engine
        self._repository = repository
        self._connector_router = connector_router or {}
        self._hunt_history: list[dict[str, Any]] = []

    def _get_connector(self, name: str) -> Any | None:
        """Retrieve a connector by name from the router."""
        connector = self._connector_router.get(name)
        if connector is None:
            logger.debug("threat_hunter.connector_not_available", connector=name)
        return connector

    async def generate_hypothesis(self, context: dict[str, Any]) -> dict[str, Any]:
        """Generate a threat hunting hypothesis from context.

        Uses threat intelligence context and LLM to refine a raw hypothesis
        into a structured hunting plan with data sources and MITRE mappings.
        """
        hypothesis_text = context.get("hypothesis", "")
        hunt_scope = context.get("hunt_scope", {})
        logger.info(
            "threat_hunter.generate_hypothesis",
            hypothesis=hypothesis_text[:80],
            scope_keys=list(hunt_scope.keys()),
        )

        # Determine relevant MITRE techniques based on hypothesis keywords
        mitre_techniques = self._map_hypothesis_to_mitre(hypothesis_text)

        # Determine data sources needed based on hypothesis
        data_sources = self._identify_data_sources(hypothesis_text)

        # Calculate initial confidence based on specificity
        confidence = self._score_hypothesis_confidence(hypothesis_text, mitre_techniques)

        # Try LLM enhancement for hypothesis refinement
        try:
            from shieldops.agents.threat_hunter.prompts import (
                SYSTEM_HYPOTHESIS,
                HypothesisOutput,
            )
            from shieldops.utils.llm import llm_structured

            llm_result = await llm_structured(
                system_prompt=SYSTEM_HYPOTHESIS,
                user_prompt=(
                    f"Raw hypothesis: {hypothesis_text}\n"
                    f"Hunt scope: {hunt_scope}\n"
                    f"Initial MITRE mappings: {mitre_techniques}"
                ),
                schema=HypothesisOutput,
            )
            if hasattr(llm_result, "hypothesis") and llm_result.hypothesis:
                hypothesis_text = llm_result.hypothesis
            if hasattr(llm_result, "data_sources") and llm_result.data_sources:
                data_sources = list(set(data_sources + llm_result.data_sources))
            if hasattr(llm_result, "mitre_techniques") and llm_result.mitre_techniques:
                mitre_techniques = list(set(mitre_techniques + llm_result.mitre_techniques))
            if hasattr(llm_result, "confidence"):
                confidence = max(confidence, llm_result.confidence)
            logger.info("threat_hunter.generate_hypothesis.llm_enhanced")
        except Exception:
            logger.debug("threat_hunter.generate_hypothesis.llm_skipped")

        # Enrich with threat intel from CrowdStrike if available
        crowdstrike = self._get_connector("crowdstrike")
        if crowdstrike:
            try:
                indicators = hunt_scope.get("indicators", [])
                for indicator in indicators[:5]:
                    graph_data = await crowdstrike.get_threat_graph(indicator)
                    if graph_data.get("resources"):
                        confidence = min(1.0, confidence + 0.1)
                        logger.info(
                            "threat_hunter.generate_hypothesis.threat_graph_hit",
                            indicator=indicator[:40],
                        )
            except Exception as e:
                logger.warning(
                    "threat_hunter.generate_hypothesis.crowdstrike_error",
                    error=str(e),
                )

        return {
            "hypothesis": hypothesis_text or "Unspecified threat activity requiring investigation",
            "data_sources": data_sources or ["security_logs", "endpoint_telemetry"],
            "mitre_techniques": mitre_techniques,
            "confidence": round(confidence, 2),
        }

    async def sweep_iocs(
        self, scope: dict[str, Any], indicators: list[str]
    ) -> list[dict[str, Any]]:
        """Sweep environment for indicators of compromise.

        Queries CrowdStrike IOC management API for matching indicators and
        searches Splunk for IOC hits in log data.
        """
        logger.info(
            "threat_hunter.sweep_iocs",
            scope_keys=list(scope.keys()),
            indicator_count=len(indicators),
        )

        # OPA policy check before querying infrastructure
        try:
            policy_ctx = PolicyContext(
                agent_name="threat_hunter",
                action_type="sweep_iocs",
                target_resources=[f"ioc:{ind[:40]}" for ind in indicators[:10]],
                environment=scope.get("environment", "production"),
                risk_score=0.2,  # read-only scan
            )
            decision = await policy_evaluate(action="sweep_iocs", context=policy_ctx)
            if not decision.allowed:
                logger.warning(
                    "threat_hunter.sweep_iocs.policy_denied",
                    reason=decision.reason,
                )
                return [
                    {
                        "source": "policy",
                        "policy_denied": True,
                        "reason": decision.reason,
                    }
                ]
        except Exception:
            logger.debug("threat_hunter.sweep_iocs.policy_error_failopen")

        results: list[dict[str, Any]] = []
        now = datetime.now(UTC).isoformat()

        # Query CrowdStrike IOC management
        crowdstrike = self._get_connector("crowdstrike")
        if crowdstrike:
            try:
                for indicator in indicators:
                    ioc_type = self._classify_ioc_type(indicator)
                    matches = await crowdstrike.query_iocs(ioc_type=ioc_type, value=indicator)
                    for match in matches:
                        results.append(
                            {
                                "source": "crowdstrike",
                                "indicator": indicator,
                                "ioc_type": ioc_type,
                                "match": match,
                                "severity": match.get("severity", "medium"),
                                "action": match.get("action", "detect"),
                                "found_at": now,
                            }
                        )
                logger.info(
                    "threat_hunter.sweep_iocs.crowdstrike_complete",
                    matches=len([r for r in results if r["source"] == "crowdstrike"]),
                )
            except Exception as e:
                logger.warning("threat_hunter.sweep_iocs.crowdstrike_error", error=str(e))

        # Search Splunk logs for IOC hits
        splunk = self._get_connector("splunk")
        if splunk and indicators:
            try:
                time_range = scope.get("time_range", "7d")
                earliest = f"-{time_range}" if not time_range.startswith("-") else time_range
                ioc_search_values = " OR ".join(f'"{ind}"' for ind in indicators[:20])
                spl_query = (
                    f"index=* ({ioc_search_values}) "
                    f"| stats count by index, source, sourcetype "
                    f"| where count > 0 "
                    f"| sort -count"
                )
                splunk_results = await splunk.search_spl(
                    query=spl_query, earliest=earliest, latest="now"
                )
                for hit in splunk_results:
                    results.append(
                        {
                            "source": "splunk",
                            "indicator": "multiple",
                            "ioc_type": "log_match",
                            "match": hit,
                            "severity": "medium",
                            "action": "investigate",
                            "found_at": now,
                            "log_source": hit.get("sourcetype", "unknown"),
                            "hit_count": int(hit.get("count", 0)),
                        }
                    )
                logger.info(
                    "threat_hunter.sweep_iocs.splunk_complete",
                    matches=len([r for r in results if r["source"] == "splunk"]),
                )
            except Exception as e:
                logger.warning("threat_hunter.sweep_iocs.splunk_error", error=str(e))

        # Fallback: generate heuristic results if no connectors available
        if not results and not crowdstrike and not splunk:
            results = self._heuristic_ioc_sweep(indicators, scope)

        return results

    async def analyze_behavior(
        self, scope: dict[str, Any], baseline_id: str
    ) -> list[dict[str, Any]]:
        """Analyze behavioral deviations against a baseline.

        Runs SPL behavioral queries via Splunk connector and checks
        CrowdStrike detections for anomalous activity.
        """
        logger.info(
            "threat_hunter.analyze_behavior",
            baseline_id=baseline_id,
            scope_keys=list(scope.keys()),
        )

        # OPA policy check before querying infrastructure
        try:
            policy_ctx = PolicyContext(
                agent_name="threat_hunter",
                action_type="analyze_behavior",
                target_resources=[f"baseline:{baseline_id}"],
                environment=scope.get("environment", "production"),
                risk_score=0.2,  # read-only analysis
            )
            decision = await policy_evaluate(action="analyze_behavior", context=policy_ctx)
            if not decision.allowed:
                logger.warning(
                    "threat_hunter.analyze_behavior.policy_denied",
                    reason=decision.reason,
                )
                return [
                    {
                        "source": "policy",
                        "policy_denied": True,
                        "reason": decision.reason,
                    }
                ]
        except Exception:
            logger.debug("threat_hunter.analyze_behavior.policy_error_failopen")

        findings: list[dict[str, Any]] = []
        now = datetime.now(UTC).isoformat()
        time_range = scope.get("time_range", "7d")
        earliest = f"-{time_range}" if not time_range.startswith("-") else time_range

        # Determine which behavioral queries to run based on scope
        query_types = self._select_behavioral_queries(scope)

        # Run SPL behavioral queries via Splunk
        splunk = self._get_connector("splunk")
        if splunk:
            try:
                for query_type in query_types:
                    spl = SPL_TEMPLATES.get(query_type)
                    if not spl:
                        continue
                    results = await splunk.search_spl(query=spl, earliest=earliest, latest="now")
                    if results:
                        findings.append(
                            {
                                "source": "splunk",
                                "analysis_type": query_type,
                                "baseline_id": baseline_id,
                                "deviations": results[:50],
                                "deviation_count": len(results),
                                "severity": self._assess_behavioral_severity(
                                    query_type, len(results)
                                ),
                                "found_at": now,
                            }
                        )
                logger.info(
                    "threat_hunter.analyze_behavior.splunk_complete",
                    finding_count=len([f for f in findings if f["source"] == "splunk"]),
                )
            except Exception as e:
                logger.warning("threat_hunter.analyze_behavior.splunk_error", error=str(e))

        # Check CrowdStrike for recent detections in scope
        crowdstrike = self._get_connector("crowdstrike")
        if crowdstrike:
            try:
                environments = scope.get("environments", ["production"])
                for _env in environments[:3]:
                    detections = await crowdstrike.get_detections(
                        filter_query="status:'new'+max_severity_displayname:'High'",
                        limit=50,
                    )
                    if detections:
                        findings.append(
                            {
                                "source": "crowdstrike",
                                "analysis_type": "endpoint_detections",
                                "baseline_id": baseline_id,
                                "deviations": [
                                    {
                                        "detection_id": d.get("detection_id", ""),
                                        "severity": d.get("max_severity_displayname", "unknown"),
                                        "tactic": d.get("tactic", ""),
                                        "technique": d.get("technique", ""),
                                        "hostname": d.get("device", {}).get("hostname", ""),
                                    }
                                    for d in detections[:20]
                                ],
                                "deviation_count": len(detections),
                                "severity": "high",
                                "found_at": now,
                            }
                        )
                logger.info(
                    "threat_hunter.analyze_behavior.crowdstrike_complete",
                    detection_count=sum(
                        f["deviation_count"] for f in findings if f["source"] == "crowdstrike"
                    ),
                )
            except Exception as e:
                logger.warning(
                    "threat_hunter.analyze_behavior.crowdstrike_error",
                    error=str(e),
                )

        # Fallback if no connectors available
        if not findings and not splunk and not crowdstrike:
            findings = self._heuristic_behavior_analysis(scope, baseline_id)

        return findings

    async def check_mitre_coverage(self, techniques: list[str]) -> list[dict[str, Any]]:
        """Check detection coverage for specified MITRE ATT&CK techniques.

        Maps technique IDs to the MITRE knowledge base and assesses
        current detection coverage.
        """
        logger.info(
            "threat_hunter.check_mitre_coverage",
            technique_count=len(techniques),
        )
        coverage_results: list[dict[str, Any]] = []

        for technique_id in techniques:
            technique_info = MITRE_TECHNIQUE_MAP.get(technique_id)
            if technique_info:
                # Determine coverage status based on available detections
                has_splunk = self._get_connector("splunk") is not None
                has_crowdstrike = self._get_connector("crowdstrike") is not None

                detection_sources: list[str] = []
                if has_splunk:
                    detection_sources.append("splunk_correlation_search")
                if has_crowdstrike:
                    detection_sources.append("crowdstrike_behavior_ioc")

                coverage_level = self._assess_technique_coverage(technique_id, detection_sources)

                coverage_results.append(
                    {
                        "technique_id": technique_id,
                        "technique_name": technique_info["name"],
                        "tactic": technique_info["tactic"],
                        "description": technique_info["description"],
                        "coverage_level": coverage_level,
                        "detection_sources": detection_sources,
                        "gap_identified": coverage_level in ("none", "low"),
                        "recommendation": self._coverage_recommendation(
                            technique_id, coverage_level
                        ),
                    }
                )
            else:
                # Unknown technique - flag as gap
                coverage_results.append(
                    {
                        "technique_id": technique_id,
                        "technique_name": "Unknown",
                        "tactic": "Unknown",
                        "description": f"Technique {technique_id} not in local mapping",
                        "coverage_level": "unknown",
                        "detection_sources": [],
                        "gap_identified": True,
                        "recommendation": (
                            f"Research technique {technique_id} and build detection rules."
                        ),
                    }
                )

        return coverage_results

    async def correlate_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Correlate findings across data sources to identify patterns.

        Groups related findings by shared attributes (IPs, users, hosts,
        techniques) and assesses the correlated severity.
        """
        logger.info("threat_hunter.correlate_findings", finding_count=len(findings))
        if not findings:
            return []

        # Extract shared attributes across findings
        ip_map: dict[str, list[int]] = {}
        user_map: dict[str, list[int]] = {}
        technique_map: dict[str, list[int]] = {}
        host_map: dict[str, list[int]] = {}

        for idx, finding in enumerate(findings):
            finding.get("type", "unknown")
            match_data = finding.get("match", {})
            deviations = finding.get("deviations", [])

            # Extract IPs
            for ip_field in ("src_ip", "dest_ip", "indicator", "ip"):
                ip_val = match_data.get(ip_field) or finding.get(ip_field)
                if ip_val and self._is_ip_like(ip_val):
                    ip_map.setdefault(ip_val, []).append(idx)

            # Extract users
            for user_field in ("user", "username", "account_name"):
                user_val = match_data.get(user_field) or finding.get(user_field)
                if user_val:
                    user_map.setdefault(user_val, []).append(idx)

            # Extract techniques
            technique_id = finding.get("technique_id") or finding.get("technique")
            if technique_id:
                technique_map.setdefault(technique_id, []).append(idx)

            # Extract hostnames from deviations
            for dev in deviations[:10] if isinstance(deviations, list) else []:
                hostname = dev.get("hostname") or dev.get("host")
                if hostname:
                    host_map.setdefault(hostname, []).append(idx)

        # Build correlated groups where the same entity appears in multiple findings
        correlated_groups: list[dict[str, Any]] = []

        for entity_type, entity_map in [
            ("ip_address", ip_map),
            ("user", user_map),
            ("mitre_technique", technique_map),
            ("hostname", host_map),
        ]:
            for entity_value, finding_indices in entity_map.items():
                if len(finding_indices) >= 2:
                    related_findings = [findings[i] for i in finding_indices]
                    sources = list({f.get("source", "unknown") for f in related_findings})
                    severities = [f.get("severity", "low") for f in related_findings]
                    max_severity = self._max_severity(severities)

                    correlated_groups.append(
                        {
                            "correlation_id": str(uuid4())[:8],
                            "entity_type": entity_type,
                            "entity_value": entity_value,
                            "finding_count": len(finding_indices),
                            "sources": sources,
                            "cross_source": len(sources) > 1,
                            "severity": max_severity,
                            "related_findings": [
                                {
                                    "type": f.get("type", "unknown"),
                                    "source": f.get("source", "unknown"),
                                    "severity": f.get("severity", "low"),
                                }
                                for f in related_findings
                            ],
                            "confidence": min(
                                1.0,
                                0.4
                                + (len(finding_indices) * 0.15)
                                + (0.2 if len(sources) > 1 else 0.0),
                            ),
                        }
                    )

        # Sort by confidence descending
        correlated_groups.sort(key=lambda g: g["confidence"], reverse=True)

        # If no correlations found but findings exist, create a single ungrouped entry
        if not correlated_groups and findings:
            correlated_groups.append(
                {
                    "correlation_id": str(uuid4())[:8],
                    "entity_type": "ungrouped",
                    "entity_value": "isolated_findings",
                    "finding_count": len(findings),
                    "sources": list({f.get("source", "unknown") for f in findings}),
                    "cross_source": False,
                    "severity": self._max_severity([f.get("severity", "low") for f in findings]),
                    "related_findings": [
                        {
                            "type": f.get("type", "unknown"),
                            "source": f.get("source", "unknown"),
                            "severity": f.get("severity", "low"),
                        }
                        for f in findings[:10]
                    ],
                    "confidence": 0.3,
                }
            )

        return correlated_groups

    async def track_effectiveness(self, hunt_id: str, outcome: dict[str, Any]) -> dict[str, Any]:
        """Track hunt effectiveness metrics for continuous improvement.

        Records hunt results, calculates time-to-detect, IOC yield, and
        technique coverage metrics.
        """
        logger.info(
            "threat_hunter.track_effectiveness",
            hunt_id=hunt_id,
            threat_found=outcome.get("threat_found", False),
        )

        total_findings = outcome.get("total_findings", 0)
        correlated_count = outcome.get("correlated_count", 0)
        duration_ms = outcome.get("duration_ms", 0)
        threat_found = outcome.get("threat_found", False)
        effectiveness_score = outcome.get("effectiveness_score", 0.0)

        metrics = {
            "hunt_id": hunt_id,
            "tracked": True,
            "timestamp": datetime.now(UTC).isoformat(),
            "duration_ms": duration_ms,
            "duration_human": self._format_duration(duration_ms),
            "total_findings": total_findings,
            "correlated_count": correlated_count,
            "threat_found": threat_found,
            "effectiveness_score": round(effectiveness_score, 3),
            "ioc_yield": (round(correlated_count / max(total_findings, 1), 2)),
            "recommendations_count": outcome.get("recommendations", 0),
            "hunt_quality": self._classify_hunt_quality(
                effectiveness_score, total_findings, threat_found
            ),
        }

        # Store in hunt history for trend analysis
        self._hunt_history.append(metrics)

        # Persist to repository if available
        if self._repository:
            try:
                await self._repository.save_hunt_metrics(hunt_id, metrics)
            except Exception as e:
                logger.warning(
                    "threat_hunter.track_effectiveness.persist_error",
                    error=str(e),
                )

        # Record to hunt_metrics engine if available
        if self._hunt_metrics:
            try:
                self._hunt_metrics.add_record(
                    hunt_id=hunt_id,
                    effectiveness=effectiveness_score,
                    findings=total_findings,
                    threat_found=threat_found,
                )
            except Exception as e:
                logger.warning(
                    "threat_hunter.track_effectiveness.metrics_error",
                    error=str(e),
                )

        return metrics

    # -- Private helper methods -----------------------------------------------

    def _map_hypothesis_to_mitre(self, hypothesis: str) -> list[str]:
        """Map hypothesis keywords to likely MITRE ATT&CK techniques."""
        hypothesis_lower = hypothesis.lower()
        matched: list[str] = []

        keyword_technique_map = {
            "lateral movement": ["T1021", "T1021.001", "T1021.002"],
            "rdp": ["T1021.001"],
            "smb": ["T1021.002"],
            "brute force": ["T1110"],
            "credential": ["T1003", "T1003.001", "T1078"],
            "lsass": ["T1003.001"],
            "phishing": ["T1566", "T1566.001"],
            "spearphishing": ["T1566.001"],
            "powershell": ["T1059.001"],
            "command line": ["T1059"],
            "scripting": ["T1059"],
            "scheduled task": ["T1053", "T1053.005"],
            "persistence": ["T1547", "T1547.001", "T1543"],
            "registry": ["T1547.001"],
            "exfiltration": ["T1048"],
            "ransomware": ["T1486"],
            "encryption": ["T1486"],
            "process injection": ["T1055"],
            "obfuscation": ["T1027"],
            "c2": ["T1071", "T1071.001"],
            "command and control": ["T1071", "T1071.001"],
            "beacon": ["T1071.001"],
            "exploit": ["T1190"],
            "privilege escalation": ["T1055", "T1078"],
            "valid account": ["T1078"],
            "defense evasion": ["T1027", "T1036", "T1070", "T1562"],
            "masquerade": ["T1036"],
            "indicator removal": ["T1070"],
            "disable security": ["T1562"],
            "tool transfer": ["T1105"],
            "lolbin": ["T1218"],
            "discovery": ["T1082", "T1083", "T1057", "T1049"],
            "account manipulation": ["T1098"],
            "dns": ["T1071"],
        }

        for keyword, techniques in keyword_technique_map.items():
            if keyword in hypothesis_lower:
                matched.extend(techniques)

        return list(dict.fromkeys(matched))  # deduplicate preserving order

    def _identify_data_sources(self, hypothesis: str) -> list[str]:
        """Identify data sources needed based on hypothesis content."""
        hypothesis_lower = hypothesis.lower()
        sources: list[str] = []

        source_keywords = {
            "endpoint_telemetry": [
                "endpoint",
                "process",
                "malware",
                "ransomware",
                "injection",
                "lsass",
                "persistence",
            ],
            "network_logs": [
                "network",
                "lateral",
                "c2",
                "beacon",
                "exfiltration",
                "dns",
                "proxy",
                "firewall",
            ],
            "authentication_logs": [
                "credential",
                "brute force",
                "login",
                "auth",
                "valid account",
                "privilege",
            ],
            "email_logs": ["phishing", "email", "spearphishing", "attachment"],
            "sysmon": [
                "process",
                "registry",
                "scheduled task",
                "service",
                "powershell",
                "command",
            ],
            "cloud_audit_logs": ["cloud", "aws", "azure", "gcp", "iam"],
            "security_logs": ["detection", "alert", "incident"],
        }

        for source, keywords in source_keywords.items():
            if any(kw in hypothesis_lower for kw in keywords):
                sources.append(source)

        return sources or ["security_logs", "endpoint_telemetry"]

    def _score_hypothesis_confidence(self, hypothesis: str, techniques: list[str]) -> float:
        """Score hypothesis confidence based on specificity."""
        if not hypothesis:
            return 0.1

        score = 0.3  # base score for having a hypothesis
        word_count = len(hypothesis.split())

        # More specific hypotheses score higher
        if word_count > 10:
            score += 0.1
        if word_count > 20:
            score += 0.1

        # Having MITRE mappings adds confidence
        if techniques:
            score += min(0.2, len(techniques) * 0.05)

        # Specific IOC types mentioned
        specificity_markers = [
            "ip address",
            "domain",
            "hash",
            "sha256",
            "md5",
            "file name",
            "registry key",
            "service name",
        ]
        for marker in specificity_markers:
            if marker in hypothesis.lower():
                score += 0.05

        return min(0.9, round(score, 2))

    def _classify_ioc_type(self, indicator: str) -> str:
        """Classify an IOC indicator by type."""
        indicator = indicator.strip()
        if (
            "." in indicator
            and all(p.isdigit() for p in indicator.split("."))
            and len(indicator.split(".")) == 4
        ):
            return "ipv4"
        if ":" in indicator and len(indicator) > 10:
            return "ipv6"
        if len(indicator) == 64 and all(c in "0123456789abcdef" for c in indicator.lower()):
            return "sha256"
        if len(indicator) == 32 and all(c in "0123456789abcdef" for c in indicator.lower()):
            return "md5"
        if len(indicator) == 40 and all(c in "0123456789abcdef" for c in indicator.lower()):
            return "sha1"
        if "." in indicator and not indicator.replace(".", "").isdigit():
            return "domain"
        return "unknown"

    def _select_behavioral_queries(self, scope: dict[str, Any]) -> list[str]:
        """Select which behavioral SPL queries to run based on scope."""
        mitre_techniques = scope.get("mitre_techniques", [])
        hypothesis = scope.get("hypothesis", "").lower()

        queries: list[str] = []

        # Map techniques/keywords to query types
        technique_query_map = {
            "T1110": "anomalous_auth",
            "T1078": "anomalous_auth",
            "T1021": "lateral_movement",
            "T1021.001": "lateral_movement",
            "T1021.002": "lateral_movement",
            "T1059": "suspicious_process",
            "T1059.001": "suspicious_process",
            "T1048": "data_exfiltration",
            "T1547": "persistence_mechanisms",
            "T1547.001": "persistence_mechanisms",
            "T1071": "command_and_control",
            "T1071.001": "dns_anomalies",
            "T1055": "suspicious_process",
            "T1003": "anomalous_auth",
        }

        for technique in mitre_techniques:
            query = technique_query_map.get(technique)
            if query and query not in queries:
                queries.append(query)

        # Keyword fallback
        keyword_query_map = {
            "lateral": "lateral_movement",
            "brute": "anomalous_auth",
            "credential": "anomalous_auth",
            "exfil": "data_exfiltration",
            "persist": "persistence_mechanisms",
            "c2": "command_and_control",
            "beacon": "command_and_control",
            "dns": "dns_anomalies",
            "process": "suspicious_process",
            "privilege": "privilege_escalation",
        }

        for keyword, query in keyword_query_map.items():
            if keyword in hypothesis and query not in queries:
                queries.append(query)

        # Default: run auth + lateral movement + process queries
        if not queries:
            queries = ["anomalous_auth", "lateral_movement", "suspicious_process"]

        return queries[:5]  # cap to avoid excessive queries

    def _assess_behavioral_severity(self, query_type: str, result_count: int) -> str:
        """Assess severity of behavioral findings."""
        high_severity_queries = {"lateral_movement", "data_exfiltration", "privilege_escalation"}
        if query_type in high_severity_queries and result_count > 5:
            return "critical"
        if query_type in high_severity_queries:
            return "high"
        if result_count > 20:
            return "high"
        if result_count > 5:
            return "medium"
        return "low"

    def _assess_technique_coverage(self, technique_id: str, detection_sources: list[str]) -> str:
        """Assess detection coverage level for a technique."""
        if not detection_sources:
            return "none"

        # Techniques with well-known detection signatures
        well_covered = {"T1059.001", "T1110", "T1547.001", "T1486", "T1566.001"}
        partial_covered = {
            "T1003",
            "T1003.001",
            "T1021",
            "T1078",
            "T1055",
            "T1071",
            "T1190",
            "T1053",
        }

        if technique_id in well_covered and len(detection_sources) >= 2:
            return "high"
        if technique_id in well_covered:
            return "medium"
        if technique_id in partial_covered:
            return "medium" if len(detection_sources) >= 2 else "low"
        return "low"

    def _coverage_recommendation(self, technique_id: str, coverage_level: str) -> str:
        """Generate a recommendation for improving technique coverage."""
        technique_info = MITRE_TECHNIQUE_MAP.get(technique_id, {})
        name = technique_info.get("name", technique_id)

        if coverage_level == "none":
            return (
                f"No detection coverage for {name} ({technique_id}). "
                f"Create correlation rules and endpoint detection signatures."
            )
        if coverage_level == "low":
            return (
                f"Low coverage for {name} ({technique_id}). "
                f"Add behavioral analytics and log-based detection rules."
            )
        if coverage_level == "medium":
            return (
                f"Moderate coverage for {name} ({technique_id}). "
                f"Validate detection efficacy and add cross-source correlation."
            )
        return f"Good coverage for {name} ({technique_id}). Continue monitoring."

    def _is_ip_like(self, value: str) -> bool:
        """Check if a value looks like an IP address."""
        if not isinstance(value, str):
            return False
        parts = value.split(".")
        if len(parts) == 4:
            return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
        return ":" in value and len(value) > 5  # rough IPv6 check

    def _max_severity(self, severities: list[str]) -> str:
        """Return the maximum severity from a list."""
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if not severities:
            return "low"
        return max(severities, key=lambda s: severity_order.get(s, 0))

    def _format_duration(self, ms: int) -> str:
        """Format milliseconds into human-readable duration."""
        if ms < 1000:
            return f"{ms}ms"
        seconds = ms / 1000
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes = seconds / 60
        if minutes < 60:
            return f"{minutes:.1f}m"
        hours = minutes / 60
        return f"{hours:.1f}h"

    def _classify_hunt_quality(
        self, effectiveness: float, findings: int, threat_found: bool
    ) -> str:
        """Classify the overall quality of a hunt."""
        if threat_found and effectiveness >= 0.7:
            return "excellent"
        if threat_found:
            return "good"
        if findings > 0 and effectiveness >= 0.3:
            return "productive"
        if findings > 0:
            return "partial"
        return "baseline"

    # -- Heuristic fallbacks (no connectors available) -------------------------

    def _heuristic_ioc_sweep(
        self, indicators: list[str], scope: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Generate heuristic IOC sweep results when no connectors are available."""
        results: list[dict[str, Any]] = []
        now = datetime.now(UTC).isoformat()

        for indicator in indicators[:10]:
            ioc_type = self._classify_ioc_type(indicator)
            results.append(
                {
                    "source": "heuristic",
                    "indicator": indicator,
                    "ioc_type": ioc_type,
                    "match": {
                        "value": indicator,
                        "type": ioc_type,
                        "status": "pending_validation",
                    },
                    "severity": "medium",
                    "action": "investigate",
                    "found_at": now,
                    "note": "No live connector available; manual validation required.",
                }
            )

        return results

    def _heuristic_behavior_analysis(
        self, scope: dict[str, Any], baseline_id: str
    ) -> list[dict[str, Any]]:
        """Generate heuristic behavioral findings when no connectors are available."""
        now = datetime.now(UTC).isoformat()
        query_types = self._select_behavioral_queries(scope)

        findings: list[dict[str, Any]] = []
        for query_type in query_types:
            findings.append(
                {
                    "source": "heuristic",
                    "analysis_type": query_type,
                    "baseline_id": baseline_id,
                    "deviations": [],
                    "deviation_count": 0,
                    "severity": "low",
                    "found_at": now,
                    "note": (
                        "No live connector available; "
                        f"would run SPL query: {SPL_TEMPLATES.get(query_type, 'N/A')[:80]}..."
                    ),
                }
            )

        return findings
