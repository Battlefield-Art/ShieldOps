"""Tool functions for the Multi-Agent Security Agent."""

from __future__ import annotations

import hashlib
import time
from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()


class MultiAgentSecurityToolkit:
    """Toolkit for securing multi-agent communication and trust chains.

    Bridges the agent to infrastructure connectors, identity registries, and
    policy engines.  When no real backend is injected the methods return
    realistic simulated data so the graph can run end-to-end in dev/test.
    """

    def __init__(
        self,
        identity_registry: Any | None = None,
        policy_engine: Any | None = None,
        message_bus: Any | None = None,
        telemetry: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._identity_registry = identity_registry
        self._policy_engine = policy_engine
        self._message_bus = message_bus
        self._telemetry = telemetry
        self._repository = repository

    # ------------------------------------------------------------------
    # 1. Discover interactions
    # ------------------------------------------------------------------

    async def discover_interactions(
        self,
        scope: dict[str, Any],
        agent_registry: list[str],
    ) -> list[dict[str, Any]]:
        """Discover agent-to-agent interactions within the given scope.

        In production this queries the message bus / telemetry backend.
        """
        logger.info(
            "multi_agent_security.discover_interactions",
            scope_keys=list(scope.keys()),
            agent_count=len(agent_registry),
        )

        if self._message_bus is not None:
            return await self._message_bus.get_interactions(scope, agent_registry)

        # --- simulated interaction data ---
        ts = int(time.time())
        interactions: list[dict[str, Any]] = [
            {
                "interaction_id": f"int-{uuid4().hex[:8]}",
                "source_agent": "investigation_agent",
                "target_agent": "remediation_agent",
                "channel": "internal_bus",
                "message_type": "action_request",
                "payload_hash": hashlib.sha256(b"remediate-host-42").hexdigest(),
                "timestamp": ts,
                "tools_requested": ["isolate_host", "block_ip"],
                "data_labels": ["pii", "infrastructure"],
            },
            {
                "interaction_id": f"int-{uuid4().hex[:8]}",
                "source_agent": "unknown_agent_x",
                "target_agent": "remediation_agent",
                "channel": "external_api",
                "message_type": "action_request",
                "payload_hash": hashlib.sha256(b"delete-database-prod").hexdigest(),
                "timestamp": ts - 30,
                "tools_requested": ["drop_table", "delete_bucket"],
                "data_labels": ["critical_infra"],
            },
            {
                "interaction_id": f"int-{uuid4().hex[:8]}",
                "source_agent": "learning_agent",
                "target_agent": "investigation_agent",
                "channel": "internal_bus",
                "message_type": "data_share",
                "payload_hash": hashlib.sha256(b"model-weights-v3").hexdigest(),
                "timestamp": ts - 60,
                "tools_requested": [],
                "data_labels": ["model_weights", "proprietary"],
            },
            {
                "interaction_id": f"int-{uuid4().hex[:8]}",
                "source_agent": "investigation_agent",
                "target_agent": "soc_brain_agent",
                "channel": "internal_bus",
                "message_type": "telemetry",
                "payload_hash": hashlib.sha256(b"alert-feed").hexdigest(),
                "timestamp": ts - 90,
                "tools_requested": ["query_siem"],
                "data_labels": ["alerts"],
            },
            {
                "interaction_id": f"int-{uuid4().hex[:8]}",
                "source_agent": "investigation_agent",
                "target_agent": "remediation_agent",
                "channel": "internal_bus",
                "message_type": "action_request",
                "payload_hash": hashlib.sha256(b"remediate-host-42-TAMPERED").hexdigest(),
                "timestamp": ts - 5,
                "tools_requested": ["isolate_host"],
                "data_labels": [],
            },
        ]
        return interactions

    # ------------------------------------------------------------------
    # 2. Map trust chains
    # ------------------------------------------------------------------

    async def map_trust_chains(
        self,
        interactions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Build delegation / trust chains from observed interactions."""
        logger.info(
            "multi_agent_security.map_trust_chains",
            interaction_count=len(interactions),
        )

        if self._identity_registry is not None:
            return await self._identity_registry.resolve_trust_chains(interactions)

        # Build adjacency from interactions
        edges: dict[str, set[str]] = {}
        tool_map: dict[str, set[str]] = {}
        for ix in interactions:
            src = ix.get("source_agent", "")
            tgt = ix.get("target_agent", "")
            edges.setdefault(src, set()).add(tgt)
            for tool in ix.get("tools_requested", []):
                tool_map.setdefault(tgt, set()).add(tool)

        chains: list[dict[str, Any]] = []
        for root, targets in edges.items():
            chain_agents = [root, *sorted(targets)]
            depth = len(chain_agents) - 1

            # Detect privilege escalation: destructive tools accessed via proxy
            destructive_tools = {"drop_table", "delete_bucket", "modify_iam"}
            proxy_tools = set()
            priv_esc = False
            for tgt in targets:
                tgt_tools = tool_map.get(tgt, set())
                overlap = tgt_tools & destructive_tools
                if overlap:
                    priv_esc = True
                    proxy_tools.update(overlap)

            # Trust level heuristic
            if priv_esc:
                trust = "compromised"
            elif depth > 3 or any(a.startswith("unknown") for a in chain_agents):
                trust = "untrusted"
            else:
                trust = "verified"

            chains.append(
                {
                    "chain_id": f"chain-{uuid4().hex[:8]}",
                    "root_agent": root,
                    "chain": chain_agents,
                    "trust_level": trust,
                    "delegation_depth": depth,
                    "privilege_escalation_detected": priv_esc,
                    "proxy_tool_access": sorted(proxy_tools),
                }
            )
        return chains

    # ------------------------------------------------------------------
    # 3. Verify communications
    # ------------------------------------------------------------------

    async def verify_communications(
        self,
        interactions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Verify message integrity and agent identity for each interaction."""
        logger.info(
            "multi_agent_security.verify_communications",
            interaction_count=len(interactions),
        )

        if self._identity_registry is not None:
            return await self._identity_registry.verify_identities(interactions)

        results: list[dict[str, Any]] = []
        seen_hashes: dict[str, str] = {}  # hash -> first interaction_id

        for ix in interactions:
            iid = ix.get("interaction_id", "")
            h = ix.get("payload_hash", "")
            src = ix.get("source_agent", "")
            channel = ix.get("channel", "")

            # Replay detection — same hash seen before
            replay = h in seen_hashes
            seen_hashes.setdefault(h, iid)

            # Identity verification — unknown agents or external channels
            identity_ok = not src.startswith("unknown") and channel != "external_api"

            # Impersonation risk scoring
            impersonation = 0.0
            tampering: list[str] = []
            if not identity_ok:
                impersonation = 0.85
                tampering.append("unregistered_agent_identity")
            if channel == "external_api":
                impersonation = max(impersonation, 0.6)
                tampering.append("external_channel_unverified")
            if replay:
                tampering.append("replay_detected")
                impersonation = max(impersonation, 0.4)

            # Hash validity — in production compare with signed originals
            hash_valid = not replay

            results.append(
                {
                    "interaction_id": iid,
                    "hash_valid": hash_valid,
                    "identity_verified": identity_ok,
                    "replay_detected": replay,
                    "impersonation_risk": round(impersonation, 2),
                    "tampering_indicators": tampering,
                }
            )
        return results

    # ------------------------------------------------------------------
    # 4. Detect anomalies
    # ------------------------------------------------------------------

    async def detect_anomalies(
        self,
        interactions: list[dict[str, Any]],
        trust_chains: list[dict[str, Any]],
        verifications: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect security anomalies across interactions, trust chains, and
        verification results."""
        logger.info(
            "multi_agent_security.detect_anomalies",
            interaction_count=len(interactions),
            chain_count=len(trust_chains),
            verification_count=len(verifications),
        )

        anomalies: list[dict[str, Any]] = []

        # A. Impersonation anomalies from verification
        for v in verifications:
            if not v.get("identity_verified"):
                anomalies.append(
                    {
                        "anomaly_id": f"anom-{uuid4().hex[:8]}",
                        "anomaly_type": "agent_impersonation",
                        "severity": "critical",
                        "description": (
                            f"Agent identity could not be verified for "
                            f"interaction {v.get('interaction_id')}"
                        ),
                        "source_agent": "",
                        "target_agent": "",
                        "confidence": v.get("impersonation_risk", 0.0),
                        "mitre_technique": "T1078.004",
                        "evidence": v.get("tampering_indicators", []),
                    }
                )
            if v.get("replay_detected"):
                anomalies.append(
                    {
                        "anomaly_id": f"anom-{uuid4().hex[:8]}",
                        "anomaly_type": "message_replay",
                        "severity": "high",
                        "description": (
                            f"Duplicate payload hash detected — possible message "
                            f"replay for interaction {v.get('interaction_id')}"
                        ),
                        "source_agent": "",
                        "target_agent": "",
                        "confidence": 0.75,
                        "mitre_technique": "T1557",
                        "evidence": ["duplicate_payload_hash"],
                    }
                )

        # B. Privilege escalation through delegation chains
        for chain in trust_chains:
            if chain.get("privilege_escalation_detected"):
                anomalies.append(
                    {
                        "anomaly_id": f"anom-{uuid4().hex[:8]}",
                        "anomaly_type": "privilege_escalation_via_delegation",
                        "severity": "critical",
                        "description": (
                            f"Destructive tools accessed through delegation chain "
                            f"rooted at {chain.get('root_agent')}: "
                            f"{chain.get('proxy_tool_access')}"
                        ),
                        "source_agent": chain.get("root_agent", ""),
                        "target_agent": chain.get("chain", [""])[-1],
                        "confidence": 0.9,
                        "mitre_technique": "T1548",
                        "evidence": chain.get("proxy_tool_access", []),
                    }
                )

        # C. Data leakage through inter-agent channels
        sensitive_labels = {"pii", "proprietary", "model_weights", "critical_infra"}
        for ix in interactions:
            labels = set(ix.get("data_labels", []))
            if labels & sensitive_labels and ix.get("channel") == "external_api":
                anomalies.append(
                    {
                        "anomaly_id": f"anom-{uuid4().hex[:8]}",
                        "anomaly_type": "data_leakage_via_channel",
                        "severity": "high",
                        "description": (
                            f"Sensitive data labels {sorted(labels & sensitive_labels)} "
                            f"transmitted over external channel from "
                            f"{ix.get('source_agent')} to {ix.get('target_agent')}"
                        ),
                        "source_agent": ix.get("source_agent", ""),
                        "target_agent": ix.get("target_agent", ""),
                        "confidence": 0.8,
                        "mitre_technique": "T1041",
                        "evidence": sorted(labels & sensitive_labels),
                    }
                )

        # D. Unauthorised tool access via agent proxying
        restricted_tools = {"drop_table", "delete_bucket", "modify_iam", "disable_mfa"}
        for ix in interactions:
            requested = set(ix.get("tools_requested", []))
            overlap = requested & restricted_tools
            if overlap:
                anomalies.append(
                    {
                        "anomaly_id": f"anom-{uuid4().hex[:8]}",
                        "anomaly_type": "unauthorised_tool_proxy",
                        "severity": "critical",
                        "description": (
                            f"Restricted tools {sorted(overlap)} requested by "
                            f"{ix.get('source_agent')} via {ix.get('target_agent')}"
                        ),
                        "source_agent": ix.get("source_agent", ""),
                        "target_agent": ix.get("target_agent", ""),
                        "confidence": 0.95,
                        "mitre_technique": "T1210",
                        "evidence": sorted(overlap),
                    }
                )

        return anomalies

    # ------------------------------------------------------------------
    # 5. Enforce policies
    # ------------------------------------------------------------------

    async def enforce_policies(
        self,
        anomalies: list[dict[str, Any]],
        interactions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Enforce security policies based on detected anomalies.

        Returns enforcement actions taken (block, quarantine, alert).
        """
        logger.info(
            "multi_agent_security.enforce_policies",
            anomaly_count=len(anomalies),
        )

        if self._policy_engine is not None:
            return await self._policy_engine.evaluate_multi_agent(anomalies, interactions)

        actions: list[dict[str, Any]] = []
        quarantined: set[str] = set()
        blocked = 0

        for anom in anomalies:
            sev = anom.get("severity", "low")
            atype = anom.get("anomaly_type", "")
            src = anom.get("source_agent", "")

            if sev == "critical":
                actions.append(
                    {
                        "action": "block_and_quarantine",
                        "anomaly_id": anom.get("anomaly_id"),
                        "target": src or "unknown",
                        "reason": atype,
                        "description": (
                            f"Blocked interaction and quarantined agent {src} due to {atype}"
                        ),
                    }
                )
                if src:
                    quarantined.add(src)
                blocked += 1
            elif sev == "high":
                actions.append(
                    {
                        "action": "block_interaction",
                        "anomaly_id": anom.get("anomaly_id"),
                        "target": src or "unknown",
                        "reason": atype,
                        "description": f"Blocked interaction due to {atype}",
                    }
                )
                blocked += 1
            else:
                actions.append(
                    {
                        "action": "alert",
                        "anomaly_id": anom.get("anomaly_id"),
                        "target": src or "unknown",
                        "reason": atype,
                        "description": f"Alert raised for {atype}",
                    }
                )

        return {
            "actions": actions,
            "blocked_interactions": blocked,
            "quarantined_agents": sorted(quarantined),
        }
