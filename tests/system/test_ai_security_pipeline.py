"""End-to-end system test — validates the complete AI Security pipeline.

Simulates: webhook event -> normalization -> SOC Brain correlation ->
situation creation -> anomaly detection -> firewall block -> kill switch ->
notification -> approval request.
"""

from __future__ import annotations

import pytest
import time

from shieldops.security.vendor_telemetry_normalizer import (
    EventCategory,
    VendorSource,
    VendorTelemetryNormalizer,
)
from shieldops.security.cross_vendor_correlation import (
    CrossVendorCorrelator,
)
from shieldops.security.agent_behavioral_firewall import (
    AgentBehavioralFirewall,
    FirewallAction,
)
from shieldops.security.agent_tool_call_interceptor import (
    AgentToolCallInterceptor,
    CallDecision,
)
from shieldops.security.firewall_kill_switch_bridge import (
    EscalationConfig,
    EscalationLevel,
    FirewallKillSwitchBridge,
)
from shieldops.security.agent_kill_switch import (
    AgentKillSwitch,
    CircuitBreakerConfig,
    CircuitState,
    TripReason,
)
from shieldops.security.agent_session_revoker import AgentSessionRevoker
from shieldops.security.soc_situation_engine import (
    SOCSituationEngine,
    SituationSeverity,
    SituationStatus,
)
from shieldops.security.response_approval_workflow import (
    ApprovalPolicy,
    ApprovalStatus,
    ResponseApprovalWorkflow,
)
from shieldops.cache.firewall_cache import FirewallDecisionCache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _crowdstrike_event(entity_id: str = "device-001") -> dict:
    return {
        "behaviors": [{"tactic": "Credential Access", "technique": "T1003"}],
        "device": {"device_id": entity_id},
        "max_severity_displayname": "high",
        "id": "cs-det-001",
    }


def _defender_event(machine_id: str = "device-001") -> dict:
    return {
        "title": "Suspicious PowerShell execution",
        "machineId": machine_id,
        "severity": "high",
        "id": "def-alert-001",
    }


def _wiz_event(resource_id: str = "device-001") -> dict:
    return {
        "title": "Publicly exposed S3 bucket with sensitive data",
        "entitySnapshot": {"id": resource_id},
        "severity": "CRITICAL",
        "id": "wiz-issue-001",
    }


# ===========================================================================
# TestWebhookToSituation
# ===========================================================================


class TestWebhookToSituation:
    """Webhook events flow through normalizer to correlation and situation."""

    def test_crowdstrike_webhook_normalization(self) -> None:
        normalizer = VendorTelemetryNormalizer()
        raw = _crowdstrike_event()
        record = normalizer.ingest_event(VendorSource.CROWDSTRIKE, raw)

        assert record.vendor == VendorSource.CROWDSTRIKE
        assert record.normalized_severity == "high"
        assert record.entity_id == "device-001"
        assert record.category == EventCategory.DETECTION

    def test_defender_webhook_normalization(self) -> None:
        normalizer = VendorTelemetryNormalizer()
        raw = _defender_event()
        record = normalizer.ingest_event(VendorSource.MICROSOFT_DEFENDER, raw)

        assert record.vendor == VendorSource.MICROSOFT_DEFENDER
        # Defender "high" maps to normalized "critical"
        assert record.normalized_severity == "critical"
        assert record.entity_id == "device-001"

    def test_wiz_webhook_normalization(self) -> None:
        normalizer = VendorTelemetryNormalizer()
        raw = _wiz_event()
        record = normalizer.ingest_event(VendorSource.WIZ, raw)

        assert record.vendor == VendorSource.WIZ
        assert record.normalized_severity == "critical"
        assert record.entity_id == "device-001"

    def test_normalized_events_correlate(self) -> None:
        """Three events from different vendors for the same entity -> correlation."""
        normalizer = VendorTelemetryNormalizer()
        cs_rec = normalizer.ingest_event(VendorSource.CROWDSTRIKE, _crowdstrike_event())
        def_rec = normalizer.ingest_event(VendorSource.MICROSOFT_DEFENDER, _defender_event())
        wiz_rec = normalizer.ingest_event(VendorSource.WIZ, _wiz_event())

        correlator = CrossVendorCorrelator()
        for rec in [cs_rec, def_rec, wiz_rec]:
            correlator.add_finding(
                vendor=rec.vendor.value,
                finding={
                    "id": rec.id,
                    "entity_id": rec.entity_id,
                    "entity_type": rec.entity_type,
                    "severity": rec.normalized_severity,
                    "title": rec.title,
                    "mitre_techniques": rec.mitre_techniques,
                },
            )

        situations = correlator.correlate()
        assert len(situations) >= 1
        # The situation should span multiple vendors
        first = situations[0]
        assert len(first.vendors) >= 2


# ===========================================================================
# TestFirewallPipeline
# ===========================================================================


class TestFirewallPipeline:
    """Agent behavioral firewall detects anomalies and responds."""

    def test_normal_call_allowed(self) -> None:
        fw = AgentBehavioralFirewall()
        agent = "agent-fw-test"
        # Record baseline events
        for tool in ["query_logs", "get_metrics", "list_pods"]:
            for _ in range(5):
                fw.record_event(agent, tool)
        fw.build_baseline(agent)

        result = fw.evaluate_call(agent, "query_logs")
        assert result["action"] == FirewallAction.ALLOW.value

    def test_anomalous_call_flagged(self) -> None:
        fw = AgentBehavioralFirewall()
        agent = "agent-fw-anomaly"
        for _ in range(10):
            fw.record_event(agent, "query_logs")
        fw.build_baseline(agent)

        result = fw.evaluate_call(agent, "delete_production_database")
        # Unusual tool should raise risk
        assert result["risk_score"] >= 0.3
        assert any("unusual_tool" in r for r in result["reasons"])

    def test_rate_spike_detected(self) -> None:
        fw = AgentBehavioralFirewall(default_rate_limit=10.0)
        agent = "agent-rate-spike"
        # Build a low baseline from a few events
        for _ in range(5):
            fw.record_event(agent, "query_logs")
        fw.build_baseline(agent)

        # Now inject a burst of events to spike the rate above 2x baseline
        for _ in range(200):
            fw.record_event(agent, "query_logs")

        rate_result = fw.detect_rate_anomaly(agent, window_minutes=1)
        # Current rate should be well above the baseline
        assert rate_result["current_rate"] > 10
        assert rate_result["anomaly"] is True

    def test_interceptor_policy_blocks(self) -> None:
        interceptor = AgentToolCallInterceptor()
        # Record a prior call so rate counter is > 0
        interceptor.record_call("agent-01", "execute_command")
        interceptor.add_policy(
            tool_pattern="execute_command",
            max_rate=0.0,  # zero rate => any call exceeds limit
        )
        result = interceptor.intercept("agent-01", "execute_command")
        assert result["decision"] == CallDecision.BLOCK.value


# ===========================================================================
# TestKillSwitchPipeline
# ===========================================================================


class TestKillSwitchPipeline:
    """Anomaly detection triggers kill switch and recovery."""

    def test_bridge_trips_on_high_risk(self) -> None:
        fw = AgentBehavioralFirewall()
        ks = AgentKillSwitch()
        ks.configure(
            "agent-ks", CircuitBreakerConfig(agent_id="agent-ks", auto_trip_threshold=0.85)
        )
        bridge = FirewallKillSwitchBridge(
            config=EscalationConfig(kill_threshold=0.85),
        )

        # Feed multiple high-risk anomalies to push escalation to KILL
        for _ in range(5):
            bridge.on_anomaly_detected("agent-ks", "scope_violation", risk_score=0.9)

        level = bridge._agent_levels.get("agent-ks")
        assert level == EscalationLevel.KILL

    def test_kill_switch_revokes_sessions(self) -> None:
        ks = AgentKillSwitch()
        revoker = AgentSessionRevoker()

        ks.trip("agent-rev", reason=TripReason.BEHAVIORAL_ANOMALY, risk_score=0.95)
        assert ks.get_state("agent-rev") == CircuitState.OPEN

        revocations = revoker.revoke_all("agent-rev")
        assert len(revocations) >= 1
        assert all(r.agent_id == "agent-rev" for r in revocations)

    def test_recovery_flow(self) -> None:
        ks = AgentKillSwitch()
        ks.trip("agent-recover", reason=TripReason.BEHAVIORAL_ANOMALY, risk_score=0.9)
        assert ks.get_state("agent-recover") == CircuitState.OPEN

        # First reset: OPEN -> HALF_OPEN
        ks.reset("agent-recover")
        assert ks.get_state("agent-recover") == CircuitState.HALF_OPEN

        # Second reset: HALF_OPEN -> CLOSED
        ks.reset("agent-recover")
        assert ks.get_state("agent-recover") == CircuitState.CLOSED


# ===========================================================================
# TestSituationLifecycle
# ===========================================================================


class TestSituationLifecycle:
    """Full SOC situation workflow: create -> triage -> investigate -> close."""

    def _make_findings(self) -> list[dict]:
        return [
            {
                "id": "f-001",
                "entity_id": "host-42",
                "vendor": "crowdstrike",
                "severity": "high",
                "mitre_techniques": ["T1003"],
            },
            {
                "id": "f-002",
                "entity_id": "host-42",
                "vendor": "defender",
                "severity": "medium",
                "mitre_techniques": ["T1059"],
            },
        ]

    def test_create_and_triage(self) -> None:
        engine = SOCSituationEngine()
        sit = engine.create_situation(
            title="Credential theft on host-42",
            findings=self._make_findings(),
            severity=SituationSeverity.HIGH,
        )
        assert sit.status == SituationStatus.NEW
        assert sit.risk_score > 0
        assert "crowdstrike" in sit.vendors

    def test_update_status_flow(self) -> None:
        engine = SOCSituationEngine()
        sit = engine.create_situation(
            title="Multi-vendor alert",
            findings=self._make_findings(),
            severity=SituationSeverity.HIGH,
        )
        # Walk through the full lifecycle
        transitions = [
            SituationStatus.TRIAGING,
            SituationStatus.INVESTIGATING,
            SituationStatus.CONTAINING,
            SituationStatus.REMEDIATED,
            SituationStatus.CLOSED,
        ]
        for new_status in transitions:
            result = engine.update_status(sit.id, new_status)
            assert result is not None, f"Transition to {new_status.value} failed"
            assert result.status == new_status

    def test_approval_workflow_auto(self) -> None:
        workflow = ResponseApprovalWorkflow(
            policy=ApprovalPolicy(min_confidence_auto=0.85),
        )
        rec = workflow.request_approval(
            situation_id="sit-001",
            action_id="act-001",
            action_description="Block IP",
            confidence=0.95,
            severity="low",
        )
        assert rec.status == ApprovalStatus.AUTO_APPROVED

    def test_approval_requires_manual(self) -> None:
        workflow = ResponseApprovalWorkflow(
            policy=ApprovalPolicy(min_confidence_auto=0.85),
        )
        rec = workflow.request_approval(
            situation_id="sit-002",
            action_id="act-002",
            action_description="Isolate host",
            confidence=0.5,
            severity="high",
        )
        assert rec.status == ApprovalStatus.PENDING

        # Manually approve
        approved = workflow.approve(rec.id, responder="analyst-1")
        assert approved is not None
        assert approved.status == ApprovalStatus.APPROVED

    def test_evidence_chain(self) -> None:
        engine = SOCSituationEngine()
        sit = engine.create_situation(
            title="Evidence chain test",
            findings=self._make_findings(),
            severity=SituationSeverity.MEDIUM,
        )
        # Execute actions to build evidence
        engine.update_status(sit.id, SituationStatus.TRIAGING)
        engine.execute_action(
            sit.id,
            action_type=__import__(
                "shieldops.security.soc_situation_engine", fromlist=["ActionType"]
            ).ActionType.INVESTIGATE,
        )

        refreshed = engine.get_situation(sit.id)
        assert refreshed is not None
        assert len(refreshed.actions_taken) >= 1
        assert refreshed.timestamps.get("investigating") or refreshed.timestamps.get("triaging")


# ===========================================================================
# TestCacheIntegration
# ===========================================================================


class TestCacheIntegration:
    """FirewallDecisionCache integrates with firewall evaluation."""

    @pytest.mark.asyncio
    async def test_cached_decision_returned(self) -> None:
        cache = FirewallDecisionCache(redis_client=None, decision_ttl=60)
        decision = {"action": "allow", "risk_score": 0.1, "reasons": ["cached"]}
        args_hash = cache.hash_args({"tool": "query_logs"})

        await cache.set_decision("agent-cache", "query_logs", args_hash, decision)
        result = await cache.get_decision("agent-cache", "query_logs", args_hash)

        assert result is not None
        assert result["action"] == "allow"
        assert cache._stats["hits"] >= 1

    @pytest.mark.asyncio
    async def test_cache_miss_evaluates(self) -> None:
        cache = FirewallDecisionCache(redis_client=None, decision_ttl=60)
        args_hash = cache.hash_args({"tool": "unknown"})

        result = await cache.get_decision("agent-miss", "unknown_tool", args_hash)
        assert result is None
        assert cache._stats["misses"] >= 1

        # Fallback: evaluate via firewall
        fw = AgentBehavioralFirewall()
        eval_result = fw.evaluate_call("agent-miss", "unknown_tool")
        assert eval_result["action"] == FirewallAction.ALLOW.value  # no baseline => allow
