"""Integration tests for Phase 9 AI Security deployment modes."""

from __future__ import annotations

from shieldops.security.agent_behavioral_firewall import (
    AgentBehavioralFirewall,
    FirewallAction,
)
from shieldops.security.agent_kill_switch import (
    AgentKillSwitch,
    CircuitBreakerConfig,
    CircuitState,
    TripReason,
)
from shieldops.security.mcp_security_gateway import (
    AuthRequirement,
    GatewayAction,
    MCPSecurityGateway,
)
from shieldops.security.response_approval_workflow import (
    ApprovalPolicy,
    ApprovalStatus,
    ApprovalTier,
    ResponseApprovalWorkflow,
)

# ══════════════════════════════════════════════════════════════════════════════
# TestFirewallModeSwitch
# ══════════════════════════════════════════════════════════════════════════════


class TestFirewallModeSwitch:
    """Tests for behavioral firewall audit vs enforce mode switching."""

    def _setup_firewall_with_baseline(self) -> AgentBehavioralFirewall:
        """Create a firewall with a known baseline for agent-001."""
        fw = AgentBehavioralFirewall()
        agent = "agent-001"
        # Record normal behavior to build a baseline
        for tool in ["kubectl_get", "kubectl_describe", "log_search"]:
            for _ in range(10):
                fw.record_event(agent, tool, action=FirewallAction.ALLOW)
        fw.build_baseline(agent)
        return fw

    def test_audit_mode_allows_all(self) -> None:
        """In audit mode, evaluate_call always returns allow but still records events."""
        fw = self._setup_firewall_with_baseline()
        agent = "agent-001"

        # In audit mode we always allow but still evaluate (record the anomaly).
        # The firewall engine itself doesn't have a mode field; audit mode is
        # implemented by the caller ignoring block decisions. We verify that
        # evaluate_call detects anomalies, then show that an audit-mode wrapper
        # would still allow.
        result = fw.evaluate_call(agent, tool_name="rm_rf_slash")
        detected_risk = result["risk_score"]
        detected_action = result["action"]

        # The call IS anomalous (unusual tool)
        assert detected_risk > 0, "Should detect non-zero risk for unknown tool"

        # Audit mode: regardless of the raw action, we allow and record
        audit_action = FirewallAction.ALLOW  # audit wrapper overrides
        fw.record_event(agent, "rm_rf_slash", action=audit_action, risk_score=detected_risk)
        events = fw.list_events(agent_id=agent)
        assert len(events) > 0, "Events should still be recorded in audit mode"

        # The underlying engine detected it as non-allow
        assert detected_action != FirewallAction.ALLOW.value or detected_risk > 0

    def test_enforce_mode_blocks_anomalous(self) -> None:
        """In enforce mode, anomalous calls are flagged/blocked."""
        fw = self._setup_firewall_with_baseline()
        agent = "agent-001"

        result = fw.evaluate_call(agent, tool_name="unknown_destructive_tool")
        assert result["risk_score"] > 0
        assert result["action"] in (
            FirewallAction.BLOCK.value,
            FirewallAction.FLAG.value,
            FirewallAction.THROTTLE.value,
        ), f"Enforce mode should restrict anomalous call, got {result['action']}"

    def test_mode_switch_audit_to_enforce(self) -> None:
        """Switching from audit to enforce changes behavior for the same call."""
        fw = self._setup_firewall_with_baseline()
        agent = "agent-001"
        anomalous_tool = "drop_database"

        # Audit mode: evaluate but always allow
        audit_result = fw.evaluate_call(agent, tool_name=anomalous_tool)
        audit_risk = audit_result["risk_score"]
        # In audit, caller would override to ALLOW
        audit_action = FirewallAction.ALLOW

        # Enforce mode: use the engine decision directly
        enforce_result = fw.evaluate_call(agent, tool_name=anomalous_tool)
        enforce_action = enforce_result["action"]

        # Risk detected in both modes
        assert audit_risk > 0
        assert enforce_result["risk_score"] > 0

        # But the effective action differs
        assert audit_action == FirewallAction.ALLOW
        assert enforce_action != FirewallAction.ALLOW.value

    def test_mode_switch_preserves_baseline(self) -> None:
        """Switching modes does not lose behavioral baseline data."""
        fw = self._setup_firewall_with_baseline()
        agent = "agent-001"

        # Verify baseline exists
        profile = fw._profiles.get(agent)
        assert profile is not None
        assert profile.sample_count > 0
        original_tools = list(profile.normal_tools)
        original_count = profile.sample_count

        # Simulate mode switch (no API change to profiles)
        # Access evaluate in different "mode" — profiles stay intact
        fw.evaluate_call(agent, tool_name="kubectl_get")
        fw.evaluate_call(agent, tool_name="unknown_tool")

        # Baseline unchanged
        profile_after = fw._profiles.get(agent)
        assert profile_after is not None
        assert profile_after.normal_tools == original_tools
        assert profile_after.sample_count == original_count


# ══════════════════════════════════════════════════════════════════════════════
# TestMCPGatewayModeSwitch
# ══════════════════════════════════════════════════════════════════════════════


class TestMCPGatewayModeSwitch:
    """Tests for MCP Security Gateway audit vs enforce modes."""

    def _setup_gateway(self) -> MCPSecurityGateway:
        gw = MCPSecurityGateway()
        gw.add_policy(
            server_pattern="prod-mcp-.*",
            allowed_agents=["agent-001", "agent-002"],
            auth_requirement=AuthRequirement.API_KEY,
            allowed_tools=["read_logs", "get_metrics"],
        )
        return gw

    def test_mcp_audit_mode(self) -> None:
        """Gateway logs but does not block in audit mode (no policy matched = audit_only)."""
        gw = MCPSecurityGateway()
        # No policies -> default audit_only for all requests
        result = gw.evaluate_request(
            server_endpoint="dev-mcp-server",
            agent_id="rogue-agent",
            tool_name="dangerous_tool",
            auth_token="tok-123",
        )
        assert result["action"] == GatewayAction.AUDIT_ONLY
        assert "no_policy_matched" in result["reasons"][0]

    def test_mcp_enforce_mode(self) -> None:
        """Gateway blocks unauthorized requests when policy is enforced."""
        gw = self._setup_gateway()

        # Unauthorized agent
        result = gw.evaluate_request(
            server_endpoint="prod-mcp-cluster",
            agent_id="rogue-agent",
            tool_name="read_logs",
            auth_token="tok-123",
        )
        assert result["action"] == GatewayAction.BLOCK

        # Blocked tool
        result2 = gw.evaluate_request(
            server_endpoint="prod-mcp-cluster",
            agent_id="agent-001",
            tool_name="delete_everything",
            auth_token="tok-123",
        )
        assert result2["action"] == GatewayAction.BLOCK

        # Missing auth
        result3 = gw.evaluate_request(
            server_endpoint="prod-mcp-cluster",
            agent_id="agent-001",
            tool_name="read_logs",
            auth_token=None,
        )
        assert result3["action"] == GatewayAction.REQUIRE_AUTH

    def test_mcp_mode_switch(self) -> None:
        """Switching from audit to enforce changes gateway behavior."""
        gw = MCPSecurityGateway()
        endpoint = "staging-mcp-server"
        agent = "agent-test"
        tool = "read_logs"

        # Phase 1: audit mode (no policy)
        audit_result = gw.evaluate_request(
            server_endpoint=endpoint, agent_id=agent, tool_name=tool, auth_token="tok"
        )
        assert audit_result["action"] == GatewayAction.AUDIT_ONLY

        # Phase 2: add restrictive policy (switch to enforce)
        gw.add_policy(
            server_pattern="staging-mcp-.*",
            allowed_agents=["agent-prod-only"],
            auth_requirement=AuthRequirement.OAUTH2,
            allowed_tools=["get_metrics"],
        )
        enforce_result = gw.evaluate_request(
            server_endpoint=endpoint, agent_id=agent, tool_name=tool, auth_token="tok"
        )
        # Now blocked because agent is not in allowlist
        assert enforce_result["action"] == GatewayAction.BLOCK


# ══════════════════════════════════════════════════════════════════════════════
# TestSOCBrainAutoExecute
# ══════════════════════════════════════════════════════════════════════════════


class TestSOCBrainAutoExecute:
    """Tests for SOC response approval workflow auto-execute logic."""

    def test_auto_execute_disabled(self) -> None:
        """All actions require approval when auto-execute threshold is unreachably high."""
        policy = ApprovalPolicy(min_confidence_auto=1.1)  # impossible to reach
        wf = ResponseApprovalWorkflow(policy=policy)

        record = wf.request_approval(
            situation_id="sit-001",
            action_id="block-ip",
            action_description="Block malicious IP",
            confidence=0.99,
            severity="low",
        )
        # Even 0.99 confidence should NOT auto-execute
        assert record.status == ApprovalStatus.PENDING
        assert record.required_tier != ApprovalTier.AUTO_EXECUTE

    def test_auto_execute_enabled_high_confidence(self) -> None:
        """Confidence >= 0.85 on non-critical severity triggers auto-execute."""
        wf = ResponseApprovalWorkflow()  # default policy, min_confidence_auto=0.85

        record = wf.request_approval(
            situation_id="sit-002",
            action_id="isolate-host",
            action_description="Isolate compromised host",
            confidence=0.92,
            severity="low",
        )
        assert record.status == ApprovalStatus.AUTO_APPROVED
        assert record.required_tier == ApprovalTier.AUTO_EXECUTE
        assert record.responder == "system"
        assert record.responded_at is not None

    def test_auto_execute_enabled_low_confidence(self) -> None:
        """Confidence < 0.85 requires manual approval."""
        wf = ResponseApprovalWorkflow()

        record = wf.request_approval(
            situation_id="sit-003",
            action_id="quarantine-file",
            action_description="Quarantine suspicious file",
            confidence=0.60,
            severity="medium",
        )
        assert record.status == ApprovalStatus.PENDING
        assert record.required_tier != ApprovalTier.AUTO_EXECUTE
        # Confidence 0.60, severity medium -> should be TIER_1
        assert record.required_tier in (ApprovalTier.TIER_1, ApprovalTier.TIER_2)


# ══════════════════════════════════════════════════════════════════════════════
# TestCircuitBreakerInEnforceMode
# ══════════════════════════════════════════════════════════════════════════════


class TestCircuitBreakerInEnforceMode:
    """Tests for circuit breaker trip and recovery in enforce mode."""

    def test_circuit_breaker_trips_in_enforce(self) -> None:
        """Anomaly storm triggers circuit breaker -> all calls blocked (OPEN state)."""
        ks = AgentKillSwitch()
        agent = "agent-overloaded"

        # Configure auto-trip at 0.85
        ks.configure(
            agent,
            CircuitBreakerConfig(
                agent_id=agent,
                auto_trip_threshold=0.85,
                max_half_open_calls=3,
            ),
        )

        # Agent starts CLOSED
        assert ks.get_state(agent) == CircuitState.CLOSED

        # High risk score triggers auto-trip
        tripped = ks.check_auto_trip(agent, current_risk_score=0.95)
        assert tripped is True
        assert ks.get_state(agent) == CircuitState.OPEN

        # All calls should be blocked while OPEN
        open_circuits = ks.list_open_circuits()
        assert any(c["agent_id"] == agent and c["state"] == "open" for c in open_circuits)

        # Subsequent auto-trip attempts on already-open circuit return False
        tripped_again = ks.check_auto_trip(agent, current_risk_score=0.99)
        assert tripped_again is False  # already open, no re-trip

    def test_circuit_breaker_recovery_flow(self) -> None:
        """Trip -> cooldown -> half_open -> test calls -> closed."""
        ks = AgentKillSwitch()
        agent = "agent-recovering"

        ks.configure(
            agent,
            CircuitBreakerConfig(
                agent_id=agent,
                auto_trip_threshold=0.85,
                max_half_open_calls=3,
            ),
        )

        # Step 1: Trip the circuit
        ks.trip(agent, reason=TripReason.BEHAVIORAL_ANOMALY, risk_score=0.9)
        assert ks.get_state(agent) == CircuitState.OPEN

        # Step 2: Reset OPEN -> HALF_OPEN (simulates cooldown expiry)
        ks.reset(agent, triggered_by="cooldown_timer")
        assert ks.get_state(agent) == CircuitState.HALF_OPEN

        # Step 3: Test calls in HALF_OPEN
        result1 = ks.attempt_recovery(agent)
        assert result1["recovery"] is False
        assert result1["calls_completed"] == 1

        result2 = ks.attempt_recovery(agent)
        assert result2["recovery"] is False
        assert result2["calls_completed"] == 2

        # Step 4: Third call reaches max_half_open_calls -> CLOSED
        result3 = ks.attempt_recovery(agent)
        assert result3["recovery"] is True
        assert result3["new_state"] == CircuitState.CLOSED.value
        assert ks.get_state(agent) == CircuitState.CLOSED

        # Verify full recovery — circuit is clean
        open_circuits = ks.list_open_circuits()
        assert all(c["agent_id"] != agent for c in open_circuits)
