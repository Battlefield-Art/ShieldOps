"""Tests for ShieldOps Agent Firewall SDK — interceptor.py and config.py."""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.sdk.config import SDKConfig, SDKMode
from shieldops.sdk.interceptor import (
    _DEFAULT_BLOCKED_PATTERNS,
    _HIGH_RISK_PATTERNS,
    AuditEvent,
    InterceptResult,
    ShieldOpsInterceptor,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_config() -> SDKConfig:
    """SDKConfig in audit mode with small batch size for testing."""
    return SDKConfig(
        api_key="test-key-123",
        endpoint="https://test.shieldops.io",
        mode=SDKMode.AUDIT,
        agent_id="test-agent",
        max_batch_size=3,
    )


@pytest.fixture
def enforce_config() -> SDKConfig:
    """SDKConfig in enforce mode with small batch size for testing."""
    return SDKConfig(
        api_key="test-key-456",
        endpoint="https://test.shieldops.io",
        mode=SDKMode.ENFORCE,
        agent_id="enforce-agent",
        max_batch_size=3,
    )


@pytest.fixture
def audit_interceptor(audit_config: SDKConfig) -> ShieldOpsInterceptor:
    return ShieldOpsInterceptor(audit_config)


@pytest.fixture
def enforce_interceptor(enforce_config: SDKConfig) -> ShieldOpsInterceptor:
    return ShieldOpsInterceptor(enforce_config)


# ---------------------------------------------------------------------------
# TestSDKConfig
# ---------------------------------------------------------------------------


class TestSDKConfig:
    """Tests for SDKConfig defaults, properties, and validation."""

    def test_default_endpoint(self):
        cfg = SDKConfig()
        assert cfg.endpoint == "https://api.shieldops.io"

    def test_default_mode_is_audit(self):
        cfg = SDKConfig()
        assert cfg.mode == SDKMode.AUDIT

    def test_default_batch_size(self):
        cfg = SDKConfig()
        assert cfg.max_batch_size == 100

    def test_default_flush_interval(self):
        cfg = SDKConfig()
        assert cfg.flush_interval_seconds == 10

    def test_default_timeout(self):
        cfg = SDKConfig()
        assert cfg.timeout_seconds == 5

    def test_default_policy_cache_ttl(self):
        cfg = SDKConfig()
        assert cfg.policy_cache_ttl_seconds == 300

    def test_default_verify_ssl(self):
        cfg = SDKConfig()
        assert cfg.verify_ssl is True

    def test_default_api_key_empty(self):
        cfg = SDKConfig()
        assert cfg.api_key == ""

    def test_default_agent_id_none(self):
        cfg = SDKConfig()
        assert cfg.agent_id is None

    def test_is_audit_when_audit_mode(self):
        cfg = SDKConfig(mode=SDKMode.AUDIT)
        assert cfg.is_audit is True
        assert cfg.is_enforce is False

    def test_is_enforce_when_enforce_mode(self):
        cfg = SDKConfig(mode=SDKMode.ENFORCE)
        assert cfg.is_enforce is True
        assert cfg.is_audit is False

    def test_mode_string_coercion(self):
        cfg = SDKConfig(mode="enforce")  # type: ignore[arg-type]
        assert cfg.is_enforce is True

    def test_custom_values_round_trip(self):
        cfg = SDKConfig(
            api_key="sk-xxx",
            endpoint="https://custom.io",
            mode=SDKMode.ENFORCE,
            agent_id="my-agent",
            flush_interval_seconds=30,
            max_batch_size=50,
            timeout_seconds=15,
            policy_cache_ttl_seconds=600,
            verify_ssl=False,
        )
        assert cfg.api_key == "sk-xxx"
        assert cfg.endpoint == "https://custom.io"
        assert cfg.agent_id == "my-agent"
        assert cfg.flush_interval_seconds == 30
        assert cfg.max_batch_size == 50
        assert cfg.timeout_seconds == 15
        assert cfg.policy_cache_ttl_seconds == 600
        assert cfg.verify_ssl is False


# ---------------------------------------------------------------------------
# TestToolDetection
# ---------------------------------------------------------------------------


class TestToolDetection:
    """Tests for blocked-pattern and high-risk pattern detection."""

    @pytest.mark.parametrize("tool_name", sorted(_DEFAULT_BLOCKED_PATTERNS))
    def test_blocked_tool_detected_with_risk_score_1(
        self, audit_interceptor: ShieldOpsInterceptor, tool_name: str
    ):
        result = audit_interceptor.intercept(tool_name)
        assert result.risk_score == pytest.approx(1.0)
        assert "blocked pattern" in result.reasons[0].lower()

    @pytest.mark.parametrize("tool_name", sorted(_HIGH_RISK_PATTERNS))
    def test_high_risk_tool_detected_with_risk_score_07(
        self, audit_interceptor: ShieldOpsInterceptor, tool_name: str
    ):
        result = audit_interceptor.intercept(tool_name)
        assert result.risk_score == pytest.approx(0.7)
        assert "high-risk" in result.reasons[0].lower()

    def test_normal_tool_gets_no_policy_violation(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("read_file")
        assert result.risk_score == pytest.approx(0.0)
        assert result.reasons == ["No policy violations detected"]

    def test_blocked_tool_case_insensitive(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("DELETE_DATABASE")
        assert result.risk_score == pytest.approx(1.0)

    def test_blocked_tool_with_whitespace(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("  delete_database  ")
        assert result.risk_score == pytest.approx(1.0)

    def test_call_count_increments(self, audit_interceptor: ShieldOpsInterceptor):
        assert audit_interceptor._call_count == 0
        audit_interceptor.intercept("read_file")
        audit_interceptor.intercept("write_file")
        assert audit_interceptor._call_count == 2


# ---------------------------------------------------------------------------
# TestRiskScoring
# ---------------------------------------------------------------------------


class TestRiskScoring:
    """Tests for argument heuristics and risk score adjustments."""

    def test_production_arg_adds_02(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("deploy_service", args={"env": "production"})
        assert result.risk_score == pytest.approx(0.2)
        assert any("production" in r.lower() for r in result.reasons)

    def test_prod_shorthand_adds_02(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("deploy_service", args={"env": "prod"})
        assert result.risk_score == pytest.approx(0.2)

    def test_wildcard_star_adds_01(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("list_resources", args={"filter": "*"})
        assert result.risk_score == pytest.approx(0.1)
        assert any("wildcard" in r.lower() for r in result.reasons)

    def test_wildcard_word_adds_01(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("list_resources", args={"filter": "wildcard"})
        assert result.risk_score == pytest.approx(0.1)

    def test_production_and_wildcard_stack(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept(
            "deploy_service", args={"env": "production", "scope": "*"}
        )
        assert result.risk_score == pytest.approx(0.3)

    def test_high_risk_plus_production_capped_at_09(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("execute_command", args={"env": "production"})
        assert result.risk_score == pytest.approx(0.9)

    def test_blocked_plus_args_capped_at_1(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept(
            "delete_database", args={"env": "production", "scope": "*"}
        )
        assert result.risk_score == pytest.approx(1.0), "Risk score should cap at 1.0"

    def test_no_args_no_heuristic_boost(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("deploy_service")
        assert result.risk_score == pytest.approx(0.0)

    def test_empty_args_dict_no_boost(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("deploy_service", args={})
        assert result.risk_score == pytest.approx(0.0)

    def test_none_args_no_boost(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("deploy_service", args=None)
        assert result.risk_score == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# TestAuditMode
# ---------------------------------------------------------------------------


class TestAuditMode:
    """Tests that audit mode logs but never blocks."""

    def test_blocked_tool_allowed_in_audit_mode(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("delete_database")
        assert result.decision == "allow", "Audit mode must never block"
        assert result.risk_score == pytest.approx(1.0)

    def test_high_risk_tool_allowed_in_audit_mode(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("execute_command")
        assert result.decision == "allow"

    def test_block_count_stays_zero_in_audit_mode(self, audit_interceptor: ShieldOpsInterceptor):
        for tool in _DEFAULT_BLOCKED_PATTERNS:
            audit_interceptor.intercept(tool)
        assert audit_interceptor._block_count == 0

    def test_intercept_result_has_request_id(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("read_file")
        assert result.request_id, "request_id must be populated"
        assert len(result.request_id) > 0

    def test_intercept_result_has_evaluated_at(self, audit_interceptor: ShieldOpsInterceptor):
        result = audit_interceptor.intercept("read_file")
        assert result.evaluated_at > 0


# ---------------------------------------------------------------------------
# TestEnforceMode
# ---------------------------------------------------------------------------


class TestEnforceMode:
    """Tests that enforce mode blocks risky calls."""

    def test_blocked_tool_blocked_in_enforce_mode(self, enforce_interceptor: ShieldOpsInterceptor):
        result = enforce_interceptor.intercept("delete_database")
        assert result.decision == "block"
        assert result.risk_score == pytest.approx(1.0)

    def test_block_count_increments_in_enforce_mode(
        self, enforce_interceptor: ShieldOpsInterceptor
    ):
        enforce_interceptor.intercept("delete_database")
        enforce_interceptor.intercept("drop_table")
        assert enforce_interceptor._block_count == 2

    def test_high_risk_tool_allowed_in_enforce_mode(
        self, enforce_interceptor: ShieldOpsInterceptor
    ):
        result = enforce_interceptor.intercept("execute_command")
        assert result.decision == "allow", "High-risk tools are not blocked, only blocked-pattern"
        assert result.risk_score == pytest.approx(0.7)

    def test_normal_tool_allowed_in_enforce_mode(self, enforce_interceptor: ShieldOpsInterceptor):
        result = enforce_interceptor.intercept("read_file")
        assert result.decision == "allow"

    @pytest.mark.parametrize("tool_name", sorted(_DEFAULT_BLOCKED_PATTERNS))
    def test_all_blocked_patterns_blocked_in_enforce(
        self, enforce_interceptor: ShieldOpsInterceptor, tool_name: str
    ):
        result = enforce_interceptor.intercept(tool_name)
        assert result.decision == "block"

    def test_agent_id_override_in_intercept(self, enforce_interceptor: ShieldOpsInterceptor):
        """Passing agent_id to intercept() should not change config agent_id."""
        enforce_interceptor.intercept("read_file", agent_id="override-agent")
        assert enforce_interceptor._config.agent_id == "enforce-agent"


# ---------------------------------------------------------------------------
# TestAuditReport
# ---------------------------------------------------------------------------


class TestAuditReport:
    """Tests for the get_audit_report() summary."""

    def test_empty_report(self, audit_interceptor: ShieldOpsInterceptor):
        report = audit_interceptor.get_audit_report()
        assert report["total_events"] == 0
        assert report["total_intercepts"] == 0
        assert report["total_blocks"] == 0
        assert report["by_tool"] == {}
        assert report["by_decision"] == {}
        assert report["avg_latency_ms"] == pytest.approx(0.0)
        assert report["mode"] == "audit"
        assert report["agent_id"] == "test-agent"

    def test_report_counts_recorded_events(self, audit_interceptor: ShieldOpsInterceptor):
        audit_interceptor.record("tool_a", latency_ms=10.0)
        audit_interceptor.record("tool_a", latency_ms=20.0)
        audit_interceptor.record("tool_b", latency_ms=30.0, decision="block")

        report = audit_interceptor.get_audit_report()
        assert report["total_events"] == 3
        assert report["by_tool"] == {"tool_a": 2, "tool_b": 1}
        assert report["by_decision"] == {"allow": 2, "block": 1}
        assert report["avg_latency_ms"] == pytest.approx(20.0)

    def test_report_reflects_intercept_counts(self, enforce_interceptor: ShieldOpsInterceptor):
        enforce_interceptor.intercept("delete_database")
        enforce_interceptor.intercept("read_file")
        report = enforce_interceptor.get_audit_report()
        assert report["total_intercepts"] == 2
        assert report["total_blocks"] == 1

    def test_avg_latency_with_single_event(self, audit_interceptor: ShieldOpsInterceptor):
        audit_interceptor.record("tool_x", latency_ms=42.5)
        report = audit_interceptor.get_audit_report()
        assert report["avg_latency_ms"] == pytest.approx(42.5)


# ---------------------------------------------------------------------------
# TestBatchAndFlush
# ---------------------------------------------------------------------------


class TestBatchAndFlush:
    """Tests for batch recording and auto-flush behavior."""

    def test_record_creates_audit_event(self, audit_interceptor: ShieldOpsInterceptor):
        event = audit_interceptor.record(
            tool_name="search_logs",
            args_hash="abc123",
            result_summary="found 42 matches",
            latency_ms=15.5,
            decision="allow",
            risk_score=0.1,
        )
        assert isinstance(event, AuditEvent)
        assert event.tool_name == "search_logs"
        assert event.args_hash == "abc123"
        assert event.result_summary == "found 42 matches"
        assert event.latency_ms == pytest.approx(15.5)
        assert event.decision == "allow"
        assert event.risk_score == pytest.approx(0.1)
        assert event.agent_id == "test-agent"

    def test_record_truncates_long_result_summary(self, audit_interceptor: ShieldOpsInterceptor):
        long_summary = "x" * 1000
        event = audit_interceptor.record("tool_a", result_summary=long_summary)
        assert len(event.result_summary) == 500

    def test_record_adds_to_events_and_batch(self, audit_interceptor: ShieldOpsInterceptor):
        audit_interceptor.record("tool_a")
        assert len(audit_interceptor._events) == 1
        assert len(audit_interceptor._batch) == 1

    @patch.object(ShieldOpsInterceptor, "flush", return_value=3)
    def test_auto_flush_at_max_batch_size(
        self, mock_flush: AsyncMock, audit_interceptor: ShieldOpsInterceptor
    ):
        """Batch size is 3 in the fixture; 3rd record should trigger flush."""
        audit_interceptor.record("tool_a")
        audit_interceptor.record("tool_b")
        mock_flush.assert_not_called()
        audit_interceptor.record("tool_c")
        mock_flush.assert_called_once()

    def test_flush_empty_batch_returns_zero(self, audit_interceptor: ShieldOpsInterceptor):
        count = audit_interceptor.flush()
        assert count == 0

    def test_flush_returns_event_count_and_clears_batch(
        self, audit_interceptor: ShieldOpsInterceptor
    ):
        audit_interceptor.record("tool_a")
        audit_interceptor.record("tool_b")

        with patch.object(audit_interceptor, "_send_batch", new_callable=AsyncMock):
            count = audit_interceptor.flush()

        assert count == 2
        assert len(audit_interceptor._batch) == 0
        # events list is NOT cleared on flush -- it's the full history
        assert len(audit_interceptor._events) == 2

    def test_record_default_agent_id_from_config(self, audit_interceptor: ShieldOpsInterceptor):
        event = audit_interceptor.record("tool_x")
        assert event.agent_id == "test-agent"

    def test_record_unknown_agent_when_config_has_none(self):
        cfg = SDKConfig(mode=SDKMode.AUDIT, agent_id=None, max_batch_size=100)
        interceptor = ShieldOpsInterceptor(cfg)
        event = interceptor.record("tool_x")
        assert event.agent_id == "unknown"


# ---------------------------------------------------------------------------
# TestHashing
# ---------------------------------------------------------------------------


class TestHashing:
    """Tests for the static hash_args utility."""

    def test_deterministic_hash(self):
        args = {"key": "value", "num": 42}
        h1 = ShieldOpsInterceptor.hash_args(args)
        h2 = ShieldOpsInterceptor.hash_args(args)
        assert h1 == h2

    def test_hash_is_16_char_hex(self):
        h = ShieldOpsInterceptor.hash_args({"a": 1})
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)

    def test_order_independent(self):
        h1 = ShieldOpsInterceptor.hash_args({"b": 2, "a": 1})
        h2 = ShieldOpsInterceptor.hash_args({"a": 1, "b": 2})
        assert h1 == h2

    def test_different_args_different_hash(self):
        h1 = ShieldOpsInterceptor.hash_args({"key": "value1"})
        h2 = ShieldOpsInterceptor.hash_args({"key": "value2"})
        assert h1 != h2

    def test_empty_args_hash(self):
        h = ShieldOpsInterceptor.hash_args({})
        assert len(h) == 16

    def test_hash_matches_manual_sha256(self):
        args = {"action": "deploy", "target": "prod"}
        raw = str(sorted(args.items())).encode()
        expected = hashlib.sha256(raw).hexdigest()[:16]
        assert ShieldOpsInterceptor.hash_args(args) == expected


# ---------------------------------------------------------------------------
# TestSessionLifecycle
# ---------------------------------------------------------------------------


class TestSessionLifecycle:
    """Tests for async context manager behavior."""

    @pytest.mark.asyncio
    async def test_aenter_returns_interceptor(self, audit_interceptor: ShieldOpsInterceptor):
        async with audit_interceptor as ctx:
            assert ctx is audit_interceptor

    @pytest.mark.asyncio
    async def test_aexit_flushes_pending_events(self, audit_interceptor: ShieldOpsInterceptor):
        with patch.object(audit_interceptor, "flush", return_value=1) as mock_flush:
            async with audit_interceptor:
                audit_interceptor.record("tool_a")
            mock_flush.assert_called()

    @pytest.mark.asyncio
    async def test_full_lifecycle(self):
        cfg = SDKConfig(
            mode=SDKMode.ENFORCE,
            agent_id="lifecycle-agent",
            max_batch_size=100,
        )
        interceptor = ShieldOpsInterceptor(cfg)

        with patch.object(interceptor, "flush", return_value=2) as mock_flush:
            async with interceptor as sdk:
                result = sdk.intercept("delete_database")
                assert result.decision == "block"
                sdk.record("delete_database", decision="block", risk_score=1.0)
                sdk.record("read_file", decision="allow", risk_score=0.0)

            mock_flush.assert_called_once()


# ---------------------------------------------------------------------------
# TestInterceptResult
# ---------------------------------------------------------------------------


class TestInterceptResult:
    """Tests for the InterceptResult model defaults."""

    def test_default_decision_is_allow(self):
        r = InterceptResult()
        assert r.decision == "allow"

    def test_default_risk_score_is_zero(self):
        r = InterceptResult()
        assert r.risk_score == pytest.approx(0.0)

    def test_default_reasons_empty(self):
        r = InterceptResult()
        assert r.reasons == []

    def test_request_id_auto_generated(self):
        r1 = InterceptResult()
        r2 = InterceptResult()
        assert r1.request_id != r2.request_id


# ---------------------------------------------------------------------------
# TestAuditEventModel
# ---------------------------------------------------------------------------


class TestAuditEventModel:
    """Tests for the AuditEvent model defaults."""

    def test_default_fields(self):
        event = AuditEvent()
        assert event.agent_id == ""
        assert event.tool_name == ""
        assert event.decision == "allow"
        assert event.risk_score == pytest.approx(0.0)
        assert event.latency_ms == pytest.approx(0.0)
        assert event.timestamp > 0
        assert len(event.id) > 0

    def test_unique_ids(self):
        e1 = AuditEvent()
        e2 = AuditEvent()
        assert e1.id != e2.id


# ---------------------------------------------------------------------------
# TestSendBatch
# ---------------------------------------------------------------------------


class TestSendBatch:
    """Tests for the _send_batch HTTP retry logic."""

    @pytest.mark.asyncio
    async def test_send_batch_posts_to_correct_url(self, audit_interceptor: ShieldOpsInterceptor):
        events = [AuditEvent(tool_name="test_tool")]

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("shieldops.sdk.interceptor.httpx.AsyncClient", return_value=mock_client):
            await audit_interceptor._send_batch(events)

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[0][0] == "https://test.shieldops.io/api/v1/agent-firewall/events"

    @pytest.mark.asyncio
    async def test_send_batch_includes_auth_header(self, audit_interceptor: ShieldOpsInterceptor):
        events = [AuditEvent(tool_name="test_tool")]

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("shieldops.sdk.interceptor.httpx.AsyncClient", return_value=mock_client):
            await audit_interceptor._send_batch(events)

        headers = mock_client.post.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer test-key-123"
        assert headers["X-ShieldOps-Agent-Id"] == "test-agent"
