"""Unit tests for firewall_rule_auditor agent."""

from __future__ import annotations

from shieldops.agents.firewall_rule_auditor.models import (
    AuditFinding,
    AuditStage,
    FirewallAuditState,
    FirewallProvider,
    RuleRisk,
)
from shieldops.agents.firewall_rule_auditor.tools import FirewallAuditToolkit


class TestEnums:
    def test_auditstage(self) -> None:
        assert AuditStage.COLLECT_RULES == "collect_rules"
        assert len(AuditStage) >= 3

    def test_firewallprovider(self) -> None:
        assert FirewallProvider.AWS_SG == "aws_sg"
        assert len(FirewallProvider) >= 3

    def test_rulerisk(self) -> None:
        assert RuleRisk.CRITICAL == "critical"
        assert len(RuleRisk) >= 3


class TestState:
    def test_defaults(self) -> None:
        state = FirewallAuditState()
        assert state.request_id == ""
        assert state.error == ""

    def test_with_values(self) -> None:
        state = FirewallAuditState(
            request_id="t-1",
            tenant_id="t-1",
        )
        assert state.request_id == "t-1"


class TestAuditFinding:
    def test_defaults(self) -> None:
        obj = AuditFinding()
        assert obj is not None


class TestToolkit:
    def test_init(self) -> None:
        tk = FirewallAuditToolkit()
        assert tk is not None
