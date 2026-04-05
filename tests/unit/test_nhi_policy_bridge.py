"""Tests for NHI Policy Bridge."""

from __future__ import annotations

from shieldops.agents.nhi_policy_bridge import NHIPolicyBridge


class TestUpdateInventory:
    def test_adds_identities(self) -> None:
        bridge = NHIPolicyBridge()
        count = bridge.update_inventory(
            [
                {"id": "sa-1", "name": "svc-deploy", "risk_level": "low", "risk_score": 20},
                {"id": "sa-2", "name": "svc-admin", "risk_level": "critical", "risk_score": 95},
            ]
        )
        assert count == 2

    def test_skips_identities_without_id(self) -> None:
        bridge = NHIPolicyBridge()
        count = bridge.update_inventory([{"name": "no-id"}])
        assert count == 0

    def test_overwrites_existing_identity(self) -> None:
        bridge = NHIPolicyBridge()
        bridge.update_inventory([{"id": "sa-1", "risk_level": "low", "risk_score": 10}])
        bridge.update_inventory([{"id": "sa-1", "risk_level": "critical", "risk_score": 95}])
        assert bridge.get_stats()["total_identities"] == 1
        result = bridge.evaluate_identity("sa-1")
        assert result["action"] == "block"


class TestRuleGeneration:
    def test_critical_generates_block(self) -> None:
        bridge = NHIPolicyBridge()
        bridge.update_inventory(
            [
                {"id": "sa-1", "name": "root-svc", "risk_level": "critical", "risk_score": 95},
            ]
        )
        rules = bridge.get_policy_rules()
        assert len(rules) == 1
        assert rules[0]["action"] == "block"
        assert "Critical risk" in rules[0]["reason"]

    def test_high_generates_audit_enhanced(self) -> None:
        bridge = NHIPolicyBridge()
        bridge.update_inventory(
            [
                {"id": "sa-2", "name": "admin-svc", "risk_level": "high", "risk_score": 75},
            ]
        )
        rules = bridge.get_policy_rules()
        assert len(rules) == 1
        assert rules[0]["action"] == "audit_enhanced"

    def test_medium_low_generate_no_rules(self) -> None:
        bridge = NHIPolicyBridge()
        bridge.update_inventory(
            [
                {"id": "sa-3", "name": "reader-svc", "risk_level": "medium", "risk_score": 40},
                {"id": "sa-4", "name": "log-svc", "risk_level": "low", "risk_score": 10},
            ]
        )
        assert len(bridge.get_policy_rules()) == 0

    def test_mixed_risk_levels(self) -> None:
        bridge = NHIPolicyBridge()
        bridge.update_inventory(
            [
                {"id": "sa-1", "risk_level": "critical", "risk_score": 95},
                {"id": "sa-2", "risk_level": "high", "risk_score": 70},
                {"id": "sa-3", "risk_level": "medium", "risk_score": 40},
                {"id": "sa-4", "risk_level": "low", "risk_score": 10},
            ]
        )
        rules = bridge.get_policy_rules()
        assert len(rules) == 2  # only critical + high


class TestEvaluateIdentity:
    def test_restricted_identity(self) -> None:
        bridge = NHIPolicyBridge()
        bridge.update_inventory(
            [
                {"id": "sa-1", "name": "admin", "risk_level": "critical", "risk_score": 95},
            ]
        )
        result = bridge.evaluate_identity("sa-1")
        assert result["restricted"] is True
        assert result["action"] == "block"

    def test_unrestricted_identity(self) -> None:
        bridge = NHIPolicyBridge()
        bridge.update_inventory(
            [
                {"id": "sa-1", "risk_level": "low", "risk_score": 10},
            ]
        )
        result = bridge.evaluate_identity("sa-1")
        assert result["restricted"] is False
        assert result["action"] == "allow"

    def test_unknown_identity(self) -> None:
        bridge = NHIPolicyBridge()
        result = bridge.evaluate_identity("unknown-id")
        assert result["restricted"] is False
        assert result["action"] == "allow"


class TestStats:
    def test_empty_stats(self) -> None:
        bridge = NHIPolicyBridge()
        stats = bridge.get_stats()
        assert stats["total_identities"] == 0
        assert stats["total_rules"] == 0

    def test_populated_stats(self) -> None:
        bridge = NHIPolicyBridge()
        bridge.update_inventory(
            [
                {"id": "1", "risk_level": "critical", "risk_score": 95},
                {"id": "2", "risk_level": "high", "risk_score": 70},
                {"id": "3", "risk_level": "medium", "risk_score": 40},
                {"id": "4", "risk_level": "low", "risk_score": 10},
            ]
        )
        stats = bridge.get_stats()
        assert stats["total_identities"] == 4
        assert stats["blocked"] == 1
        assert stats["audit_enhanced"] == 1
        assert stats["unrestricted"] == 2
