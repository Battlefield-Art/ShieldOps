"""Tests for shieldops.agents.attack_campaign."""

from __future__ import annotations

from shieldops.agents.attack_campaign.models import (
    AttackCampaignState,
)


class TestModels:
    def test_state_defaults(self):
        s = AttackCampaignState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.attack_campaign.graph import (
            create_attack_campaign_graph,
        )

        sg = create_attack_campaign_graph()
        assert sg.compile() is not None
