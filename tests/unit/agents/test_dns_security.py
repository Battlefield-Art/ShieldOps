"""Tests for shieldops.agents.dns_security."""

from __future__ import annotations

from shieldops.agents.dns_security.models import (
    DNSSecurityState,
    DNSSeverity,
    DNSStage,
    DNSThreatType,
)


class TestEnums:
    def test_dnsstage_collect_dns(self):
        assert DNSStage.COLLECT_DNS == "collect_dns"

    def test_dnsstage_detect_tunneling(self):
        assert DNSStage.DETECT_TUNNELING == "detect_tunneling"

    def test_dnsstage_detect_dga(self):
        assert DNSStage.DETECT_DGA == "detect_dga"

    def test_dnsstage_detect_typosquatting(self):
        assert DNSStage.DETECT_TYPOSQUATTING == "detect_typosquatting"

    def test_dnsthreattype_tunneling(self):
        assert DNSThreatType.TUNNELING == "tunneling"

    def test_dnsthreattype_dga(self):
        assert DNSThreatType.DGA == "dga"

    def test_dnsthreattype_typosquatting(self):
        assert DNSThreatType.TYPOSQUATTING == "typosquatting"

    def test_dnsthreattype_exfiltration(self):
        assert DNSThreatType.EXFILTRATION == "exfiltration"

    def test_dnsseverity_critical(self):
        assert DNSSeverity.CRITICAL == "critical"

    def test_dnsseverity_high(self):
        assert DNSSeverity.HIGH == "high"

    def test_dnsseverity_medium(self):
        assert DNSSeverity.MEDIUM == "medium"

    def test_dnsseverity_low(self):
        assert DNSSeverity.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = DNSSecurityState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.dns_security.graph import (
            create_dns_security_graph,
        )

        sg = create_dns_security_graph()
        assert sg.compile() is not None
