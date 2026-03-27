"""Tests for shieldops.agents.api_security."""

from __future__ import annotations

from shieldops.agents.api_security.models import (
    AbuseType,
    APISecurityState,
    SecurityStage,
    VulnerabilityType,
)


class TestEnums:
    def test_securitystage_discover_endpoints(self):
        assert SecurityStage.DISCOVER_ENDPOINTS == "discover_endpoints"

    def test_securitystage_analyze_traffic(self):
        assert SecurityStage.ANALYZE_TRAFFIC == "analyze_traffic"

    def test_securitystage_detect_vulnerabilities(self):
        assert SecurityStage.DETECT_VULNERABILITIES == "detect_vulnerabilities"

    def test_securitystage_detect_abuse(self):
        assert SecurityStage.DETECT_ABUSE == "detect_abuse"

    def test_vulnerabilitytype_bola(self):
        assert VulnerabilityType.BOLA == "bola"

    def test_vulnerabilitytype_broken_auth(self):
        assert VulnerabilityType.BROKEN_AUTH == "broken_auth"

    def test_vulnerabilitytype_excessive_data(self):
        assert VulnerabilityType.EXCESSIVE_DATA == "excessive_data"

    def test_vulnerabilitytype_resource_lack(self):
        assert VulnerabilityType.RESOURCE_LACK == "resource_lack"

    def test_abusetype_credential_stuffing(self):
        assert AbuseType.CREDENTIAL_STUFFING == "credential_stuffing"

    def test_abusetype_scraping(self):
        assert AbuseType.SCRAPING == "scraping"

    def test_abusetype_enumeration(self):
        assert AbuseType.ENUMERATION == "enumeration"

    def test_abusetype_rate_abuse(self):
        assert AbuseType.RATE_ABUSE == "rate_abuse"


class TestModels:
    def test_state_defaults(self):
        s = APISecurityState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.api_security.graph import (
            create_api_security_graph,
        )

        sg = create_api_security_graph()
        assert sg.compile() is not None
