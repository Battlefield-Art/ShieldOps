"""Tests for shieldops.agents.sca_dependency_checker — software composition analysis."""

from __future__ import annotations

import pytest

from shieldops.agents.sca_dependency_checker.models import (
    CVEMatch,
    DependencyRecord,
    DependencyRisk,
    LicenseType,
    SCADependencyCheckerState,
    SCAStage,
)


def _state(**kw) -> SCADependencyCheckerState:
    return SCADependencyCheckerState(**kw)


class TestEnums:
    def test_sca_stage_values(self):
        assert SCAStage.DISCOVER_MANIFESTS == "discover_manifests"
        assert SCAStage.PARSE_DEPENDENCIES == "parse_dependencies"
        assert SCAStage.MATCH_CVES == "match_cves"
        assert SCAStage.CHECK_LICENSES == "check_licenses"
        assert SCAStage.PRIORITIZE == "prioritize"
        assert SCAStage.REPORT == "report"

    def test_dependency_risk_values(self):
        assert DependencyRisk.CRITICAL == "critical"
        assert DependencyRisk.HIGH == "high"
        assert DependencyRisk.NONE == "none"

    def test_license_type_values(self):
        assert LicenseType.MIT == "mit"
        assert LicenseType.GPL_3 == "gpl_3"
        assert LicenseType.APACHE_2 == "apache_2"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == SCAStage.DISCOVER_MANIFESTS
        assert s.scan_targets == []
        assert s.dependencies == []
        assert s.total_dependencies == 0
        assert s.cve_matches == []
        assert s.license_violations == []
        assert s.prioritized == []
        assert s.total_findings == 0
        assert s.critical_count == 0
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(tenant_id="t-01", total_dependencies=42)
        assert s.tenant_id == "t-01"
        assert s.total_dependencies == 42

    def test_cve_match_defaults(self):
        c = CVEMatch()
        assert c.cve_id == ""
        assert c.cvss_score == 0.0
        assert c.severity == DependencyRisk.MEDIUM
        assert c.is_exploitable is False

    def test_dependency_record_defaults(self):
        d = DependencyRecord()
        assert d.package_name == ""
        assert d.is_direct is True
        assert d.is_outdated is False
        assert d.license_type == LicenseType.UNKNOWN


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.sca_dependency_checker.tools import SCADependencyCheckerToolkit

        return SCADependencyCheckerToolkit()

    @pytest.mark.asyncio()
    async def test_discover_manifests(self, toolkit):
        result = await toolkit.discover_manifests("t-01", ["requirements.txt"])
        assert isinstance(result, list)
        assert len(result) >= 1

    @pytest.mark.asyncio()
    async def test_parse_dependencies(self, toolkit):
        manifests = [
            {
                "id": "m1",
                "path": "requirements.txt",
                "type": "requirements.txt",
                "ecosystem": "pypi",
            }
        ]
        deps = await toolkit.parse_dependencies(manifests, [])
        assert isinstance(deps, list)
        assert len(deps) >= 5

    @pytest.mark.asyncio()
    async def test_match_cves(self, toolkit):
        deps = [DependencyRecord(package_name="requests", installed_version="2.28.0")]
        matches = await toolkit.match_cves(deps)
        assert isinstance(matches, list)
        assert len(matches) >= 1

    @pytest.mark.asyncio()
    async def test_check_licenses(self, toolkit):
        deps = [
            DependencyRecord(
                package_name="test", license_type=LicenseType.GPL_3, license_compatible=False
            )
        ]
        violations = await toolkit.check_licenses(deps)
        assert isinstance(violations, list)
        assert len(violations) >= 1


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.sca_dependency_checker.graph import (
            create_sca_dependency_checker_graph,
        )

        sg = create_sca_dependency_checker_graph()
        assert sg.compile() is not None
