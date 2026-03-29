"""Tests for shieldops.agents.secrets_in_code_detector — hardcoded secret detection."""

from __future__ import annotations

import pytest

from shieldops.agents.secrets_in_code_detector.models import (
    DetectionStage,
    ExposureRisk,
    RepositoryScan,
    SecretFinding,
    SecretsInCodeDetectorState,
    SecretType,
)


def _state(**kw) -> SecretsInCodeDetectorState:
    return SecretsInCodeDetectorState(**kw)


class TestEnums:
    def test_detection_stage_values(self):
        assert DetectionStage.DISCOVER_REPOSITORIES == "discover_repositories"
        assert DetectionStage.SCAN_PATTERNS == "scan_patterns"
        assert DetectionStage.VERIFY_SECRETS == "verify_secrets"
        assert DetectionStage.ASSESS_EXPOSURE == "assess_exposure"
        assert DetectionStage.PRIORITIZE == "prioritize"
        assert DetectionStage.REPORT == "report"

    def test_secret_type_values(self):
        assert SecretType.API_KEY == "api_key"
        assert SecretType.PASSWORD == "password"  # noqa: S105
        assert SecretType.TOKEN == "token"  # noqa: S105
        assert SecretType.PRIVATE_KEY == "private_key"
        assert SecretType.AWS_ACCESS_KEY == "aws_access_key"

    def test_exposure_risk_values(self):
        assert ExposureRisk.CRITICAL == "critical"
        assert ExposureRisk.HIGH == "high"
        assert ExposureRisk.INFORMATIONAL == "informational"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == DetectionStage.DISCOVER_REPOSITORIES
        assert s.scan_targets == []
        assert s.repositories == []
        assert s.total_repos == 0
        assert s.raw_findings == []
        assert s.verified_findings == []
        assert s.prioritized == []
        assert s.total_findings == 0
        assert s.critical_count == 0
        assert s.active_secrets == 0
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(tenant_id="t-01", total_repos=5, active_secrets=3)
        assert s.tenant_id == "t-01"
        assert s.total_repos == 5
        assert s.active_secrets == 3

    def test_repository_scan_defaults(self):
        r = RepositoryScan()
        assert r.id == ""
        assert r.repo_name == ""
        assert r.branch == "main"
        assert r.secrets_found == 0

    def test_secret_finding_defaults(self):
        f = SecretFinding()
        assert f.id == ""
        assert f.secret_type == SecretType.GENERIC_SECRET
        assert f.exposure_risk == ExposureRisk.HIGH
        assert f.is_active is False
        assert f.verified is False
        assert f.entropy_score == 0.0


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.secrets_in_code_detector.tools import SecretsInCodeDetectorToolkit

        return SecretsInCodeDetectorToolkit()

    @pytest.mark.asyncio()
    async def test_discover_repositories(self, toolkit):
        repos = await toolkit.discover_repositories("t-01", ["repo1", "repo2"])
        assert isinstance(repos, list)
        assert len(repos) == 2
        assert all(isinstance(r, RepositoryScan) for r in repos)

    @pytest.mark.asyncio()
    async def test_scan_patterns(self, toolkit):
        repos = [RepositoryScan(id="r1", repo_name="test")]
        findings = await toolkit.scan_patterns(repos, ["/nonexistent"])
        assert isinstance(findings, list)

    @pytest.mark.asyncio()
    async def test_verify_secrets(self, toolkit):
        findings = [SecretFinding(id="s1", entropy_score=4.5)]
        verified = await toolkit.verify_secrets(findings)
        assert isinstance(verified, list)
        assert len(verified) == 1
        assert verified[0].verified is True

    @pytest.mark.asyncio()
    async def test_assess_exposure(self, toolkit):
        findings = [SecretFinding(id="s1", is_active=True)]
        assessed = await toolkit.assess_exposure(findings)
        assert isinstance(assessed, list)
        assert len(assessed) == 1

    def test_prioritize(self, toolkit):
        findings = [
            SecretFinding(id="s1", exposure_risk=ExposureRisk.CRITICAL, is_active=True),
            SecretFinding(id="s2", exposure_risk=ExposureRisk.LOW, is_active=False),
        ]
        result = toolkit.prioritize(findings)
        assert result[0]["score"] > result[1]["score"]


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.secrets_in_code_detector.graph import (
            create_secrets_in_code_detector_graph,
        )

        sg = create_secrets_in_code_detector_graph()
        assert sg.compile() is not None
