"""Tests for the Compliance Auditor agent toolkit (production methods).

Covers: audit_aws_config, audit_controls, check_identity_posture,
check_vulnerability_posture, generate_evidence, generate_report.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from shieldops.agents.compliance_auditor.tools import ComplianceAuditorToolkit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def toolkit() -> ComplianceAuditorToolkit:
    """Toolkit with no backends (heuristic fallback mode)."""
    return ComplianceAuditorToolkit()


@pytest.fixture
def mock_router() -> MagicMock:
    """Mock ConnectorRouter with an AWS connector."""
    router = MagicMock()

    aws_connector = AsyncMock()
    router.get.return_value = aws_connector

    # S3 buckets
    bucket = MagicMock()
    bucket.id = "bucket-1"
    bucket.name = "my-bucket"
    bucket.metadata = {"public_access_blocked": True, "encryption_enabled": True}
    aws_connector.list_resources = AsyncMock(return_value=[bucket])

    return router


@pytest.fixture
def toolkit_with_router(mock_router: MagicMock) -> ComplianceAuditorToolkit:
    """Toolkit with a mocked connector router."""
    return ComplianceAuditorToolkit(connector_router=mock_router)


@pytest.fixture
def sample_identity_data() -> dict[str, Any]:
    """Sample identity graph data for posture checks."""
    now = datetime.now(UTC)
    return {
        "identities": [
            {
                "id": "user-1",
                "name": "admin-user",
                "type": "human",
                "permissions": ["admin", "read", "write"],
                "mfa_enabled": True,
                "created_at": (now - timedelta(days=30)).isoformat(),
            },
            {
                "id": "svc-1",
                "name": "deploy-service",
                "type": "service_account",
                "permissions": ["read", "write"],
                "mfa_enabled": False,
                "created_at": (now - timedelta(days=200)).isoformat(),
            },
            {
                "id": "svc-2",
                "name": "ci-runner",
                "type": "service_account",
                "permissions": ["ec2:*", "s3:*"],
                "mfa_enabled": False,
                "created_at": (now - timedelta(days=50)).isoformat(),
            },
        ],
        "risk_distribution": {"critical": 1, "high": 1, "medium": 1, "low": 0},
        "top_risks": [{"identity_id": "svc-2", "risk_score": 75}],
    }


@pytest.fixture
def sample_vuln_data() -> dict[str, Any]:
    """Sample vulnerability manager data for posture checks."""
    return {
        "vulnerabilities": [
            {
                "cve_id": "CVE-2024-1234",
                "severity": "critical",
                "days_open": 3,
                "sla_days": 7,
                "fix_available": True,
                "status": "open",
            },
            {
                "cve_id": "CVE-2024-5678",
                "severity": "high",
                "days_open": 45,
                "sla_days": 30,
                "fix_available": True,
                "status": "open",
            },
            {
                "cve_id": "CVE-2024-9012",
                "severity": "medium",
                "days_open": 10,
                "sla_days": 90,
                "fix_available": True,
                "status": "remediated",
            },
            {
                "cve_id": "CVE-2024-0001",
                "severity": "low",
                "days_open": 5,
                "sla_days": 180,
                "fix_available": False,
                "status": "open",
            },
        ],
        "total_count": 4,
    }


# ---------------------------------------------------------------------------
# audit_aws_config
# ---------------------------------------------------------------------------


class TestAuditAwsConfig:
    @pytest.mark.asyncio
    async def test_returns_findings_without_router(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assert isinstance(findings, list)
        assert len(findings) == 5

        check_types = {f["check_type"] for f in findings}
        assert check_types == {
            "s3_bucket_policy",
            "iam_password_policy",
            "cloudtrail_status",
            "encryption_settings",
            "vpc_flow_logs",
        }

    @pytest.mark.asyncio
    async def test_each_finding_has_required_fields(
        self, toolkit: ComplianceAuditorToolkit
    ) -> None:
        findings = await toolkit.audit_aws_config()
        for f in findings:
            assert "check_type" in f
            assert "status" in f
            assert f["status"] in ("pass", "fail")
            assert "details" in f
            assert "mapped_controls" in f
            assert "timestamp" in f

    @pytest.mark.asyncio
    async def test_uses_connector_router_when_available(
        self, toolkit_with_router: ComplianceAuditorToolkit, mock_router: MagicMock
    ) -> None:
        findings = await toolkit_with_router.audit_aws_config()
        assert isinstance(findings, list)
        # Router was called
        mock_router.get.assert_called_with("aws")

    @pytest.mark.asyncio
    async def test_falls_back_on_router_error(self) -> None:
        router = MagicMock()
        router.get.side_effect = ValueError("No connector for aws")
        toolkit = ComplianceAuditorToolkit(connector_router=router)

        findings = await toolkit.audit_aws_config()
        # Should fall back to mock findings
        assert len(findings) == 5

    @pytest.mark.asyncio
    async def test_accepts_context(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config(context={"environment": "staging"})
        assert len(findings) == 5


# ---------------------------------------------------------------------------
# audit_controls
# ---------------------------------------------------------------------------


class TestAuditControls:
    @pytest.mark.asyncio
    async def test_maps_findings_to_soc2(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assessments = await toolkit.audit_controls("soc2", findings)

        assert isinstance(assessments, list)
        assert len(assessments) == 5  # 5 SOC2 controls

        for a in assessments:
            assert "control_id" in a
            assert a["framework"] == "soc2"
            assert a["status"] in ("pass", "fail", "warning")
            assert "gaps" in a
            assert "evidence_sources" in a

    @pytest.mark.asyncio
    async def test_maps_findings_to_hipaa(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assessments = await toolkit.audit_controls("hipaa", findings)
        assert len(assessments) == 5
        assert all(a["framework"] == "hipaa" for a in assessments)

    @pytest.mark.asyncio
    async def test_maps_findings_to_pci_dss(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assessments = await toolkit.audit_controls("pci_dss", findings)
        assert len(assessments) == 5
        assert all(a["framework"] == "pci_dss" for a in assessments)

    @pytest.mark.asyncio
    async def test_unknown_framework_returns_empty(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assessments = await toolkit.audit_controls("unknown_framework", findings)
        assert assessments == []

    @pytest.mark.asyncio
    async def test_failed_findings_create_gaps(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assessments = await toolkit.audit_controls("soc2", findings)

        # Mock findings have some "fail" items, so at least one control should have gaps
        controls_with_gaps = [a for a in assessments if a.get("gaps")]
        assert len(controls_with_gaps) > 0

    @pytest.mark.asyncio
    async def test_all_pass_findings(self, toolkit: ComplianceAuditorToolkit) -> None:
        all_pass = [
            {
                "check_type": "s3_bucket_policy",
                "status": "pass",
                "details": {},
                "mapped_controls": {"soc2": ["SOC2-CC6.1"]},
            },
        ]
        assessments = await toolkit.audit_controls("soc2", all_pass)
        cc61 = next(a for a in assessments if a["control_id"] == "SOC2-CC6.1")
        assert cc61["status"] == "pass"
        assert cc61["gaps"] == []


# ---------------------------------------------------------------------------
# check_identity_posture
# ---------------------------------------------------------------------------


class TestCheckIdentityPosture:
    def test_returns_posture_score(
        self, toolkit: ComplianceAuditorToolkit, sample_identity_data: dict[str, Any]
    ) -> None:
        result = toolkit.check_identity_posture(sample_identity_data)

        assert "overall_score" in result
        assert 0 <= result["overall_score"] <= 100
        assert "mfa_score" in result
        assert "least_privilege_score" in result
        assert "credential_rotation_score" in result
        assert "findings" in result
        assert "recommendations" in result

    def test_mfa_score_calculation(
        self, toolkit: ComplianceAuditorToolkit, sample_identity_data: dict[str, Any]
    ) -> None:
        result = toolkit.check_identity_posture(sample_identity_data)
        # 1 of 3 has MFA enabled => ~33.3%
        assert result["mfa_score"] == pytest.approx(33.3, abs=0.1)
        assert result["mfa_enabled_count"] == 1

    def test_least_privilege_score(
        self, toolkit: ComplianceAuditorToolkit, sample_identity_data: dict[str, Any]
    ) -> None:
        result = toolkit.check_identity_posture(sample_identity_data)
        # 2 of 3 have admin-level perms (user-1 has "admin", svc-2 has "ec2:*")
        assert result["overprivileged_count"] == 2
        assert result["least_privilege_score"] == pytest.approx(33.3, abs=0.1)

    def test_credential_rotation_score(
        self, toolkit: ComplianceAuditorToolkit, sample_identity_data: dict[str, Any]
    ) -> None:
        result = toolkit.check_identity_posture(sample_identity_data)
        # svc-1 created 200 days ago without rotation => stale
        assert result["stale_credential_count"] >= 1

    def test_empty_identity_data(self, toolkit: ComplianceAuditorToolkit) -> None:
        result = toolkit.check_identity_posture({})
        assert result["overall_score"] == 0.0
        assert "No identity data available" in result["findings"][0]

    def test_all_compliant_identities(self, toolkit: ComplianceAuditorToolkit) -> None:
        now = datetime.now(UTC)
        data = {
            "identities": [
                {
                    "id": "user-1",
                    "name": "normal-user",
                    "permissions": ["read"],
                    "mfa_enabled": True,
                    "created_at": (now - timedelta(days=10)).isoformat(),
                },
            ],
            "risk_distribution": {},
            "top_risks": [],
        }
        result = toolkit.check_identity_posture(data)
        assert result["overall_score"] == 100.0
        assert result["mfa_score"] == 100.0
        assert result["least_privilege_score"] == 100.0
        assert result["credential_rotation_score"] == 100.0

    def test_risk_distribution_in_findings(
        self, toolkit: ComplianceAuditorToolkit, sample_identity_data: dict[str, Any]
    ) -> None:
        result = toolkit.check_identity_posture(sample_identity_data)
        findings_text = " ".join(result["findings"])
        assert "critical" in findings_text.lower()


# ---------------------------------------------------------------------------
# check_vulnerability_posture
# ---------------------------------------------------------------------------


class TestCheckVulnerabilityPosture:
    def test_returns_posture_score(
        self, toolkit: ComplianceAuditorToolkit, sample_vuln_data: dict[str, Any]
    ) -> None:
        result = toolkit.check_vulnerability_posture(sample_vuln_data)

        assert "overall_score" in result
        assert 0 <= result["overall_score"] <= 100
        assert "sla_adherence_score" in result
        assert "critical_cve_score" in result
        assert "remediation_rate_score" in result
        assert "findings" in result
        assert "recommendations" in result

    def test_sla_breach_detection(
        self, toolkit: ComplianceAuditorToolkit, sample_vuln_data: dict[str, Any]
    ) -> None:
        result = toolkit.check_vulnerability_posture(sample_vuln_data)
        # CVE-2024-5678: days_open=45 > sla_days=30
        assert result["sla_breaches"] == 1
        # 3/4 within SLA = 75%
        assert result["sla_adherence_score"] == 75.0

    def test_critical_cve_count(
        self, toolkit: ComplianceAuditorToolkit, sample_vuln_data: dict[str, Any]
    ) -> None:
        result = toolkit.check_vulnerability_posture(sample_vuln_data)
        assert result["critical_count"] == 1
        assert result["high_count"] == 1

    def test_remediation_rate(
        self, toolkit: ComplianceAuditorToolkit, sample_vuln_data: dict[str, Any]
    ) -> None:
        result = toolkit.check_vulnerability_posture(sample_vuln_data)
        # 1 remediated out of 3 with fix_available => 33.3%
        assert result["remediated_count"] == 1
        assert result["fix_available_count"] == 3
        assert result["remediation_rate_score"] == pytest.approx(33.3, abs=0.1)

    def test_empty_vuln_data(self, toolkit: ComplianceAuditorToolkit) -> None:
        result = toolkit.check_vulnerability_posture({})
        assert result["overall_score"] == 0.0
        assert "No vulnerability data available" in result["findings"][0]

    def test_all_remediated(self, toolkit: ComplianceAuditorToolkit) -> None:
        data = {
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-0001",
                    "severity": "low",
                    "days_open": 5,
                    "sla_days": 180,
                    "fix_available": True,
                    "status": "remediated",
                },
            ],
        }
        result = toolkit.check_vulnerability_posture(data)
        assert result["sla_breaches"] == 0
        assert result["remediation_rate_score"] == 100.0
        assert result["critical_count"] == 0
        assert "All vulnerability posture checks passed" in result["findings"]


# ---------------------------------------------------------------------------
# generate_evidence
# ---------------------------------------------------------------------------


class TestGenerateEvidence:
    @pytest.mark.asyncio
    async def test_generates_evidence_docs(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assessments = await toolkit.audit_controls("soc2", findings)
        evidence_docs = toolkit.generate_evidence(assessments)

        assert isinstance(evidence_docs, list)
        assert len(evidence_docs) == 1  # One framework

        doc = evidence_docs[0]
        assert doc["framework"] == "soc2"
        assert "markdown" in doc
        assert doc["control_count"] == 5
        assert "pass_rate" in doc
        assert "generated_at" in doc

    @pytest.mark.asyncio
    async def test_markdown_contains_controls(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assessments = await toolkit.audit_controls("soc2", findings)
        evidence_docs = toolkit.generate_evidence(assessments)

        md = evidence_docs[0]["markdown"]
        assert "SOC2-CC6.1" in md
        assert "Compliance Evidence Report" in md

    @pytest.mark.asyncio
    async def test_multiple_frameworks(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()

        all_assessments: list[dict[str, Any]] = []
        for fw in ("soc2", "hipaa"):
            assessments = await toolkit.audit_controls(fw, findings)
            all_assessments.extend(assessments)

        evidence_docs = toolkit.generate_evidence(all_assessments)
        assert len(evidence_docs) == 2
        frameworks = {d["framework"] for d in evidence_docs}
        assert frameworks == {"soc2", "hipaa"}

    def test_empty_assessments(self, toolkit: ComplianceAuditorToolkit) -> None:
        evidence_docs = toolkit.generate_evidence([])
        assert evidence_docs == []

    @pytest.mark.asyncio
    async def test_pass_rate_calculation(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assessments = await toolkit.audit_controls("soc2", findings)
        evidence_docs = toolkit.generate_evidence(assessments)

        doc = evidence_docs[0]
        assert doc["passed"] + doc["failed"] + doc["warnings"] == doc["control_count"]
        expected_rate = round(doc["passed"] / max(doc["control_count"], 1) * 100, 1)
        assert doc["pass_rate"] == expected_rate


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestGenerateReport:
    @pytest.mark.asyncio
    async def test_full_report_generation(
        self,
        toolkit: ComplianceAuditorToolkit,
        sample_identity_data: dict[str, Any],
        sample_vuln_data: dict[str, Any],
    ) -> None:
        findings = await toolkit.audit_aws_config()
        soc2_assessments = await toolkit.audit_controls("soc2", findings)
        identity_posture = toolkit.check_identity_posture(sample_identity_data)
        vuln_posture = toolkit.check_vulnerability_posture(sample_vuln_data)

        report = toolkit.generate_report(
            {
                "control_assessments": soc2_assessments,
                "identity_posture": identity_posture,
                "vulnerability_posture": vuln_posture,
                "aws_findings": findings,
                "previous_score": 65.0,
            }
        )

        assert "overall_score" in report
        assert 0 <= report["overall_score"] <= 100
        assert "control_compliance_score" in report
        assert "identity_posture_score" in report
        assert "vulnerability_posture_score" in report
        assert "framework_scores" in report
        assert "soc2" in report["framework_scores"]
        assert "top_gaps" in report
        assert "recommendations" in report
        assert "trend" in report
        assert "generated_at" in report

    @pytest.mark.asyncio
    async def test_trend_improving(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assessments = await toolkit.audit_controls("soc2", findings)

        report = toolkit.generate_report(
            {
                "control_assessments": assessments,
                "previous_score": 10.0,
            }
        )
        # Score should be higher than 10 so trend is improving
        assert report["trend"]["direction"] == "improving"
        assert report["trend"]["delta"] > 0

    @pytest.mark.asyncio
    async def test_trend_declining(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assessments = await toolkit.audit_controls("soc2", findings)

        report = toolkit.generate_report(
            {
                "control_assessments": assessments,
                "previous_score": 99.0,
            }
        )
        assert report["trend"]["direction"] == "declining"
        assert report["trend"]["delta"] < 0

    @pytest.mark.asyncio
    async def test_no_previous_score(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assessments = await toolkit.audit_controls("soc2", findings)

        report = toolkit.generate_report(
            {
                "control_assessments": assessments,
            }
        )
        assert report["trend"] is None

    def test_empty_report(self, toolkit: ComplianceAuditorToolkit) -> None:
        report = toolkit.generate_report({})
        assert report["overall_score"] == 0.0
        assert report["total_controls_assessed"] == 0

    @pytest.mark.asyncio
    async def test_controls_only_report(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        assessments = await toolkit.audit_controls("soc2", findings)

        report = toolkit.generate_report(
            {
                "control_assessments": assessments,
            }
        )
        # Without identity/vuln data, overall = control_score
        assert report["overall_score"] == report["control_compliance_score"]
        assert report["identity_posture_score"] is None
        assert report["vulnerability_posture_score"] is None

    @pytest.mark.asyncio
    async def test_aws_config_summary(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        report = toolkit.generate_report(
            {
                "control_assessments": [],
                "aws_findings": findings,
            }
        )
        assert report["aws_config_summary"] is not None
        assert report["aws_config_summary"]["total_checks"] == 5
        assert "pass_rate" in report["aws_config_summary"]

    @pytest.mark.asyncio
    async def test_multiple_frameworks_in_report(self, toolkit: ComplianceAuditorToolkit) -> None:
        findings = await toolkit.audit_aws_config()
        all_assessments: list[dict[str, Any]] = []
        for fw in ("soc2", "hipaa", "pci_dss"):
            assessments = await toolkit.audit_controls(fw, findings)
            all_assessments.extend(assessments)

        report = toolkit.generate_report(
            {
                "control_assessments": all_assessments,
            }
        )
        assert "soc2" in report["framework_scores"]
        assert "hipaa" in report["framework_scores"]
        assert "pci_dss" in report["framework_scores"]
        assert report["total_controls_assessed"] == 15


# ---------------------------------------------------------------------------
# Backward compatibility with original methods
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    @pytest.mark.asyncio
    async def test_scan_controls_still_works(self, toolkit: ComplianceAuditorToolkit) -> None:
        results = await toolkit.scan_controls("soc2")
        assert len(results) == 5
        assert results[0]["control_id"] == "SOC2-CC6.1"

    @pytest.mark.asyncio
    async def test_collect_evidence_still_works(self, toolkit: ComplianceAuditorToolkit) -> None:
        evidence = await toolkit.collect_evidence("SOC2-CC6.1")
        assert len(evidence) == 1
        assert evidence[0]["id"] == "ev-SOC2-CC6.1-001"

    def test_assess_control_still_works(self, toolkit: ComplianceAuditorToolkit) -> None:
        control = {
            "control_id": "SOC2-CC6.1",
            "framework": "soc2",
            "status": "compliant",
            "gaps": [],
        }
        result = toolkit.assess_control(control, [{"id": "ev-001"}])
        assert result["status"] == "compliant"
        assert result["evidence_refs"] == ["ev-001"]

    def test_generate_audit_report_still_works(self, toolkit: ComplianceAuditorToolkit) -> None:
        assessments = [
            {"status": "compliant", "control_id": "SOC2-CC6.1", "framework": "soc2", "gaps": []},
            {
                "status": "non_compliant",
                "control_id": "SOC2-CC6.2",
                "framework": "soc2",
                "gaps": ["gap"],
            },
        ]
        report = toolkit.generate_audit_report(assessments)
        assert report["total_controls"] == 2
        assert report["compliant"] == 1
        assert report["non_compliant"] == 1
