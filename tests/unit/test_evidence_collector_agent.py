"""Unit tests for evidence_collector agent."""

from __future__ import annotations

import pytest

from shieldops.agents.evidence_collector.models import (
    Artifact,
    ArtifactType,
    ChainOfCustody,
    CollectedArtifact,
    CustodyStatus,
    EvidenceCollectorState,
    EvidencePackage,
    EvidenceSource,
    EvidenceStage,
    EvidenceType,
    IntegrityStatus,
    IntegrityVerification,
)
from shieldops.agents.evidence_collector.tools import (
    SOURCE_TEMPLATES,
    EvidenceCollectorToolkit,
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class TestEnums:
    def test_evidence_stage_values(self):
        assert EvidenceStage.IDENTIFY_SOURCES == "identify_sources"
        assert EvidenceStage.REPORT == "report"

    def test_artifact_type_values(self):
        assert ArtifactType.MEMORY_DUMP == "memory_dump"
        assert ArtifactType.PROCESS_LIST == "process_list"

    def test_custody_status_values(self):
        assert CustodyStatus.COLLECTED == "collected"
        assert CustodyStatus.COMPROMISED == "compromised"

    def test_evidence_type_values(self):
        assert EvidenceType.MEMORY_DUMP == "memory_dump"
        assert EvidenceType.REGISTRY_HIVE == "registry_hive"

    def test_integrity_status_values(self):
        assert IntegrityStatus.VERIFIED == "verified"
        assert IntegrityStatus.TAMPERED == "tampered"


class TestState:
    def test_defaults(self):
        state = EvidenceCollectorState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.error == ""
        assert state.stage == EvidenceStage.IDENTIFY_SOURCES
        assert state.incident_id == ""
        assert state.incident_details == {}
        assert state.sources == []
        assert state.artifacts == []
        assert state.verifications == []
        assert state.custody_records == []
        assert state.package == {}
        assert state.report == {}
        assert state.verified_count == 0
        assert state.reasoning_chain == []
        assert state.session_start == 0.0

    def test_with_values(self):
        state = EvidenceCollectorState(
            request_id="req-1",
            tenant_id="t-1",
            incident_id="inc-7",
            incident_details={"type": "malware", "affected_hosts": ["srv-1"]},
        )
        assert state.request_id == "req-1"
        assert state.incident_id == "inc-7"
        assert state.incident_details["type"] == "malware"


class TestModels:
    def test_artifact_defaults(self):
        a = Artifact()
        assert a.artifact_type == ArtifactType.LOG_FILE
        assert a.custody == CustodyStatus.COLLECTED

    def test_evidence_source_defaults(self):
        es = EvidenceSource()
        assert es.accessible is True
        assert es.priority == "medium"

    def test_collected_artifact_defaults(self):
        ca = CollectedArtifact()
        assert ca.evidence_type == EvidenceType.LOG_FILES
        assert ca.metadata == {}

    def test_integrity_verification_defaults(self):
        iv = IntegrityVerification()
        assert iv.status == IntegrityStatus.UNKNOWN
        assert iv.hash_verified is False

    def test_chain_of_custody_defaults(self):
        coc = ChainOfCustody()
        assert coc.custodian == ""
        assert coc.signature == ""

    def test_evidence_package_defaults(self):
        ep = EvidencePackage()
        assert ep.artifact_ids == []
        assert ep.total_size_bytes == 0


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        return EvidenceCollectorToolkit()

    @pytest.mark.asyncio
    async def test_identify_sources_malware(self, toolkit):
        details = {
            "type": "malware",
            "affected_hosts": ["srv-1", "srv-2"],
        }
        sources = await toolkit.identify_sources(details)
        templates = SOURCE_TEMPLATES["malware"]
        assert len(sources) == len(templates) * 2  # 2 hosts
        for src in sources:
            assert isinstance(src, EvidenceSource)
            assert src.id.startswith("src-")
            assert src.accessible is True

    @pytest.mark.asyncio
    async def test_identify_sources_default(self, toolkit):
        details = {"type": "unknown_type"}
        sources = await toolkit.identify_sources(details)
        assert len(sources) == len(SOURCE_TEMPLATES["default"])

    @pytest.mark.asyncio
    async def test_collect_artifact(self, toolkit):
        source = EvidenceSource(
            id="src-test",
            host="srv-1",
            source_type=EvidenceType.LOG_FILES,
            path="/var/log/syslog",
            estimated_size_mb=100,
        )
        artifact = await toolkit.collect_artifact(source)
        assert isinstance(artifact, CollectedArtifact)
        assert artifact.id.startswith("art-")
        assert artifact.source_id == "src-test"
        assert artifact.sha256_hash != ""
        assert artifact.size_bytes == 100 * 1024 * 1024
        assert artifact.collector == "evidence_collector_agent"

    @pytest.mark.asyncio
    async def test_verify_integrity(self, toolkit):
        artifact = CollectedArtifact(
            id="art-test",
            sha256_hash="abc123",
        )
        result = await toolkit.verify_integrity(artifact)
        assert isinstance(result, IntegrityVerification)
        assert result.status == IntegrityStatus.VERIFIED
        assert result.hash_verified is True
        assert result.original_hash == "abc123"
        assert result.current_hash == "abc123"

    @pytest.mark.asyncio
    async def test_package_evidence(self, toolkit):
        artifacts = [
            CollectedArtifact(
                id="art-1",
                sha256_hash="hash1",
                size_bytes=1000,
            ),
            CollectedArtifact(
                id="art-2",
                sha256_hash="hash2",
                size_bytes=2000,
            ),
        ]
        pkg = await toolkit.package_evidence("inc-1", artifacts)
        assert isinstance(pkg, EvidencePackage)
        assert pkg.id.startswith("pkg-")
        assert pkg.incident_id == "inc-1"
        assert pkg.artifact_ids == ["art-1", "art-2"]
        assert pkg.total_size_bytes == 3000
        assert pkg.package_hash != ""
        assert pkg.storage_location.startswith("s3://")

    @pytest.mark.asyncio
    async def test_record_custody(self, toolkit):
        record = await toolkit.record_custody(
            artifact_id="art-1",
            custodian="forensics_agent",
            action="collected",
            purpose="incident investigation",
        )
        assert isinstance(record, ChainOfCustody)
        assert record.id.startswith("coc-")
        assert record.artifact_id == "art-1"
        assert record.custodian == "forensics_agent"
        assert record.action == "collected"
        assert record.signature != ""


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio
    async def test_identify_sources_node(self):
        from shieldops.agents.evidence_collector.nodes import (
            identify_sources,
            set_toolkit,
        )

        set_toolkit(EvidenceCollectorToolkit())
        state = EvidenceCollectorState(
            incident_id="inc-1",
            incident_details={
                "type": "malware",
                "affected_hosts": ["srv-1"],
            },
        )
        result = await identify_sources(state)
        assert "sources" in result
        assert len(result["sources"]) > 0
        assert result["stage"] == EvidenceStage.COLLECT_ARTIFACTS

    @pytest.mark.asyncio
    async def test_collect_artifacts_node(self):
        from shieldops.agents.evidence_collector.nodes import (
            collect_artifacts,
            set_toolkit,
        )

        set_toolkit(EvidenceCollectorToolkit())
        state = EvidenceCollectorState(
            incident_id="inc-1",
            sources=[
                EvidenceSource(
                    id="src-1",
                    host="srv-1",
                    source_type=EvidenceType.LOG_FILES,
                    path="/var/log",
                    estimated_size_mb=50,
                ),
            ],
        )
        result = await collect_artifacts(state)
        assert len(result["artifacts"]) == 1
        assert result["stage"] == EvidenceStage.HASH_VERIFY

    @pytest.mark.asyncio
    async def test_hash_verify_node(self):
        from shieldops.agents.evidence_collector.nodes import (
            hash_verify,
            set_toolkit,
        )

        set_toolkit(EvidenceCollectorToolkit())
        state = EvidenceCollectorState(
            incident_id="inc-1",
            artifacts=[
                CollectedArtifact(id="art-1", sha256_hash="aaa"),
                CollectedArtifact(id="art-2", sha256_hash="bbb"),
            ],
        )
        result = await hash_verify(state)
        assert result["verified_count"] == 2
        assert len(result["verifications"]) == 2
        assert result["stage"] == EvidenceStage.CHAIN_OF_CUSTODY

    @pytest.mark.asyncio
    async def test_chain_of_custody_node(self):
        from shieldops.agents.evidence_collector.nodes import (
            chain_of_custody,
            set_toolkit,
        )

        set_toolkit(EvidenceCollectorToolkit())
        state = EvidenceCollectorState(
            incident_id="inc-1",
            artifacts=[CollectedArtifact(id="art-1")],
        )
        result = await chain_of_custody(state)
        assert len(result["custody_records"]) == 1
        assert result["stage"] == EvidenceStage.PACKAGE_EVIDENCE

    @pytest.mark.asyncio
    async def test_package_evidence_node(self):
        from shieldops.agents.evidence_collector.nodes import (
            package_evidence,
            set_toolkit,
        )

        set_toolkit(EvidenceCollectorToolkit())
        state = EvidenceCollectorState(
            incident_id="inc-1",
            artifacts=[
                CollectedArtifact(
                    id="art-1",
                    sha256_hash="hash1",
                    size_bytes=500,
                ),
            ],
        )
        result = await package_evidence(state)
        assert "package" in result
        assert result["stage"] == EvidenceStage.REPORT

    @pytest.mark.asyncio
    async def test_report_node(self):
        import time

        from shieldops.agents.evidence_collector.nodes import (
            report,
            set_toolkit,
        )

        set_toolkit(EvidenceCollectorToolkit())
        state = EvidenceCollectorState(
            incident_id="inc-1",
            session_start=time.time(),
            sources=[EvidenceSource(id="src-1")],
            artifacts=[CollectedArtifact(id="art-1")],
            verifications=[
                IntegrityVerification(hash_verified=True),
            ],
            verified_count=1,
            custody_records=[ChainOfCustody(id="coc-1")],
            package={"id": "pkg-1"},
        )
        result = await report(state)
        assert "report" in result
        assert result["report"]["status"] == "complete"


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class TestRunner:
    def test_runner_init(self):
        from shieldops.agents.evidence_collector.runner import (
            EvidenceCollectorRunner,
        )

        runner = EvidenceCollectorRunner()
        assert runner is not None
