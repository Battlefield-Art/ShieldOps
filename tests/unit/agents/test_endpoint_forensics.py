"""Tests for shieldops.agents.endpoint_forensics."""

from __future__ import annotations

import pytest

from shieldops.agents.endpoint_forensics.models import (
    ArtifactType,
    EndpointForensicsState,
    FindingSeverity,
    ForensicArtifact,
    ForensicsStage,
    MemoryFinding,
    TimelineEvent,
)


def _state(**kw) -> EndpointForensicsState:
    return EndpointForensicsState(**kw)


class TestEnums:
    def test_forensics_stage_values(self):
        assert ForensicsStage.COLLECT_ARTIFACTS == "collect_artifacts"
        assert ForensicsStage.ANALYZE_MEMORY == "analyze_memory"
        assert ForensicsStage.INVESTIGATE_PROCESSES == "investigate_processes"
        assert ForensicsStage.CARVE_FILES == "carve_files"
        assert ForensicsStage.RECONSTRUCT_TIMELINE == "reconstruct_timeline"
        assert ForensicsStage.REPORT == "report"

    def test_artifact_type_values(self):
        assert ArtifactType.MEMORY_DUMP == "memory_dump"
        assert ArtifactType.PROCESS_LIST == "process_list"
        assert ArtifactType.NETWORK_CONNECTIONS == "network_connections"
        assert ArtifactType.FILE_SYSTEM == "file_system"
        assert ArtifactType.REGISTRY == "registry"
        assert ArtifactType.EVENT_LOG == "event_log"
        assert ArtifactType.PREFETCH == "prefetch"

    def test_finding_severity_values(self):
        assert FindingSeverity.CRITICAL == "critical"
        assert FindingSeverity.HIGH == "high"
        assert FindingSeverity.MEDIUM == "medium"
        assert FindingSeverity.LOW == "low"
        assert FindingSeverity.INFO == "info"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.endpoint_id == ""
        assert s.case_id == ""
        assert s.stage == ForensicsStage.COLLECT_ARTIFACTS
        assert s.artifacts == []
        assert s.total_artifacts == 0
        assert s.memory_findings == []
        assert s.injected_processes == 0
        assert s.suspicious_processes == []
        assert s.process_tree == []
        assert s.carved_files == []
        assert s.malware_found == 0
        assert s.timeline == []
        assert s.summary == ""
        assert s.ioc_list == []
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(endpoint_id="EP-001", case_id="CASE-001", malware_found=3)
        assert s.endpoint_id == "EP-001"
        assert s.case_id == "CASE-001"
        assert s.malware_found == 3

    def test_forensic_artifact_defaults(self):
        a = ForensicArtifact()
        assert a.id == ""
        assert a.artifact_type == ArtifactType.FILE_SYSTEM
        assert a.size_bytes == 0

    def test_memory_finding_defaults(self):
        m = MemoryFinding()
        assert m.severity == FindingSeverity.INFO
        assert m.indicators == []
        assert m.pid == 0

    def test_timeline_event_defaults(self):
        t = TimelineEvent()
        assert t.source == ""
        assert t.severity == FindingSeverity.INFO
        assert t.evidence == {}


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.endpoint_forensics.tools import (
            EndpointForensicsToolkit,
        )

        return EndpointForensicsToolkit()

    @pytest.mark.asyncio
    async def test_collect_artifacts(self, toolkit):
        result = await toolkit.collect_artifacts("EP-001", "CASE-001")
        assert isinstance(result, list)
        assert len(result) >= 3

    @pytest.mark.asyncio
    async def test_analyze_memory(self, toolkit):
        artifacts = await toolkit.collect_artifacts("EP-001", "CASE-001")
        findings, injected = await toolkit.analyze_memory(artifacts)
        assert isinstance(findings, list)
        assert len(findings) >= 2
        assert injected >= 2

    @pytest.mark.asyncio
    async def test_investigate_processes(self, toolkit):
        artifacts = await toolkit.collect_artifacts("EP-001", "CASE-001")
        suspicious, tree = await toolkit.investigate_processes(artifacts)
        assert isinstance(suspicious, list)
        assert isinstance(tree, list)

    @pytest.mark.asyncio
    async def test_carve_files(self, toolkit):
        artifacts = await toolkit.collect_artifacts("EP-001", "CASE-001")
        carved, malware = await toolkit.carve_files(artifacts)
        assert isinstance(carved, list)
        assert malware >= 1

    @pytest.mark.asyncio
    async def test_reconstruct_timeline(self, toolkit):
        timeline = await toolkit.reconstruct_timeline([], [], [])
        assert isinstance(timeline, list)
        assert len(timeline) >= 3


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.endpoint_forensics.graph import (
            create_endpoint_forensics_graph,
        )

        sg = create_endpoint_forensics_graph()
        assert sg.compile() is not None
