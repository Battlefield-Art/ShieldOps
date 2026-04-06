"""Tests for Threat Hunter Agent production-readiness.

Covers:
- Hypothesis generation with LLM and heuristic fallback
- IOC sweep queries CrowdStrike and Splunk connectors correctly
- Behavioral analysis runs SPL queries
- MITRE ATT&CK mapping with LLM and keyword fallback
- OPA policy checks before infrastructure actions
- Graph compilation and node structure
- Persistence calls after execution
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.agents.threat_hunter.models import ThreatHunterState
from shieldops.agents.threat_hunter.nodes import (
    analyze_behavior,
    check_mitre,
    generate_hypothesis,
    set_toolkit,
    sweep_iocs,
)
from shieldops.agents.threat_hunter.tools import (
    MITRE_TECHNIQUE_MAP,
    SPL_TEMPLATES,
    ThreatHunterToolkit,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def empty_toolkit() -> ThreatHunterToolkit:
    """Toolkit with no connectors (safe for unit tests)."""
    return ThreatHunterToolkit()


@pytest.fixture()
def mock_crowdstrike() -> AsyncMock:
    """Mock CrowdStrike connector."""
    cs = AsyncMock()
    cs.query_iocs = AsyncMock(
        return_value=[
            {
                "id": "ioc-001",
                "type": "ipv4",
                "value": "10.0.0.99",
                "severity": "high",
                "action": "detect",
            }
        ]
    )
    cs.get_detections = AsyncMock(
        return_value=[
            {
                "detection_id": "det-001",
                "max_severity_displayname": "High",
                "tactic": "Lateral Movement",
                "technique": "T1021",
                "device": {"hostname": "srv-prod-01"},
            }
        ]
    )
    cs.get_threat_graph = AsyncMock(return_value={"resources": [{"id": "graph-1"}]})
    return cs


@pytest.fixture()
def mock_splunk() -> AsyncMock:
    """Mock Splunk connector."""
    sp = AsyncMock()
    sp.search_spl = AsyncMock(
        return_value=[
            {"src_ip": "10.0.0.99", "user": "admin", "count": "15", "sourcetype": "WinEventLog"},
        ]
    )
    return sp


@pytest.fixture()
def connected_toolkit(mock_crowdstrike: AsyncMock, mock_splunk: AsyncMock) -> ThreatHunterToolkit:
    """Toolkit with mock connectors."""
    return ThreatHunterToolkit(
        connector_router={"crowdstrike": mock_crowdstrike, "splunk": mock_splunk},
    )


@pytest.fixture()
def hunt_state() -> ThreatHunterState:
    """Populated hunt state for testing downstream nodes."""
    return ThreatHunterState(
        hypothesis_id="hyp-test01",
        hypothesis="Detect lateral movement via RDP from compromised credentials",
        hunt_scope={
            "time_range": "7d",
            "environments": ["production"],
            "indicators": ["10.0.0.99", "evil.example.com"],
            "mitre_techniques": ["T1021.001", "T1110"],
        },
        data_sources=["authentication_logs", "network_logs", "endpoint_telemetry"],
        ioc_sweep_results=[
            {
                "source": "crowdstrike",
                "indicator": "10.0.0.99",
                "ioc_type": "ipv4",
                "match": {"value": "10.0.0.99", "severity": "high"},
                "severity": "high",
            }
        ],
        behavioral_findings=[
            {
                "source": "splunk",
                "analysis_type": "lateral_movement",
                "deviations": [{"hostname": "srv-prod-01", "user": "admin"}],
                "deviation_count": 3,
                "severity": "high",
            }
        ],
    )


# ---------------------------------------------------------------------------
# Hypothesis Generation Tests
# ---------------------------------------------------------------------------


class TestHypothesisGeneration:
    """Verify hypothesis generation with LLM and heuristic fallback."""

    @pytest.mark.asyncio()
    async def test_hypothesis_uses_heuristic_without_llm(
        self, empty_toolkit: ThreatHunterToolkit
    ) -> None:
        """generate_hypothesis should produce contextual hypotheses with heuristic fallback."""
        context = {
            "hypothesis": "Detect lateral movement via RDP from compromised credentials",
            "hunt_scope": {"indicators": []},
        }
        result = await empty_toolkit.generate_hypothesis(context)

        assert result["hypothesis"]
        assert len(result["data_sources"]) > 0
        assert len(result["mitre_techniques"]) > 0
        # Should map RDP and credentials to MITRE techniques
        assert "T1021.001" in result["mitre_techniques"]  # RDP
        assert any(t in result["mitre_techniques"] for t in ["T1003", "T1078"])  # credentials

    @pytest.mark.asyncio()
    async def test_hypothesis_with_llm_enhancement(
        self, empty_toolkit: ThreatHunterToolkit
    ) -> None:
        """generate_hypothesis should integrate LLM output when available."""
        set_toolkit(empty_toolkit)
        mock_llm_output = MagicMock()
        mock_llm_output.hypothesis = "Refined: APT29 lateral movement via RDP tunneling"
        mock_llm_output.data_sources = ["endpoint_telemetry", "vpn_logs"]
        mock_llm_output.mitre_techniques = ["T1021.001", "T1572"]
        mock_llm_output.confidence = 0.85

        with patch(
            "shieldops.utils.llm.llm_structured",
            new_callable=AsyncMock,
            return_value=mock_llm_output,
        ):
            context = {
                "hypothesis": "lateral movement via RDP",
                "hunt_scope": {},
            }
            result = await empty_toolkit.generate_hypothesis(context)

            assert "APT29" in result["hypothesis"]
            assert "vpn_logs" in result["data_sources"]
            assert result["confidence"] >= 0.85

    @pytest.mark.asyncio()
    async def test_hypothesis_llm_failure_falls_back(
        self, empty_toolkit: ThreatHunterToolkit
    ) -> None:
        """generate_hypothesis should fall back gracefully when LLM fails."""
        with patch(
            "shieldops.utils.llm.llm_structured",
            new_callable=AsyncMock,
            side_effect=Exception("LLM unavailable"),
        ):
            context = {"hypothesis": "brute force attack on VPN", "hunt_scope": {}}
            result = await empty_toolkit.generate_hypothesis(context)

            # Heuristic fallback should still produce results
            assert result["hypothesis"]
            assert "T1110" in result["mitre_techniques"]  # brute force

    @pytest.mark.asyncio()
    async def test_hypothesis_node_produces_state_update(
        self, empty_toolkit: ThreatHunterToolkit
    ) -> None:
        """The generate_hypothesis node should return proper state updates."""
        set_toolkit(empty_toolkit)
        state = ThreatHunterState(
            hypothesis="Detect data exfiltration over DNS tunneling",
        )
        with patch(
            "shieldops.utils.llm.llm_structured",
            new_callable=AsyncMock,
            side_effect=Exception("skip"),
        ):
            result = await generate_hypothesis(state)

        assert "hypothesis" in result
        assert "data_sources" in result
        assert len(result["reasoning_chain"]) == 1
        assert result["reasoning_chain"][0].action == "generate_hypothesis"


# ---------------------------------------------------------------------------
# IOC Sweep Tests
# ---------------------------------------------------------------------------


class TestIOCSweep:
    """Verify IOC sweep queries connectors correctly."""

    @pytest.mark.asyncio()
    async def test_sweep_queries_crowdstrike(
        self,
        connected_toolkit: ThreatHunterToolkit,
        mock_crowdstrike: AsyncMock,
    ) -> None:
        """sweep_iocs should query CrowdStrike IOC management API."""
        scope = {"time_range": "7d", "environment": "production"}
        indicators = ["10.0.0.99"]

        with patch(
            "shieldops.agents.threat_hunter.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            results = await connected_toolkit.sweep_iocs(scope, indicators)

        assert len(results) > 0
        cs_results = [r for r in results if r["source"] == "crowdstrike"]
        assert len(cs_results) >= 1
        mock_crowdstrike.query_iocs.assert_called()

    @pytest.mark.asyncio()
    async def test_sweep_queries_splunk(
        self,
        connected_toolkit: ThreatHunterToolkit,
        mock_splunk: AsyncMock,
    ) -> None:
        """sweep_iocs should search Splunk logs for IOC hits."""
        scope = {"time_range": "7d", "environment": "production"}
        indicators = ["10.0.0.99", "evil.example.com"]

        with patch(
            "shieldops.agents.threat_hunter.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            results = await connected_toolkit.sweep_iocs(scope, indicators)

        splunk_results = [r for r in results if r["source"] == "splunk"]
        assert len(splunk_results) >= 1
        mock_splunk.search_spl.assert_called()

    @pytest.mark.asyncio()
    async def test_sweep_heuristic_fallback(self, empty_toolkit: ThreatHunterToolkit) -> None:
        """sweep_iocs should produce heuristic results when no connectors available."""
        with patch(
            "shieldops.agents.threat_hunter.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            results = await empty_toolkit.sweep_iocs({}, ["10.0.0.99"])

        assert len(results) > 0
        assert results[0]["source"] == "heuristic"

    @pytest.mark.asyncio()
    async def test_sweep_policy_denied(self, connected_toolkit: ThreatHunterToolkit) -> None:
        """sweep_iocs should respect OPA policy denial."""
        with patch(
            "shieldops.agents.threat_hunter.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = False
            mock_decision.reason = "Test deny"
            mock_policy.return_value = mock_decision

            results = await connected_toolkit.sweep_iocs({}, ["10.0.0.99"])

        assert len(results) == 1
        assert results[0]["policy_denied"] is True

    @pytest.mark.asyncio()
    async def test_sweep_policy_error_fails_open(self, empty_toolkit: ThreatHunterToolkit) -> None:
        """sweep_iocs should fail-open on policy evaluation error."""
        with patch(
            "shieldops.agents.threat_hunter.tools.policy_evaluate",
            new_callable=AsyncMock,
            side_effect=Exception("OPA unreachable"),
        ):
            results = await empty_toolkit.sweep_iocs({}, ["10.0.0.99"])

        # Should still produce results (heuristic fallback)
        assert len(results) > 0
        assert "policy_denied" not in results[0]

    @pytest.mark.asyncio()
    async def test_sweep_node_updates_state(self, empty_toolkit: ThreatHunterToolkit) -> None:
        """The sweep_iocs node should return proper state updates."""
        set_toolkit(empty_toolkit)
        state = ThreatHunterState(
            hunt_scope={"indicators": ["10.0.0.99"]},
        )
        with patch(
            "shieldops.agents.threat_hunter.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await sweep_iocs(state)

        assert "ioc_sweep_results" in result
        assert len(result["reasoning_chain"]) == 1
        assert result["reasoning_chain"][0].action == "sweep_iocs"


# ---------------------------------------------------------------------------
# Behavioral Analysis Tests
# ---------------------------------------------------------------------------


class TestBehavioralAnalysis:
    """Verify behavioral analysis runs SPL queries."""

    @pytest.mark.asyncio()
    async def test_behavior_runs_splunk_queries(
        self,
        connected_toolkit: ThreatHunterToolkit,
        mock_splunk: AsyncMock,
    ) -> None:
        """analyze_behavior should run SPL queries via Splunk connector."""
        scope = {
            "time_range": "7d",
            "environment": "production",
            "mitre_techniques": ["T1110"],
        }

        with patch(
            "shieldops.agents.threat_hunter.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            findings = await connected_toolkit.analyze_behavior(scope, "baseline-01")

        assert len(findings) > 0
        splunk_findings = [f for f in findings if f["source"] == "splunk"]
        assert len(splunk_findings) >= 1
        mock_splunk.search_spl.assert_called()

    @pytest.mark.asyncio()
    async def test_behavior_checks_crowdstrike_detections(
        self,
        connected_toolkit: ThreatHunterToolkit,
        mock_crowdstrike: AsyncMock,
    ) -> None:
        """analyze_behavior should check CrowdStrike for endpoint detections."""
        scope = {"time_range": "7d", "environments": ["production"]}

        with patch(
            "shieldops.agents.threat_hunter.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            findings = await connected_toolkit.analyze_behavior(scope, "baseline-01")

        cs_findings = [f for f in findings if f["source"] == "crowdstrike"]
        assert len(cs_findings) >= 1
        mock_crowdstrike.get_detections.assert_called()

    @pytest.mark.asyncio()
    async def test_behavior_selects_queries_from_techniques(
        self, empty_toolkit: ThreatHunterToolkit
    ) -> None:
        """Behavioral query selection should map MITRE techniques to SPL queries."""
        scope = {"mitre_techniques": ["T1021", "T1048"], "hypothesis": ""}
        queries = empty_toolkit._select_behavioral_queries(scope)
        assert "lateral_movement" in queries
        assert "data_exfiltration" in queries

    @pytest.mark.asyncio()
    async def test_behavior_policy_denied(self, connected_toolkit: ThreatHunterToolkit) -> None:
        """analyze_behavior should respect OPA policy denial."""
        with patch(
            "shieldops.agents.threat_hunter.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = False
            mock_decision.reason = "Denied by OPA"
            mock_policy.return_value = mock_decision

            findings = await connected_toolkit.analyze_behavior({}, "baseline-01")

        assert len(findings) == 1
        assert findings[0]["policy_denied"] is True

    @pytest.mark.asyncio()
    async def test_behavior_heuristic_fallback(self, empty_toolkit: ThreatHunterToolkit) -> None:
        """analyze_behavior should produce heuristic results without connectors."""
        with patch(
            "shieldops.agents.threat_hunter.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            findings = await empty_toolkit.analyze_behavior({}, "default")

        assert len(findings) > 0
        assert findings[0]["source"] == "heuristic"

    @pytest.mark.asyncio()
    async def test_behavior_node_updates_state(self, empty_toolkit: ThreatHunterToolkit) -> None:
        """The analyze_behavior node should return proper state updates."""
        set_toolkit(empty_toolkit)
        state = ThreatHunterState(
            hunt_scope={"baseline_id": "default"},
        )
        with patch(
            "shieldops.agents.threat_hunter.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await analyze_behavior(state)

        assert "behavioral_findings" in result
        assert len(result["reasoning_chain"]) == 1
        assert result["reasoning_chain"][0].action == "analyze_behavior"


# ---------------------------------------------------------------------------
# MITRE ATT&CK Mapping Tests
# ---------------------------------------------------------------------------


class TestMITREMapping:
    """Verify MITRE ATT&CK mapping with LLM and keyword fallback."""

    def test_keyword_mitre_mapping(self, empty_toolkit: ThreatHunterToolkit) -> None:
        """Keyword-based mapping should map common threat terms to techniques."""
        techniques = empty_toolkit._map_hypothesis_to_mitre(
            "Detect brute force attack followed by lateral movement via RDP"
        )
        assert "T1110" in techniques  # brute force
        assert "T1021" in techniques  # lateral movement / remote services
        assert "T1021.001" in techniques  # RDP

    def test_mitre_technique_map_has_entries(self) -> None:
        """MITRE technique map should have comprehensive entries."""
        assert len(MITRE_TECHNIQUE_MAP) >= 25
        # Check key techniques exist
        assert "T1059" in MITRE_TECHNIQUE_MAP
        assert "T1110" in MITRE_TECHNIQUE_MAP
        assert "T1021" in MITRE_TECHNIQUE_MAP
        assert "T1486" in MITRE_TECHNIQUE_MAP  # ransomware

    @pytest.mark.asyncio()
    async def test_check_mitre_coverage_with_known_techniques(
        self, empty_toolkit: ThreatHunterToolkit
    ) -> None:
        """check_mitre_coverage should return coverage info for known techniques."""
        coverage = await empty_toolkit.check_mitre_coverage(["T1110", "T1021", "T1059.001"])
        assert len(coverage) == 3
        for entry in coverage:
            assert "technique_id" in entry
            assert "coverage_level" in entry
            assert "recommendation" in entry

    @pytest.mark.asyncio()
    async def test_check_mitre_coverage_unknown_technique(
        self, empty_toolkit: ThreatHunterToolkit
    ) -> None:
        """check_mitre_coverage should flag unknown techniques as gaps."""
        coverage = await empty_toolkit.check_mitre_coverage(["T9999"])
        assert len(coverage) == 1
        assert coverage[0]["technique_name"] == "Unknown"
        assert coverage[0]["gap_identified"] is True

    @pytest.mark.asyncio()
    async def test_check_mitre_node_with_llm(self, empty_toolkit: ThreatHunterToolkit) -> None:
        """check_mitre node should integrate LLM mappings when available."""
        set_toolkit(empty_toolkit)
        state = ThreatHunterState(
            hypothesis="Detect lateral movement",
            hunt_scope={"mitre_techniques": ["T1021"]},
            ioc_sweep_results=[{"indicator": "10.0.0.99", "severity": "high"}],
            behavioral_findings=[{"analysis_type": "lateral_movement", "severity": "high"}],
        )

        mock_llm_output = MagicMock()
        mock_llm_output.technique_mappings = [
            {
                "technique_id": "T1021.002",
                "technique_name": "SMB/Windows Admin Shares",
                "tactic": "Lateral Movement",
                "confidence": "high",
                "evidence": "IOC 10.0.0.99 + lateral movement behavioral finding",
            }
        ]
        mock_llm_output.coverage_gaps = ["T1550"]
        mock_llm_output.kill_chain_phase = "exploit"

        with patch(
            "shieldops.agents.threat_hunter.nodes.llm_structured",
            new_callable=AsyncMock,
            return_value=mock_llm_output,
        ):
            result = await check_mitre(state)

        assert "mitre_findings" in result
        # Should include both original technique + LLM-discovered ones
        technique_ids = [f.get("technique_id") for f in result["mitre_findings"]]
        assert "T1021" in technique_ids
        assert "T1021.002" in technique_ids  # LLM-discovered
        assert "T1550" in technique_ids  # LLM-identified gap

    @pytest.mark.asyncio()
    async def test_check_mitre_node_llm_fallback(self, empty_toolkit: ThreatHunterToolkit) -> None:
        """check_mitre node should work with keyword fallback when LLM fails."""
        set_toolkit(empty_toolkit)
        state = ThreatHunterState(
            hypothesis="Detect brute force",
            hunt_scope={"mitre_techniques": ["T1110"]},
        )

        with patch(
            "shieldops.agents.threat_hunter.nodes.llm_structured",
            new_callable=AsyncMock,
            side_effect=Exception("LLM unavailable"),
        ):
            result = await check_mitre(state)

        assert "mitre_findings" in result
        assert len(result["mitre_findings"]) >= 1
        assert "fallback" in result["reasoning_chain"][-1].output_summary


# ---------------------------------------------------------------------------
# Graph Compilation Tests
# ---------------------------------------------------------------------------


class TestGraphCompilation:
    """Verify the threat hunter graph compiles and has correct structure."""

    def test_graph_compiles(self) -> None:
        """create_threat_hunter_graph() should compile without errors."""
        from shieldops.agents.threat_hunter.graph import create_threat_hunter_graph

        graph = create_threat_hunter_graph()
        app = graph.compile()
        assert app is not None

    def test_graph_has_expected_nodes(self) -> None:
        """Graph should have all expected node names."""
        from shieldops.agents.threat_hunter.graph import create_threat_hunter_graph

        graph = create_threat_hunter_graph()
        expected_nodes = {
            "generate_hypothesis",
            "define_scope",
            "collect_data",
            "sweep_iocs",
            "analyze_behavior",
            "check_mitre",
            "correlate_findings",
            "assess_threat",
            "recommend_response",
            "track_effectiveness",
        }
        assert expected_nodes.issubset(set(graph.nodes.keys()))


# ---------------------------------------------------------------------------
# Persistence Tests
# ---------------------------------------------------------------------------


class TestPersistence:
    """Verify persistence is called after graph execution."""

    @pytest.mark.asyncio()
    async def test_persist_called_on_success(self) -> None:
        """persist_agent_run and write_audit_log should be called after successful hunt."""
        with (
            patch(
                "shieldops.agents.threat_hunter.runner.persist_agent_run",
                new_callable=AsyncMock,
            ) as mock_persist,
            patch(
                "shieldops.agents.threat_hunter.runner.write_audit_log",
                new_callable=AsyncMock,
            ) as mock_audit,
        ):
            from shieldops.agents.threat_hunter.runner import ThreatHunterRunner

            runner = ThreatHunterRunner()

            mock_final_state = ThreatHunterState(
                hypothesis_id="hyp-test01",
                hypothesis="test hypothesis",
                threat_found=True,
                effectiveness_score=0.7,
                current_step="complete",
            )
            runner._app = AsyncMock()
            runner._app.ainvoke = AsyncMock(return_value=mock_final_state.model_dump())

            await runner.hunt("test hypothesis", context={"org_id": "org-1"})

            mock_persist.assert_called_once()
            persist_kwargs = mock_persist.call_args[1]
            assert persist_kwargs["agent_name"] == "threat_hunter"
            assert persist_kwargs["org_id"] == "org-1"

            mock_audit.assert_called_once()
            audit_kwargs = mock_audit.call_args[1]
            assert audit_kwargs["action"] == "threat_hunter.completed"

    @pytest.mark.asyncio()
    async def test_persist_called_on_failure(self) -> None:
        """persist_agent_run should be called with error on failed hunt."""
        with (
            patch(
                "shieldops.agents.threat_hunter.runner.persist_agent_run",
                new_callable=AsyncMock,
            ) as mock_persist,
            patch(
                "shieldops.agents.threat_hunter.runner.write_audit_log",
                new_callable=AsyncMock,
            ) as mock_audit,
        ):
            from shieldops.agents.threat_hunter.runner import ThreatHunterRunner

            runner = ThreatHunterRunner()
            runner._app = AsyncMock()
            runner._app.ainvoke = AsyncMock(side_effect=RuntimeError("Graph execution failed"))

            result = await runner.hunt("test hypothesis", context={"org_id": "org-1"})

            assert result.error == "Graph execution failed"
            mock_persist.assert_called_once()
            persist_kwargs = mock_persist.call_args[1]
            assert persist_kwargs["error_message"] == "Graph execution failed"

            mock_audit.assert_called_once()
            audit_kwargs = mock_audit.call_args[1]
            assert audit_kwargs["action"] == "threat_hunter.failed"


# ---------------------------------------------------------------------------
# Correlation Tests
# ---------------------------------------------------------------------------


class TestCorrelation:
    """Verify finding correlation logic."""

    @pytest.mark.asyncio()
    async def test_correlate_groups_by_ip(self, empty_toolkit: ThreatHunterToolkit) -> None:
        """correlate_findings should group findings sharing the same IP."""
        findings: list[dict[str, Any]] = [
            {"type": "ioc", "source": "crowdstrike", "src_ip": "10.0.0.99", "severity": "high"},
            {"type": "behavioral", "source": "splunk", "src_ip": "10.0.0.99", "severity": "high"},
        ]
        groups = await empty_toolkit.correlate_findings(findings)
        assert len(groups) >= 1
        ip_group = [g for g in groups if g["entity_type"] == "ip_address"]
        assert len(ip_group) >= 1
        assert ip_group[0]["cross_source"] is True

    @pytest.mark.asyncio()
    async def test_correlate_empty_findings(self, empty_toolkit: ThreatHunterToolkit) -> None:
        """correlate_findings should handle empty input gracefully."""
        groups = await empty_toolkit.correlate_findings([])
        assert groups == []


# ---------------------------------------------------------------------------
# Helper Method Tests
# ---------------------------------------------------------------------------


class TestHelperMethods:
    """Verify private helper methods work correctly."""

    def test_classify_ioc_type_ipv4(self, empty_toolkit: ThreatHunterToolkit) -> None:
        assert empty_toolkit._classify_ioc_type("192.168.1.1") == "ipv4"

    def test_classify_ioc_type_sha256(self, empty_toolkit: ThreatHunterToolkit) -> None:
        assert empty_toolkit._classify_ioc_type("a" * 64) == "sha256"

    def test_classify_ioc_type_md5(self, empty_toolkit: ThreatHunterToolkit) -> None:
        assert empty_toolkit._classify_ioc_type("a" * 32) == "md5"

    def test_classify_ioc_type_domain(self, empty_toolkit: ThreatHunterToolkit) -> None:
        assert empty_toolkit._classify_ioc_type("evil.example.com") == "domain"

    def test_identify_data_sources(self, empty_toolkit: ThreatHunterToolkit) -> None:
        sources = empty_toolkit._identify_data_sources("lateral movement via network")
        assert "network_logs" in sources

    def test_score_hypothesis_confidence(self, empty_toolkit: ThreatHunterToolkit) -> None:
        score = empty_toolkit._score_hypothesis_confidence(
            "Detect brute force attack on VPN using ip address 10.0.0.1",
            ["T1110"],
        )
        assert score > 0.3  # base score
        assert score <= 0.9

    def test_spl_templates_exist(self) -> None:
        """SPL templates should cover key behavioral query types."""
        assert "anomalous_auth" in SPL_TEMPLATES
        assert "lateral_movement" in SPL_TEMPLATES
        assert "data_exfiltration" in SPL_TEMPLATES
        assert "command_and_control" in SPL_TEMPLATES
        assert len(SPL_TEMPLATES) >= 8
