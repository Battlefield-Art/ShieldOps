"""Tests for Phase 140 Engines (engines 4-8)."""

from __future__ import annotations

from shieldops.analytics.agent_specialization_engine import (
    AdaptationSpeed,
    AgentSpecializationEngine,
    ProficiencyLevel,
    SpecializationDomain,
)
from shieldops.analytics.knowledge_graph_engine import (
    EntityType,
    GraphHealth,
    KnowledgeGraphEngine,
    RelationshipType,
)
from shieldops.analytics.predictive_incident_engine import (
    IndicatorType,
    PredictionConfidence,
    PredictionHorizon,
    PredictiveIncidentEngine,
)
from shieldops.security.attack_path_analysis_engine import (
    AttackPathAnalysisEngine,
    EntryPointType,
    PathComplexity,
    PathStatus,
)
from shieldops.security.stride_analysis_engine import (
    AnalysisDepth,
    StrideAnalysisEngine,
    StrideCategory,
    ThreatStatus,
)

# ============================================================
# StrideAnalysisEngine Tests
# ============================================================


class TestStrideAnalysisEnums:
    def test_stride_category_values(self) -> None:
        assert StrideCategory.SPOOFING == "spoofing"
        assert StrideCategory.TAMPERING == "tampering"
        assert StrideCategory.REPUDIATION == "repudiation"
        assert StrideCategory.INFO_DISCLOSURE == "info_disclosure"
        assert StrideCategory.DENIAL_OF_SERVICE == "denial_of_service"
        assert StrideCategory.ELEVATION == "elevation"

    def test_threat_status_values(self) -> None:
        assert ThreatStatus.IDENTIFIED == "identified"
        assert ThreatStatus.MITIGATED == "mitigated"
        assert ThreatStatus.ACCEPTED == "accepted"
        assert ThreatStatus.MONITORING == "monitoring"

    def test_analysis_depth_values(self) -> None:
        assert AnalysisDepth.SURFACE == "surface"
        assert AnalysisDepth.STANDARD == "standard"
        assert AnalysisDepth.DEEP == "deep"


class TestStrideAnalysisEngine:
    def setup_method(self) -> None:
        self.engine = StrideAnalysisEngine(max_records=100, threshold=50.0)

    def test_init(self) -> None:
        assert self.engine._max_records == 100
        assert self.engine._threshold == 50.0

    def test_add_record(self) -> None:
        r = self.engine.add_record(name="t1", score=70.0, service="svc-a")
        assert r.name == "t1"
        assert len(self.engine._records) == 1

    def test_add_record_with_enums(self) -> None:
        r = self.engine.add_record(
            name="t1",
            category=StrideCategory.ELEVATION,
            status=ThreatStatus.MITIGATED,
            depth=AnalysisDepth.DEEP,
        )
        assert r.category == StrideCategory.ELEVATION
        assert r.status == ThreatStatus.MITIGATED
        assert r.depth == AnalysisDepth.DEEP

    def test_ring_buffer_eviction(self) -> None:
        for i in range(150):
            self.engine.add_record(name=f"r{i}")
        assert len(self.engine._records) == 100

    def test_get_record(self) -> None:
        r = self.engine.add_record(name="find")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        assert self.engine.get_record("nope") is None

    def test_list_records_filter_category(self) -> None:
        self.engine.add_record(name="a", category=StrideCategory.SPOOFING)
        self.engine.add_record(name="b", category=StrideCategory.TAMPERING)
        result = self.engine.list_records(category=StrideCategory.SPOOFING)
        assert len(result) == 1

    def test_list_records_filter_status(self) -> None:
        self.engine.add_record(name="a", status=ThreatStatus.IDENTIFIED)
        self.engine.add_record(name="b", status=ThreatStatus.MITIGATED)
        result = self.engine.list_records(status=ThreatStatus.MITIGATED)
        assert len(result) == 1

    def test_list_records_filter_team(self) -> None:
        self.engine.add_record(name="a", team="alpha")
        self.engine.add_record(name="b", team="beta")
        result = self.engine.list_records(team="alpha")
        assert len(result) == 1

    def test_add_analysis(self) -> None:
        a = self.engine.add_analysis(name="a1", analysis_score=80.0)
        assert a.analysis_score == 80.0

    def test_compute_threat_density(self) -> None:
        self.engine.add_record(
            name="r1", service="svc-a", category=StrideCategory.SPOOFING, threat_count=5
        )
        self.engine.add_record(
            name="r2", service="svc-a", category=StrideCategory.TAMPERING, threat_count=3
        )
        result = self.engine.compute_threat_density()
        assert len(result) == 1
        assert result[0]["total_threats"] == 8

    def test_compute_threat_density_grade(self) -> None:
        self.engine.add_record(
            name="r1", service="svc-a", category=StrideCategory.SPOOFING, threat_count=25
        )
        result = self.engine.compute_threat_density()
        assert result[0]["density_grade"] == "critical"

    def test_identify_unmitigated_threats(self) -> None:
        self.engine.add_record(
            name="r1", service="svc-a", status=ThreatStatus.IDENTIFIED, severity_score=9.0
        )
        self.engine.add_record(
            name="r2", service="svc-a", status=ThreatStatus.MITIGATED, severity_score=8.0
        )
        result = self.engine.identify_unmitigated_threats()
        assert len(result) == 1
        assert result[0]["priority"] == "critical"

    def test_identify_unmitigated_threats_low(self) -> None:
        self.engine.add_record(
            name="r1", status=ThreatStatus.IDENTIFIED, severity_score=2.0, service="svc"
        )
        result = self.engine.identify_unmitigated_threats()
        assert result[0]["priority"] == "low"

    def test_recommend_analysis_priorities(self) -> None:
        self.engine.add_record(
            name="r1",
            service="svc-a",
            depth=AnalysisDepth.SURFACE,
            status=ThreatStatus.IDENTIFIED,
            severity_score=7.0,
        )
        result = self.engine.recommend_analysis_priorities()
        assert len(result) >= 1
        assert result[0]["priority"] == "high"

    def test_recommend_analysis_priorities_high_severity(self) -> None:
        self.engine.add_record(
            name="r1",
            service="svc-b",
            depth=AnalysisDepth.STANDARD,
            status=ThreatStatus.IDENTIFIED,
            severity_score=8.0,
        )
        result = self.engine.recommend_analysis_priorities()
        assert any(r["issue"] == "high_severity_unmitigated" for r in result)

    def test_analyze_distribution(self) -> None:
        self.engine.add_record(name="r1", category=StrideCategory.SPOOFING, score=70.0)
        result = self.engine.analyze_distribution()
        assert "spoofing" in result

    def test_identify_gaps(self) -> None:
        self.engine.add_record(name="low", score=10.0, service="svc")
        gaps = self.engine.identify_gaps()
        assert len(gaps) == 1

    def test_rank_by_score(self) -> None:
        self.engine.add_record(name="r1", service="a", score=20.0)
        self.engine.add_record(name="r2", service="b", score=90.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "a"

    def test_process_found(self) -> None:
        self.engine.add_record(name="k1", score=60.0)
        assert self.engine.process("k1")["status"] == "processed"

    def test_process_not_found(self) -> None:
        assert self.engine.process("nope")["status"] == "not_found"

    def test_generate_report(self) -> None:
        self.engine.add_record(name="r1", score=30.0, service="svc")
        report = self.engine.generate_report()
        assert report.total_records == 1
        assert report.gap_count == 1

    def test_generate_report_healthy(self) -> None:
        self.engine.add_record(name="r1", score=90.0, service="svc")
        report = self.engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self) -> None:
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self) -> None:
        self.engine.add_record(name="r1", service="svc", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1


# ============================================================
# AttackPathAnalysisEngine Tests
# ============================================================


class TestAttackPathAnalysisEnums:
    def test_path_complexity_values(self) -> None:
        assert PathComplexity.TRIVIAL == "trivial"
        assert PathComplexity.MODERATE == "moderate"
        assert PathComplexity.COMPLEX == "complex"
        assert PathComplexity.THEORETICAL == "theoretical"

    def test_path_status_values(self) -> None:
        assert PathStatus.ACTIVE == "active"
        assert PathStatus.BLOCKED == "blocked"
        assert PathStatus.PARTIALLY_BLOCKED == "partially_blocked"

    def test_entry_point_type_values(self) -> None:
        assert EntryPointType.EXTERNAL == "external"
        assert EntryPointType.INTERNAL == "internal"
        assert EntryPointType.SUPPLY_CHAIN == "supply_chain"


class TestAttackPathAnalysisEngine:
    def setup_method(self) -> None:
        self.engine = AttackPathAnalysisEngine(max_records=100, threshold=50.0)

    def test_init(self) -> None:
        assert self.engine._max_records == 100

    def test_add_record(self) -> None:
        r = self.engine.add_record(name="path1", score=60.0, service="svc-a")
        assert r.name == "path1"

    def test_add_record_with_enums(self) -> None:
        r = self.engine.add_record(
            name="p1",
            complexity=PathComplexity.TRIVIAL,
            status=PathStatus.BLOCKED,
            entry_point=EntryPointType.SUPPLY_CHAIN,
        )
        assert r.complexity == PathComplexity.TRIVIAL
        assert r.status == PathStatus.BLOCKED
        assert r.entry_point == EntryPointType.SUPPLY_CHAIN

    def test_ring_buffer_eviction(self) -> None:
        for i in range(150):
            self.engine.add_record(name=f"r{i}")
        assert len(self.engine._records) == 100

    def test_get_record(self) -> None:
        r = self.engine.add_record(name="find")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        assert self.engine.get_record("nope") is None

    def test_list_records_filter_complexity(self) -> None:
        self.engine.add_record(name="a", complexity=PathComplexity.TRIVIAL)
        self.engine.add_record(name="b", complexity=PathComplexity.COMPLEX)
        result = self.engine.list_records(complexity=PathComplexity.TRIVIAL)
        assert len(result) == 1

    def test_list_records_filter_status(self) -> None:
        self.engine.add_record(name="a", status=PathStatus.ACTIVE)
        self.engine.add_record(name="b", status=PathStatus.BLOCKED)
        result = self.engine.list_records(status=PathStatus.BLOCKED)
        assert len(result) == 1

    def test_add_analysis(self) -> None:
        a = self.engine.add_analysis(name="a1", analysis_score=55.0)
        assert a.analysis_score == 55.0

    def test_identify_shortest_attack_paths(self) -> None:
        self.engine.add_record(
            name="p1",
            service="svc-a",
            status=PathStatus.ACTIVE,
            complexity=PathComplexity.TRIVIAL,
            path_length=1,
            risk_score=9.0,
        )
        self.engine.add_record(
            name="p2",
            service="svc-a",
            status=PathStatus.ACTIVE,
            complexity=PathComplexity.COMPLEX,
            path_length=5,
            risk_score=3.0,
        )
        result = self.engine.identify_shortest_attack_paths()
        assert len(result) == 2
        assert result[0]["name"] == "p1"  # shorter effective length
        assert result[0]["priority"] == "critical"

    def test_identify_shortest_attack_paths_blocked_excluded(self) -> None:
        self.engine.add_record(name="p1", status=PathStatus.BLOCKED, path_length=1, service="svc")
        result = self.engine.identify_shortest_attack_paths()
        assert len(result) == 0

    def test_evaluate_path_blockage(self) -> None:
        self.engine.add_record(name="p1", service="svc-a", status=PathStatus.BLOCKED)
        self.engine.add_record(name="p2", service="svc-a", status=PathStatus.ACTIVE)
        result = self.engine.evaluate_path_blockage()
        assert len(result) == 1
        assert result[0]["blockage_pct"] == 50.0

    def test_evaluate_path_blockage_excellent(self) -> None:
        for _ in range(10):
            self.engine.add_record(name="p", service="svc-a", status=PathStatus.BLOCKED)
        result = self.engine.evaluate_path_blockage()
        assert result[0]["grade"] == "excellent"

    def test_recommend_choke_points(self) -> None:
        self.engine.add_record(
            name="p1",
            service="svc-a",
            status=PathStatus.ACTIVE,
            complexity=PathComplexity.TRIVIAL,
            risk_score=8.0,
        )
        result = self.engine.recommend_choke_points()
        assert len(result) == 1
        assert result[0]["priority"] == "critical"

    def test_recommend_choke_points_no_active(self) -> None:
        self.engine.add_record(name="p1", service="svc-a", status=PathStatus.BLOCKED)
        result = self.engine.recommend_choke_points()
        assert len(result) == 0

    def test_analyze_distribution(self) -> None:
        self.engine.add_record(name="r1", complexity=PathComplexity.MODERATE, score=70.0)
        result = self.engine.analyze_distribution()
        assert "moderate" in result

    def test_identify_gaps(self) -> None:
        self.engine.add_record(name="low", score=10.0, service="svc")
        assert len(self.engine.identify_gaps()) == 1

    def test_rank_by_score(self) -> None:
        self.engine.add_record(name="r1", service="a", score=20.0)
        self.engine.add_record(name="r2", service="b", score=80.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "a"

    def test_process_found(self) -> None:
        self.engine.add_record(name="k1", score=60.0)
        assert self.engine.process("k1")["status"] == "processed"

    def test_process_not_found(self) -> None:
        assert self.engine.process("nope")["status"] == "not_found"

    def test_generate_report(self) -> None:
        self.engine.add_record(name="r1", score=30.0, service="svc")
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_clear_data(self) -> None:
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self) -> None:
        self.engine.add_record(name="r1", service="svc", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1


# ============================================================
# AgentSpecializationEngine Tests
# ============================================================


class TestAgentSpecializationEnums:
    def test_specialization_domain_values(self) -> None:
        assert SpecializationDomain.INFRASTRUCTURE == "infrastructure"
        assert SpecializationDomain.SECURITY == "security"
        assert SpecializationDomain.COST == "cost"
        assert SpecializationDomain.COMPLIANCE == "compliance"
        assert SpecializationDomain.OBSERVABILITY == "observability"

    def test_proficiency_level_values(self) -> None:
        assert ProficiencyLevel.NOVICE == "novice"
        assert ProficiencyLevel.COMPETENT == "competent"
        assert ProficiencyLevel.PROFICIENT == "proficient"
        assert ProficiencyLevel.EXPERT == "expert"

    def test_adaptation_speed_values(self) -> None:
        assert AdaptationSpeed.FAST == "fast"
        assert AdaptationSpeed.MODERATE == "moderate"
        assert AdaptationSpeed.SLOW == "slow"


class TestAgentSpecializationEngine:
    def setup_method(self) -> None:
        self.engine = AgentSpecializationEngine(max_records=100, threshold=50.0)

    def test_init(self) -> None:
        assert self.engine._max_records == 100

    def test_add_record(self) -> None:
        r = self.engine.add_record(name="agent-1", score=80.0, service="svc")
        assert r.name == "agent-1"

    def test_add_record_with_enums(self) -> None:
        r = self.engine.add_record(
            name="a1",
            domain=SpecializationDomain.SECURITY,
            proficiency=ProficiencyLevel.EXPERT,
            adaptation=AdaptationSpeed.FAST,
        )
        assert r.domain == SpecializationDomain.SECURITY
        assert r.proficiency == ProficiencyLevel.EXPERT
        assert r.adaptation == AdaptationSpeed.FAST

    def test_ring_buffer_eviction(self) -> None:
        for i in range(150):
            self.engine.add_record(name=f"r{i}")
        assert len(self.engine._records) == 100

    def test_get_record(self) -> None:
        r = self.engine.add_record(name="find")
        assert self.engine.get_record(r.id) is not None

    def test_list_records_filter_domain(self) -> None:
        self.engine.add_record(name="a", domain=SpecializationDomain.SECURITY)
        self.engine.add_record(name="b", domain=SpecializationDomain.COST)
        result = self.engine.list_records(domain=SpecializationDomain.SECURITY)
        assert len(result) == 1

    def test_list_records_filter_proficiency(self) -> None:
        self.engine.add_record(name="a", proficiency=ProficiencyLevel.NOVICE)
        self.engine.add_record(name="b", proficiency=ProficiencyLevel.EXPERT)
        result = self.engine.list_records(proficiency=ProficiencyLevel.EXPERT)
        assert len(result) == 1

    def test_add_analysis(self) -> None:
        a = self.engine.add_analysis(name="a1", analysis_score=90.0)
        assert a.analysis_score == 90.0

    def test_identify_agent_specializations(self) -> None:
        self.engine.add_record(
            name="agent-1", domain=SpecializationDomain.SECURITY, success_rate=0.95, service="svc"
        )
        self.engine.add_record(
            name="agent-1", domain=SpecializationDomain.COST, success_rate=0.60, service="svc"
        )
        result = self.engine.identify_agent_specializations()
        assert len(result) == 1
        assert result[0]["best_domain"] == "security"
        assert result[0]["domains_covered"] == 2

    def test_detect_skill_overlap(self) -> None:
        self.engine.add_record(
            name="agent-1",
            domain=SpecializationDomain.SECURITY,
            proficiency=ProficiencyLevel.EXPERT,
            service="svc",
        )
        self.engine.add_record(
            name="agent-2",
            domain=SpecializationDomain.SECURITY,
            proficiency=ProficiencyLevel.PROFICIENT,
            service="svc",
        )
        result = self.engine.detect_skill_overlap()
        assert len(result) == 1
        assert result[0]["agent_count"] == 2

    def test_detect_skill_overlap_no_overlap(self) -> None:
        self.engine.add_record(
            name="agent-1",
            domain=SpecializationDomain.SECURITY,
            proficiency=ProficiencyLevel.NOVICE,
            service="svc",
        )
        result = self.engine.detect_skill_overlap()
        assert len(result) == 0

    def test_recommend_agent_assignments(self) -> None:
        self.engine.add_record(
            name="agent-1",
            domain=SpecializationDomain.SECURITY,
            proficiency=ProficiencyLevel.NOVICE,
            success_rate=0.4,
            service="svc",
        )
        result = self.engine.recommend_agent_assignments()
        # Should find uncovered domains (security has no expert)
        assert len(result) >= 1

    def test_recommend_agent_assignments_critical(self) -> None:
        # Only add to one domain, others are completely uncovered
        self.engine.add_record(
            name="agent-1",
            domain=SpecializationDomain.SECURITY,
            proficiency=ProficiencyLevel.EXPERT,
            service="svc",
        )
        result = self.engine.recommend_agent_assignments()
        critical = [r for r in result if r["priority"] == "critical"]
        # 4 uncovered domains
        assert len(critical) == 4

    def test_analyze_distribution(self) -> None:
        self.engine.add_record(name="r1", domain=SpecializationDomain.COST, score=70.0)
        result = self.engine.analyze_distribution()
        assert "cost" in result

    def test_identify_gaps(self) -> None:
        self.engine.add_record(name="low", score=10.0, service="svc")
        assert len(self.engine.identify_gaps()) == 1

    def test_rank_by_score(self) -> None:
        self.engine.add_record(name="r1", service="a", score=20.0)
        self.engine.add_record(name="r2", service="b", score=80.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "a"

    def test_process_found(self) -> None:
        self.engine.add_record(name="k1", score=60.0)
        assert self.engine.process("k1")["status"] == "processed"

    def test_process_not_found(self) -> None:
        assert self.engine.process("nope")["status"] == "not_found"

    def test_generate_report(self) -> None:
        self.engine.add_record(name="r1", score=30.0, service="svc")
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_clear_data(self) -> None:
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self) -> None:
        self.engine.add_record(name="r1", service="svc", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1


# ============================================================
# KnowledgeGraphEngine Tests
# ============================================================


class TestKnowledgeGraphEnums:
    def test_entity_type_values(self) -> None:
        assert EntityType.SERVICE == "service"
        assert EntityType.INFRASTRUCTURE == "infrastructure"
        assert EntityType.INCIDENT == "incident"
        assert EntityType.RUNBOOK == "runbook"
        assert EntityType.PERSON == "person"

    def test_relationship_type_values(self) -> None:
        assert RelationshipType.DEPENDS_ON == "depends_on"
        assert RelationshipType.CAUSES == "causes"
        assert RelationshipType.RESOLVES == "resolves"
        assert RelationshipType.OWNS == "owns"
        assert RelationshipType.MONITORS == "monitors"

    def test_graph_health_values(self) -> None:
        assert GraphHealth.CONNECTED == "connected"
        assert GraphHealth.FRAGMENTED == "fragmented"
        assert GraphHealth.STALE == "stale"


class TestKnowledgeGraphEngine:
    def setup_method(self) -> None:
        self.engine = KnowledgeGraphEngine(max_records=100, threshold=50.0)

    def test_init(self) -> None:
        assert self.engine._max_records == 100

    def test_add_record(self) -> None:
        r = self.engine.add_record(name="node1", score=80.0, service="svc-a")
        assert r.name == "node1"

    def test_add_record_with_enums(self) -> None:
        r = self.engine.add_record(
            name="n1",
            entity_type=EntityType.INCIDENT,
            relationship=RelationshipType.CAUSES,
            health=GraphHealth.STALE,
        )
        assert r.entity_type == EntityType.INCIDENT
        assert r.relationship == RelationshipType.CAUSES
        assert r.health == GraphHealth.STALE

    def test_ring_buffer_eviction(self) -> None:
        for i in range(150):
            self.engine.add_record(name=f"r{i}")
        assert len(self.engine._records) == 100

    def test_get_record(self) -> None:
        r = self.engine.add_record(name="find")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        assert self.engine.get_record("nope") is None

    def test_list_records_filter_entity_type(self) -> None:
        self.engine.add_record(name="a", entity_type=EntityType.SERVICE)
        self.engine.add_record(name="b", entity_type=EntityType.RUNBOOK)
        result = self.engine.list_records(entity_type=EntityType.RUNBOOK)
        assert len(result) == 1

    def test_list_records_filter_health(self) -> None:
        self.engine.add_record(name="a", health=GraphHealth.CONNECTED)
        self.engine.add_record(name="b", health=GraphHealth.STALE)
        result = self.engine.list_records(health=GraphHealth.STALE)
        assert len(result) == 1

    def test_add_analysis(self) -> None:
        a = self.engine.add_analysis(name="a1", analysis_score=70.0)
        assert a.analysis_score == 70.0

    def test_identify_knowledge_islands(self) -> None:
        self.engine.add_record(name="isolated", edge_count=0, service="svc-a")
        self.engine.add_record(name="connected", edge_count=5, service="svc-a")
        result = self.engine.identify_knowledge_islands()
        assert len(result) == 1
        assert result[0]["isolation"] == "complete"

    def test_identify_knowledge_islands_near(self) -> None:
        self.engine.add_record(name="near", edge_count=1, service="svc")
        result = self.engine.identify_knowledge_islands()
        assert len(result) == 1
        assert result[0]["isolation"] == "near"

    def test_compute_graph_connectivity_empty(self) -> None:
        result = self.engine.compute_graph_connectivity()
        assert result["total_entities"] == 0

    def test_compute_graph_connectivity(self) -> None:
        self.engine.add_record(name="n1", edge_count=3, health=GraphHealth.CONNECTED, service="svc")
        self.engine.add_record(name="n2", edge_count=2, health=GraphHealth.CONNECTED, service="svc")
        result = self.engine.compute_graph_connectivity()
        assert result["total_entities"] == 2
        assert result["total_edges"] == 5
        assert result["connectivity_score"] == 100.0

    def test_recommend_knowledge_gaps_stale(self) -> None:
        self.engine.add_record(name="n1", health=GraphHealth.STALE, service="svc-a")
        result = self.engine.recommend_knowledge_gaps()
        stale = [r for r in result if r["issue"] == "stale_knowledge"]
        assert len(stale) >= 1

    def test_recommend_knowledge_gaps_missing_types(self) -> None:
        self.engine.add_record(name="n1", entity_type=EntityType.SERVICE, service="svc")
        result = self.engine.recommend_knowledge_gaps()
        missing = [r for r in result if r["issue"] == "missing_entity_type"]
        assert len(missing) == 4  # 5 types - 1 present

    def test_analyze_distribution(self) -> None:
        self.engine.add_record(name="r1", entity_type=EntityType.SERVICE, score=70.0)
        result = self.engine.analyze_distribution()
        assert "service" in result

    def test_identify_gaps(self) -> None:
        self.engine.add_record(name="low", score=10.0, service="svc")
        assert len(self.engine.identify_gaps()) == 1

    def test_rank_by_score(self) -> None:
        self.engine.add_record(name="r1", service="a", score=20.0)
        self.engine.add_record(name="r2", service="b", score=80.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "a"

    def test_process_found(self) -> None:
        self.engine.add_record(name="k1", score=60.0)
        assert self.engine.process("k1")["status"] == "processed"

    def test_process_not_found(self) -> None:
        assert self.engine.process("nope")["status"] == "not_found"

    def test_generate_report(self) -> None:
        self.engine.add_record(name="r1", score=30.0, service="svc")
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_generate_report_healthy(self) -> None:
        self.engine.add_record(name="r1", score=90.0, service="svc")
        report = self.engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self) -> None:
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self) -> None:
        self.engine.add_record(name="r1", service="svc", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1


# ============================================================
# PredictiveIncidentEngine Tests
# ============================================================


class TestPredictiveIncidentEnums:
    def test_prediction_horizon_values(self) -> None:
        assert PredictionHorizon.MINUTES == "minutes"
        assert PredictionHorizon.HOURS == "hours"
        assert PredictionHorizon.DAYS == "days"

    def test_indicator_type_values(self) -> None:
        assert IndicatorType.METRIC_ANOMALY == "metric_anomaly"
        assert IndicatorType.LOG_PATTERN == "log_pattern"
        assert IndicatorType.DEPLOYMENT_CHANGE == "deployment_change"
        assert IndicatorType.CAPACITY_TREND == "capacity_trend"

    def test_prediction_confidence_values(self) -> None:
        assert PredictionConfidence.HIGH == "high"
        assert PredictionConfidence.MEDIUM == "medium"
        assert PredictionConfidence.LOW == "low"


class TestPredictiveIncidentEngine:
    def setup_method(self) -> None:
        self.engine = PredictiveIncidentEngine(max_records=100, threshold=50.0)

    def test_init(self) -> None:
        assert self.engine._max_records == 100

    def test_add_record(self) -> None:
        r = self.engine.add_record(name="pred1", score=75.0, service="svc-a")
        assert r.name == "pred1"

    def test_add_record_with_enums(self) -> None:
        r = self.engine.add_record(
            name="p1",
            horizon=PredictionHorizon.MINUTES,
            indicator=IndicatorType.LOG_PATTERN,
            confidence=PredictionConfidence.HIGH,
        )
        assert r.horizon == PredictionHorizon.MINUTES
        assert r.indicator == IndicatorType.LOG_PATTERN
        assert r.confidence == PredictionConfidence.HIGH

    def test_ring_buffer_eviction(self) -> None:
        for i in range(150):
            self.engine.add_record(name=f"r{i}")
        assert len(self.engine._records) == 100

    def test_get_record(self) -> None:
        r = self.engine.add_record(name="find")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        assert self.engine.get_record("nope") is None

    def test_list_records_filter_horizon(self) -> None:
        self.engine.add_record(name="a", horizon=PredictionHorizon.MINUTES)
        self.engine.add_record(name="b", horizon=PredictionHorizon.DAYS)
        result = self.engine.list_records(horizon=PredictionHorizon.MINUTES)
        assert len(result) == 1

    def test_list_records_filter_confidence(self) -> None:
        self.engine.add_record(name="a", confidence=PredictionConfidence.HIGH)
        self.engine.add_record(name="b", confidence=PredictionConfidence.LOW)
        result = self.engine.list_records(confidence=PredictionConfidence.HIGH)
        assert len(result) == 1

    def test_add_analysis(self) -> None:
        a = self.engine.add_analysis(name="a1", analysis_score=85.0)
        assert a.analysis_score == 85.0

    def test_generate_incident_predictions(self) -> None:
        self.engine.add_record(
            name="p1",
            service="svc-a",
            confidence=PredictionConfidence.HIGH,
            score=80.0,
            horizon=PredictionHorizon.MINUTES,
        )
        self.engine.add_record(
            name="p2",
            service="svc-a",
            confidence=PredictionConfidence.HIGH,
            score=70.0,
            horizon=PredictionHorizon.HOURS,
        )
        result = self.engine.generate_incident_predictions()
        assert len(result) == 1
        assert result[0]["high_confidence_indicators"] == 2

    def test_generate_incident_predictions_risk_levels(self) -> None:
        for i in range(5):
            self.engine.add_record(
                name=f"p{i}", service="svc-a", confidence=PredictionConfidence.HIGH, score=90.0
            )
        result = self.engine.generate_incident_predictions()
        assert result[0]["risk_level"] == "critical"

    def test_evaluate_prediction_accuracy(self) -> None:
        self.engine.add_record(
            name="p1",
            horizon=PredictionHorizon.HOURS,
            indicator=IndicatorType.METRIC_ANOMALY,
            prediction_accuracy=85.0,
            service="svc",
        )
        result = self.engine.evaluate_prediction_accuracy()
        assert len(result) >= 1
        assert any(r["dimension"] == "horizon" for r in result)
        assert any(r["dimension"] == "indicator" for r in result)

    def test_evaluate_prediction_accuracy_grades(self) -> None:
        self.engine.add_record(
            name="p1", horizon=PredictionHorizon.HOURS, prediction_accuracy=95.0, service="svc"
        )
        result = self.engine.evaluate_prediction_accuracy()
        horizon_results = [r for r in result if r["dimension"] == "horizon"]
        assert horizon_results[0]["grade"] == "excellent"

    def test_identify_leading_indicators(self) -> None:
        self.engine.add_record(
            name="p1",
            indicator=IndicatorType.METRIC_ANOMALY,
            confidence=PredictionConfidence.HIGH,
            prediction_accuracy=90.0,
            service="svc-a",
        )
        self.engine.add_record(
            name="p2",
            indicator=IndicatorType.METRIC_ANOMALY,
            confidence=PredictionConfidence.HIGH,
            prediction_accuracy=85.0,
            service="svc-b",
        )
        result = self.engine.identify_leading_indicators()
        assert len(result) >= 1
        assert result[0]["indicator"] == "metric_anomaly"
        assert result[0]["high_confidence_pct"] == 100.0

    def test_identify_leading_indicators_mixed(self) -> None:
        self.engine.add_record(
            name="p1",
            indicator=IndicatorType.LOG_PATTERN,
            confidence=PredictionConfidence.HIGH,
            prediction_accuracy=80.0,
            service="svc",
        )
        self.engine.add_record(
            name="p2",
            indicator=IndicatorType.LOG_PATTERN,
            confidence=PredictionConfidence.LOW,
            prediction_accuracy=40.0,
            service="svc",
        )
        result = self.engine.identify_leading_indicators()
        lp = [r for r in result if r["indicator"] == "log_pattern"]
        assert lp[0]["high_confidence_pct"] == 50.0

    def test_analyze_distribution(self) -> None:
        self.engine.add_record(name="r1", horizon=PredictionHorizon.DAYS, score=70.0)
        result = self.engine.analyze_distribution()
        assert "days" in result

    def test_identify_gaps(self) -> None:
        self.engine.add_record(name="low", score=10.0, service="svc")
        assert len(self.engine.identify_gaps()) == 1

    def test_rank_by_score(self) -> None:
        self.engine.add_record(name="r1", service="a", score=20.0)
        self.engine.add_record(name="r2", service="b", score=80.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "a"

    def test_process_found(self) -> None:
        self.engine.add_record(name="k1", score=60.0)
        assert self.engine.process("k1")["status"] == "processed"

    def test_process_not_found(self) -> None:
        assert self.engine.process("nope")["status"] == "not_found"

    def test_generate_report(self) -> None:
        self.engine.add_record(name="r1", score=30.0, service="svc")
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_generate_report_healthy(self) -> None:
        self.engine.add_record(name="r1", score=90.0, service="svc")
        report = self.engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self) -> None:
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self) -> None:
        self.engine.add_record(name="r1", service="svc", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_services"] == 1
