"""Read-only view over threshold-category engines fields.

Decomposed from the 1,820-LOC sub/engines.py monolith (RFC #241 PR-6 / #254).
Source of truth is the underlying EnginesConfig (which itself delegates to
FlatSettings for any field deleted from the model). This view exists so that
category-specific lookup tables stay maintainable as the monolith shrinks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shieldops.config.sub.engines import EnginesConfig

_FIELDS: frozenset[str] = frozenset(
    {
        "prediction_confidence_threshold",
        "slo_burn_rate_threshold",
        "health_degraded_threshold",
        "health_unhealthy_threshold",
        "cost_anomaly_z_threshold",
        "dependency_cascade_threshold",
        "error_budget_warning_threshold",
        "error_budget_critical_threshold",
        "readiness_review_passing_threshold",
        "change_risk_high_threshold",
        "change_risk_critical_threshold",
        "synthetic_monitor_failure_threshold",
        "workload_fingerprint_drift_threshold",
        "cost_forecast_alert_threshold",
        "capacity_trends_exhaustion_threshold",
        "alert_noise_threshold",
        "oncall_fatigue_burnout_threshold",
        "latency_profiler_regression_threshold",
        "budget_manager_warning_threshold",
        "incident_dedup_similarity_threshold",
        "trace_analyzer_bottleneck_threshold",
        "api_security_alert_threshold",
        "team_performance_burnout_threshold",
        "change_intelligence_risk_threshold",
        "network_flow_anomaly_threshold",
        "escalation_analyzer_false_alarm_threshold",
        "right_sizer_underutil_threshold",
        "alert_routing_reroute_threshold",
        "resilience_scorer_minimum_score_threshold",
        "spend_allocation_min_allocation_threshold",
        "secrets_detector_high_severity_threshold",
        "dependency_freshness_stale_version_threshold",
        "service_health_agg_health_threshold",
        "alert_fatigue_threshold",
        "dependency_update_planner_max_risk_threshold",
        "outage_predictor_composite_threshold",
        "policy_violation_tracker_repeat_threshold",
        "deploy_health_scorer_failing_threshold",
        "runbook_gap_analyzer_critical_incident_threshold",
        "latency_budget_tracker_chronic_violation_threshold",
        "handoff_tracker_quality_threshold",
        "unit_economics_high_cost_threshold",
        "posture_trend_regression_threshold",
        "access_anomaly_threat_threshold",
        "response_advisor_confidence_threshold",
        "escalation_effectiveness_false_rate_threshold",
        "alert_tuning_feedback_precision_threshold",
        "cardinality_manager_max_cardinality_threshold",
        "permission_drift_unused_days_threshold",
        "flag_lifecycle_stale_days_threshold",
        "rate_limit_policy_violation_threshold",
        "queue_depth_forecast_overflow_threshold",
        "dependency_risk_critical_threshold",
        "incident_cost_high_threshold",
        "cognitive_load_critical_threshold",
        "llm_cost_tracker_high_cost_threshold",
        "observability_cost_high_cost_threshold",
        "risk_aggregator_critical_threshold",
        "dynamic_risk_scorer_high_threshold",
        "platform_cost_min_savings_threshold",
        "risk_predictor_max_risk_threshold",
        "vuln_prioritizer_critical_cvss_threshold",
        "incident_mitigation_effectiveness_threshold",
        "metric_anomaly_cls_confidence_threshold",
        "change_rollout_risk_tolerance_threshold",
        "security_signal_corr_correlation_confidence_threshold",
        "audit_workflow_opt_cycle_time_threshold",
        "perf_baseline_tracker_deviation_threshold",
        "compliance_control_map_coverage_gap_threshold",
        "stakeholder_impact_tracker_impact_score_threshold",
        "service_health_predictor_prediction_confidence_threshold",
        "metric_collection_optimizer_collection_efficiency_threshold",
        "cost_forecast_precision_precision_accuracy_threshold",
        "change_coordination_planner_coordination_risk_threshold",
        "slo_cross_correlation_correlation_strength_threshold",
        "team_capacity_planner_capacity_utilization_threshold",
        "security_compliance_scorer_compliance_gap_threshold",
        "knowledge_impact_analyzer_impact_relevance_threshold",
        "audit_scope_optimizer_scope_efficiency_threshold",
        "data_quality_scorer_quality_score_threshold",
        "regulatory_impact_tracker_impact_severity_threshold",
        "mitre_attack_mapper_coverage_gap_threshold",
        "threat_intel_aggregator_ioc_confidence_threshold",
        "soar_playbook_engine_effectiveness_threshold",
        "attack_chain_reconstructor_completeness_threshold",
        "soc_metrics_dashboard_metric_target_threshold",
        "adversary_simulation_engine_detection_threshold",
        "risk_quantification_engine_risk_tolerance_threshold",
        "alert_triage_scorer_triage_score_threshold",
        "compliance_evidence_automator_v2_completeness_threshold",
        "incident_containment_tracker_effectiveness_threshold",
        "incident_forensics_tracker_integrity_threshold",
        "deception_tech_manager_detection_threshold",
        "alert_enrichment_engine_enrichment_quality_threshold",
        "detection_rule_effectiveness_rule_effectiveness_threshold",
        "analyst_workload_balancer_utilization_threshold",
        "alert_escalation_intelligence_escalation_effectiveness_threshold",
        "ioc_sweep_engine_match_score_threshold",
        "security_alert_dedup_engine_dedup_effectiveness_threshold",
        "hunt_hypothesis_generator_hypothesis_quality_threshold",
        "behavioral_baseline_engine_deviation_threshold",
        "hunt_effectiveness_tracker_hunt_effectiveness_threshold",
        "threat_campaign_tracker_threat_score_threshold",
        "anomalous_access_detector_anomaly_score_threshold",
        "network_flow_analyzer_suspicion_score_threshold",
        "evidence_integrity_verifier_integrity_confidence_threshold",
        "forensic_timeline_builder_accuracy_threshold",
        "honeypot_interaction_analyzer_threat_score_threshold",
        "attacker_profile_builder_profile_confidence_threshold",
        "zero_day_detection_engine_detection_confidence_threshold",
        "supply_chain_attack_detector_supply_chain_risk_threshold",
        "apt_detection_engine_apt_threat_threshold",
        "ransomware_defense_engine_readiness_threshold",
        "dlp_scorer_protection_threshold",
        "insider_threat_ai_scorer_insider_threat_threshold",
        "cloud_security_posture_scorer_posture_threshold",
        "container_runtime_security_runtime_security_threshold",
        "identity_threat_detection_identity_threat_threshold",
        "threat_intel_correlation_correlation_confidence_threshold",
        "security_automation_coverage_automation_coverage_threshold",
        "purple_team_exercise_tracker_exercise_effectiveness_threshold",
        "fair_risk_modeler_risk_estimate_threshold",
        "continuous_compliance_monitor_compliance_drift_threshold",
        "regulatory_change_impact_regulatory_impact_threshold",
        "risk_prediction_engine_forecast_confidence_threshold",
        "control_effectiveness_scorer_control_effectiveness_threshold",
        "vendor_risk_intelligence_vendor_risk_threshold",
        "compliance_gap_prioritizer_gap_priority_threshold",
        "audit_readiness_scorer_readiness_threshold",
        "risk_treatment_tracker_residual_risk_threshold",
        "compliance_automation_scorer_automation_threshold",
        "data_privacy_impact_assessor_privacy_impact_threshold",
        "security_maturity_model_maturity_threshold",
    }
)


class EnginesThresholdsView:
    """Read-only projection over engines fields in this category."""

    __slots__ = ("_engines",)

    def __init__(self, engines: EnginesConfig) -> None:
        self._engines = engines

    def __getattr__(self, name: str) -> Any:
        if name in _FIELDS:
            return getattr(self._engines, name)
        raise AttributeError(f"EnginesThresholdsView has no attribute {name!r}")

    @classmethod
    def field_names(cls) -> frozenset[str]:
        return _FIELDS
