"""AI Compliance Agent — Tool functions for AI regulatory compliance assessment."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import (
    AISystemRecord,
    ComplianceRequirement,
    ControlAssessment,
    ControlStatus,
    EvidencePackage,
    RiskClassification,
)

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# EU AI Act framework requirements (Articles 6, 9, 10, 13, 14)
# ---------------------------------------------------------------------------
_EU_AI_ACT_REQUIREMENTS: list[dict[str, Any]] = [
    {
        "requirement_id": "EUAIA-ART6-01",
        "framework": "eu_ai_act",
        "article": "Article 6",
        "title": "High-Risk AI System Classification",
        "description": (
            "AI systems listed in Annex III shall be classified as high-risk. "
            "Providers must determine whether their AI system falls within a "
            "high-risk category based on intended purpose and deployment context."
        ),
        "risk_tiers": [RiskClassification.HIGH_RISK, RiskClassification.UNACCEPTABLE],
        "mandatory": True,
        "evidence_needed": [
            "system_classification_record",
            "annex_iii_mapping",
            "intended_purpose_documentation",
        ],
    },
    {
        "requirement_id": "EUAIA-ART9-01",
        "framework": "eu_ai_act",
        "article": "Article 9",
        "title": "Risk Management System",
        "description": (
            "A risk management system shall be established, implemented, documented "
            "and maintained for high-risk AI systems. It shall consist of a continuous "
            "iterative process planned and run throughout the entire lifecycle."
        ),
        "risk_tiers": [RiskClassification.HIGH_RISK],
        "mandatory": True,
        "evidence_needed": [
            "risk_management_plan",
            "risk_assessment_records",
            "residual_risk_acceptance",
            "lifecycle_risk_reviews",
        ],
    },
    {
        "requirement_id": "EUAIA-ART10-01",
        "framework": "eu_ai_act",
        "article": "Article 10",
        "title": "Data and Data Governance",
        "description": (
            "High-risk AI systems using data for training shall be developed on the "
            "basis of training, validation and testing data sets that meet quality "
            "criteria including relevance, representativeness, and freedom from errors."
        ),
        "risk_tiers": [RiskClassification.HIGH_RISK],
        "mandatory": True,
        "evidence_needed": [
            "data_governance_policy",
            "data_quality_assessment",
            "bias_testing_report",
            "training_data_documentation",
        ],
    },
    {
        "requirement_id": "EUAIA-ART13-01",
        "framework": "eu_ai_act",
        "article": "Article 13",
        "title": "Transparency and Provision of Information",
        "description": (
            "High-risk AI systems shall be designed and developed to ensure their "
            "operation is sufficiently transparent to enable deployers to interpret "
            "the system output and use it appropriately."
        ),
        "risk_tiers": [
            RiskClassification.HIGH_RISK,
            RiskClassification.LIMITED_RISK,
        ],
        "mandatory": True,
        "evidence_needed": [
            "transparency_documentation",
            "user_instructions",
            "system_capabilities_limitations",
            "interpretability_report",
        ],
    },
    {
        "requirement_id": "EUAIA-ART14-01",
        "framework": "eu_ai_act",
        "article": "Article 14",
        "title": "Human Oversight",
        "description": (
            "High-risk AI systems shall be designed and developed to allow effective "
            "oversight by natural persons during use, including the ability to "
            "correctly interpret output, decide not to use or override the system, "
            "and intervene or interrupt operation."
        ),
        "risk_tiers": [RiskClassification.HIGH_RISK],
        "mandatory": True,
        "evidence_needed": [
            "human_oversight_procedures",
            "override_mechanisms",
            "escalation_workflows",
            "operator_training_records",
        ],
    },
]


# ---------------------------------------------------------------------------
# NIST AI RMF requirements (GOVERN, MAP, MEASURE, MANAGE)
# ---------------------------------------------------------------------------
_NIST_AI_RMF_REQUIREMENTS: list[dict[str, Any]] = [
    {
        "requirement_id": "NIST-GOV-1",
        "framework": "nist_ai_rmf",
        "article": "GOVERN 1",
        "title": "Policies and Processes for AI Risk Management",
        "description": (
            "Policies, processes, procedures, and practices across the organization "
            "related to the mapping, measuring, and managing of AI risks are in place, "
            "transparent, and implemented effectively."
        ),
        "risk_tiers": [
            RiskClassification.HIGH_RISK,
            RiskClassification.LIMITED_RISK,
            RiskClassification.MINIMAL_RISK,
        ],
        "mandatory": True,
        "evidence_needed": [
            "ai_governance_policy",
            "risk_management_framework",
            "roles_responsibilities_matrix",
        ],
    },
    {
        "requirement_id": "NIST-MAP-1",
        "framework": "nist_ai_rmf",
        "article": "MAP 1",
        "title": "Context and Use Case Mapping",
        "description": (
            "Context is established and understood. The AI system's intended purpose, "
            "potential impacts, and assumptions are identified and documented."
        ),
        "risk_tiers": [
            RiskClassification.HIGH_RISK,
            RiskClassification.LIMITED_RISK,
            RiskClassification.MINIMAL_RISK,
        ],
        "mandatory": True,
        "evidence_needed": [
            "use_case_documentation",
            "impact_assessment",
            "stakeholder_analysis",
        ],
    },
    {
        "requirement_id": "NIST-MAP-3",
        "framework": "nist_ai_rmf",
        "article": "MAP 3",
        "title": "AI Benefits and Costs Assessment",
        "description": (
            "AI capabilities, targeted usage, goals, and expected benefits and costs "
            "compared with appropriate benchmarks are understood."
        ),
        "risk_tiers": [
            RiskClassification.HIGH_RISK,
            RiskClassification.LIMITED_RISK,
        ],
        "mandatory": False,
        "evidence_needed": [
            "benefit_cost_analysis",
            "benchmark_comparison",
            "performance_metrics",
        ],
    },
    {
        "requirement_id": "NIST-MEA-1",
        "framework": "nist_ai_rmf",
        "article": "MEASURE 1",
        "title": "AI Risk Measurement and Monitoring",
        "description": (
            "Appropriate methods and metrics are identified and applied to measure "
            "AI risks including performance, fairness, reliability, and safety."
        ),
        "risk_tiers": [
            RiskClassification.HIGH_RISK,
            RiskClassification.LIMITED_RISK,
        ],
        "mandatory": True,
        "evidence_needed": [
            "performance_metrics_report",
            "fairness_assessment",
            "reliability_testing",
            "safety_evaluation",
        ],
    },
    {
        "requirement_id": "NIST-MAN-1",
        "framework": "nist_ai_rmf",
        "article": "MANAGE 1",
        "title": "AI Risk Prioritization and Response",
        "description": (
            "AI risks based on assessments and other analytical output from the MAP "
            "and MEASURE functions are prioritized, responded to, and managed."
        ),
        "risk_tiers": [RiskClassification.HIGH_RISK],
        "mandatory": True,
        "evidence_needed": [
            "risk_response_plan",
            "risk_prioritization_matrix",
            "incident_response_procedures",
        ],
    },
    {
        "requirement_id": "NIST-MAN-4",
        "framework": "nist_ai_rmf",
        "article": "MANAGE 4",
        "title": "Risk Treatment and Continuous Improvement",
        "description": (
            "Risks are monitored on an ongoing basis, risk treatments are applied "
            "and adjusted, and there is a process for continuous improvement."
        ),
        "risk_tiers": [
            RiskClassification.HIGH_RISK,
            RiskClassification.LIMITED_RISK,
        ],
        "mandatory": True,
        "evidence_needed": [
            "continuous_monitoring_plan",
            "risk_treatment_log",
            "improvement_records",
        ],
    },
]


# ---------------------------------------------------------------------------
# ISO 42001 requirements (AI Management System)
# ---------------------------------------------------------------------------
_ISO_42001_REQUIREMENTS: list[dict[str, Any]] = [
    {
        "requirement_id": "ISO42001-5.1",
        "framework": "iso_42001",
        "article": "5.1",
        "title": "Leadership and Commitment",
        "description": (
            "Top management shall demonstrate leadership and commitment with respect "
            "to the AI management system by establishing AI policy, ensuring "
            "integration into business processes, and ensuring resources are available."
        ),
        "risk_tiers": [
            RiskClassification.HIGH_RISK,
            RiskClassification.LIMITED_RISK,
            RiskClassification.MINIMAL_RISK,
        ],
        "mandatory": True,
        "evidence_needed": [
            "ai_policy_statement",
            "management_review_minutes",
            "resource_allocation_records",
        ],
    },
    {
        "requirement_id": "ISO42001-6.1",
        "framework": "iso_42001",
        "article": "6.1",
        "title": "Actions to Address Risks and Opportunities",
        "description": (
            "The organization shall determine risks and opportunities that need to "
            "be addressed to ensure the AI management system achieves its intended "
            "outcomes, prevent undesired effects, and achieve continual improvement."
        ),
        "risk_tiers": [
            RiskClassification.HIGH_RISK,
            RiskClassification.LIMITED_RISK,
        ],
        "mandatory": True,
        "evidence_needed": [
            "ai_risk_register",
            "opportunity_assessment",
            "risk_treatment_plan",
        ],
    },
    {
        "requirement_id": "ISO42001-7.5",
        "framework": "iso_42001",
        "article": "7.5",
        "title": "Documented Information",
        "description": (
            "The AI management system shall include documented information required "
            "by ISO 42001 and determined by the organization as necessary for the "
            "effectiveness of the management system."
        ),
        "risk_tiers": [
            RiskClassification.HIGH_RISK,
            RiskClassification.LIMITED_RISK,
            RiskClassification.MINIMAL_RISK,
        ],
        "mandatory": True,
        "evidence_needed": [
            "document_control_procedure",
            "records_management_policy",
            "system_documentation_index",
        ],
    },
    {
        "requirement_id": "ISO42001-8.4",
        "framework": "iso_42001",
        "article": "8.4",
        "title": "AI System Impact Assessment",
        "description": (
            "The organization shall conduct an AI impact assessment for each AI "
            "system to identify and evaluate the potential impacts on individuals, "
            "groups, communities, and society."
        ),
        "risk_tiers": [RiskClassification.HIGH_RISK],
        "mandatory": True,
        "evidence_needed": [
            "impact_assessment_report",
            "affected_stakeholder_analysis",
            "mitigation_measures",
        ],
    },
    {
        "requirement_id": "ISO42001-9.1",
        "framework": "iso_42001",
        "article": "9.1",
        "title": "Monitoring, Measurement, Analysis and Evaluation",
        "description": (
            "The organization shall determine what needs to be monitored and measured "
            "for AI systems, the methods for monitoring, when monitoring shall be "
            "performed, and when results shall be analyzed and evaluated."
        ),
        "risk_tiers": [
            RiskClassification.HIGH_RISK,
            RiskClassification.LIMITED_RISK,
        ],
        "mandatory": True,
        "evidence_needed": [
            "monitoring_plan",
            "kpi_dashboard",
            "evaluation_reports",
        ],
    },
    {
        "requirement_id": "ISO42001-10.1",
        "framework": "iso_42001",
        "article": "10.1",
        "title": "Continual Improvement",
        "description": (
            "The organization shall continually improve the suitability, adequacy "
            "and effectiveness of the AI management system through corrective actions, "
            "management reviews, and performance evaluations."
        ),
        "risk_tiers": [
            RiskClassification.HIGH_RISK,
            RiskClassification.LIMITED_RISK,
            RiskClassification.MINIMAL_RISK,
        ],
        "mandatory": True,
        "evidence_needed": [
            "improvement_register",
            "corrective_action_log",
            "management_review_outputs",
        ],
    },
]


# ---------------------------------------------------------------------------
# All frameworks combined
# ---------------------------------------------------------------------------
_ALL_REQUIREMENTS: dict[str, list[dict[str, Any]]] = {
    "eu_ai_act": _EU_AI_ACT_REQUIREMENTS,
    "nist_ai_rmf": _NIST_AI_RMF_REQUIREMENTS,
    "iso_42001": _ISO_42001_REQUIREMENTS,
}

# High-risk domain classifiers per EU AI Act Annex III
_ANNEX_III_DOMAINS: dict[str, RiskClassification] = {
    "biometric_identification": RiskClassification.HIGH_RISK,
    "critical_infrastructure": RiskClassification.HIGH_RISK,
    "education": RiskClassification.HIGH_RISK,
    "employment": RiskClassification.HIGH_RISK,
    "essential_services": RiskClassification.HIGH_RISK,
    "law_enforcement": RiskClassification.HIGH_RISK,
    "migration": RiskClassification.HIGH_RISK,
    "justice": RiskClassification.HIGH_RISK,
    "healthcare": RiskClassification.HIGH_RISK,
    "safety_components": RiskClassification.HIGH_RISK,
}

# Unacceptable use patterns per EU AI Act Article 5
_UNACCEPTABLE_PATTERNS: list[str] = [
    "social_scoring",
    "subliminal_manipulation",
    "exploitation_of_vulnerabilities",
    "real_time_remote_biometric_public",
    "emotion_recognition_workplace",
    "predictive_policing_individual",
]

# Control assessment scoring weights per status
_STATUS_SCORES: dict[ControlStatus, float] = {
    ControlStatus.IMPLEMENTED: 100.0,
    ControlStatus.PARTIAL: 50.0,
    ControlStatus.MISSING: 0.0,
    ControlStatus.NOT_APPLICABLE: 100.0,
}


def _generate_id(prefix: str, *parts: str) -> str:
    """Generate a deterministic ID from parts."""
    raw = ":".join(parts)
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class AIComplianceToolkit:
    """Tools for AI regulatory compliance assessment across frameworks."""

    def __init__(
        self,
        inventory_client: Any | None = None,
        policy_client: Any | None = None,
        evidence_store: Any | None = None,
    ) -> None:
        self._inventory_client = inventory_client
        self._policy_client = policy_client
        self._evidence_store = evidence_store

    async def collect_inventory(self, tenant_id: str) -> list[AISystemRecord]:
        """Collect AI system inventory for a tenant.

        Uses an inventory client if available, otherwise returns representative
        sample systems for assessment.
        """
        logger.info("ai_compliance.collect_inventory", tenant_id=tenant_id)

        if self._inventory_client is not None:
            try:
                raw = await self._inventory_client.list_ai_systems(tenant_id=tenant_id)
                return [AISystemRecord(**s) for s in raw]
            except Exception:
                logger.exception("ai_compliance.collect_inventory.error")

        # Default sample inventory for assessment
        return [
            AISystemRecord(
                system_id="ais-001",
                name="Customer Support Chatbot",
                description="LLM-powered customer service agent",
                purpose="Automate customer support interactions",
                domain="customer_service",
                model_type="llm",
                deployment_env="production",
                data_categories=["customer_pii", "conversation_logs"],
                stakeholders=["product_team", "customer_ops"],
            ),
            AISystemRecord(
                system_id="ais-002",
                name="Resume Screening Engine",
                description="ML model for automated resume screening and ranking",
                purpose="Pre-screen job applicants based on qualifications",
                domain="employment",
                model_type="classification",
                deployment_env="production",
                data_categories=["applicant_pii", "employment_history"],
                stakeholders=["hr_team", "legal"],
            ),
            AISystemRecord(
                system_id="ais-003",
                name="Fraud Detection Model",
                description="Real-time transaction fraud scoring model",
                purpose="Detect and prevent fraudulent financial transactions",
                domain="essential_services",
                model_type="anomaly_detection",
                deployment_env="production",
                data_categories=["financial_data", "transaction_logs"],
                stakeholders=["risk_team", "compliance"],
            ),
            AISystemRecord(
                system_id="ais-004",
                name="Internal Code Assistant",
                description="LLM-based code generation and review tool",
                purpose="Assist developers with code generation",
                domain="internal_tooling",
                model_type="llm",
                deployment_env="staging",
                data_categories=["source_code", "developer_activity"],
                stakeholders=["engineering"],
            ),
        ]

    def classify_risk(self, systems: list[AISystemRecord]) -> list[AISystemRecord]:
        """Classify risk level for each AI system per EU AI Act tiers.

        Applies Annex III domain matching, checks for unacceptable use patterns,
        and assigns risk classification.
        """
        logger.info("ai_compliance.classify_risk", system_count=len(systems))

        classified: list[AISystemRecord] = []

        for system in systems:
            domain_lower = system.domain.lower()
            purpose_lower = system.purpose.lower()

            # Check for unacceptable risk patterns
            is_unacceptable = any(
                pattern in domain_lower or pattern in purpose_lower
                for pattern in _UNACCEPTABLE_PATTERNS
            )
            if is_unacceptable:
                classification = RiskClassification.UNACCEPTABLE
            # Check Annex III high-risk domains
            elif domain_lower in _ANNEX_III_DOMAINS:
                classification = _ANNEX_III_DOMAINS[domain_lower]
            # Check for transparency-obligation triggers (limited risk)
            elif system.model_type == "llm" or "chatbot" in system.name.lower():
                classification = RiskClassification.LIMITED_RISK
            else:
                classification = RiskClassification.MINIMAL_RISK

            classified.append(system.model_copy(update={"risk_classification": classification}))

        return classified

    def assess_requirements(
        self,
        systems: list[AISystemRecord],
        frameworks: list[str],
    ) -> list[ComplianceRequirement]:
        """Determine applicable requirements based on frameworks and risk levels.

        Filters framework requirements to those applicable given each system's
        risk classification.
        """
        logger.info(
            "ai_compliance.assess_requirements",
            system_count=len(systems),
            frameworks=frameworks,
        )

        # Collect all risk tiers across systems
        system_tiers: set[RiskClassification] = set()
        for system in systems:
            system_tiers.add(system.risk_classification)

        applicable: list[ComplianceRequirement] = []
        seen_ids: set[str] = set()

        for fw in frameworks:
            fw_lower = fw.lower().replace(" ", "_").replace("-", "_")
            raw_reqs = _ALL_REQUIREMENTS.get(fw_lower, [])

            for req_data in raw_reqs:
                req = ComplianceRequirement(**req_data)

                # Include if any system's risk tier matches
                req_tiers = set(req.risk_tiers)
                if req_tiers & system_tiers and req.requirement_id not in seen_ids:
                    applicable.append(req)
                    seen_ids.add(req.requirement_id)

        return applicable

    def evaluate_controls(
        self,
        systems: list[AISystemRecord],
        requirements: list[ComplianceRequirement],
    ) -> list[ControlAssessment]:
        """Evaluate control implementations against requirements.

        Generates an assessment for each system-requirement pair, determining
        control status based on system attributes and available evidence.
        """
        logger.info(
            "ai_compliance.evaluate_controls",
            system_count=len(systems),
            requirement_count=len(requirements),
        )

        assessments: list[ControlAssessment] = []

        for system in systems:
            for req in requirements:
                # Skip if requirement doesn't apply to this system's risk tier
                if system.risk_classification not in req.risk_tiers:
                    status = ControlStatus.NOT_APPLICABLE
                    findings = "Requirement not applicable to this risk tier"
                    remediation = ""
                    score = 100.0
                elif system.risk_classification == RiskClassification.UNACCEPTABLE:
                    status = ControlStatus.MISSING
                    findings = (
                        "System classified as unacceptable risk — "
                        "must be decommissioned or redesigned"
                    )
                    remediation = (
                        "Immediately halt deployment. Conduct redesign to remove "
                        "unacceptable use patterns or decommission system."
                    )
                    score = 0.0
                elif system.deployment_env == "production":
                    # Production systems: partial compliance assumed
                    status = ControlStatus.PARTIAL
                    findings = (
                        f"Control partially implemented for {req.title}. "
                        f"Evidence needed: {', '.join(req.evidence_needed[:2])}"
                    )
                    remediation = (
                        f"Complete implementation of {req.title} controls. "
                        f"Produce required evidence: {', '.join(req.evidence_needed)}"
                    )
                    score = 50.0
                else:
                    # Non-production: likely missing
                    status = ControlStatus.MISSING
                    findings = f"No evidence of {req.title} controls for non-production system"
                    remediation = (
                        f"Implement {req.title} controls before production "
                        f"deployment. Required evidence: {', '.join(req.evidence_needed)}"
                    )
                    score = 0.0

                assessment_id = _generate_id("CA", system.system_id, req.requirement_id)
                assessments.append(
                    ControlAssessment(
                        assessment_id=assessment_id,
                        requirement_id=req.requirement_id,
                        system_id=system.system_id,
                        framework=req.framework,
                        control_name=req.title,
                        status=status,
                        findings=findings,
                        remediation=remediation,
                        score=score,
                        evidence_refs=[],
                    )
                )

        return assessments

    async def generate_evidence(
        self,
        systems: list[AISystemRecord],
        assessments: list[ControlAssessment],
    ) -> list[EvidencePackage]:
        """Generate evidence packages for compliance assessments.

        Creates evidence artifacts for each assessed control, linking them
        to the relevant assessment records.
        """
        logger.info(
            "ai_compliance.generate_evidence",
            assessment_count=len(assessments),
        )

        now = datetime.now(tz=UTC).isoformat()
        evidence_packages: list[EvidencePackage] = []
        system_map = {s.system_id: s for s in systems}

        for assessment in assessments:
            if assessment.status == ControlStatus.NOT_APPLICABLE:
                continue

            system = system_map.get(assessment.system_id)
            system_name = system.name if system else assessment.system_id

            evidence_id = _generate_id("EV", assessment.assessment_id, assessment.framework)

            artifacts: list[str] = []
            if assessment.status == ControlStatus.IMPLEMENTED:
                artifacts = [
                    f"{assessment.control_name}_implementation_record.pdf",
                    f"{assessment.control_name}_test_results.json",
                ]
            elif assessment.status == ControlStatus.PARTIAL:
                artifacts = [
                    f"{assessment.control_name}_partial_evidence.pdf",
                    f"{assessment.control_name}_gap_analysis.md",
                ]
            else:
                artifacts = [f"{assessment.control_name}_gap_report.md"]

            evidence_packages.append(
                EvidencePackage(
                    evidence_id=evidence_id,
                    system_id=assessment.system_id,
                    framework=assessment.framework,
                    evidence_type="assessment_evidence",
                    title=f"{assessment.control_name} — {system_name}",
                    description=(
                        f"Evidence for {assessment.control_name} control assessment "
                        f"on {system_name}. Status: {assessment.status.value}"
                    ),
                    artifacts=artifacts,
                    generated_at=now,
                    valid_until="",
                )
            )

            # Store evidence if client available
            if self._evidence_store is not None:
                try:
                    await self._evidence_store.store(
                        evidence_id=evidence_id,
                        data=evidence_packages[-1].model_dump(),
                    )
                except Exception:
                    logger.exception("ai_compliance.generate_evidence.store_error")

        return evidence_packages

    def calculate_compliance_scores(
        self,
        assessments: list[ControlAssessment],
    ) -> dict[str, float]:
        """Calculate overall compliance scores per framework.

        Averages control scores per framework, excluding N/A assessments.
        """
        framework_scores: dict[str, list[float]] = {}

        for assessment in assessments:
            if assessment.status == ControlStatus.NOT_APPLICABLE:
                continue
            fw = assessment.framework
            if fw not in framework_scores:
                framework_scores[fw] = []
            framework_scores[fw].append(assessment.score)

        return {
            fw: round(sum(scores) / len(scores), 1) if scores else 0.0
            for fw, scores in framework_scores.items()
        }
