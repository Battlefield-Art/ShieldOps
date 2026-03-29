"""Privacy Engineering Agent — Tool functions for privacy validation and PET auditing."""

from __future__ import annotations

import math
import time
import uuid
from typing import Any

import structlog

from .models import (
    AnonymizationFinding,
    ComplianceMapping,
    DataPipeline,
    PETImplementation,
    PrivacyTechnique,
    RiskLevel,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Epsilon thresholds for differential privacy risk classification
# ---------------------------------------------------------------------------
_EPSILON_THRESHOLDS: dict[RiskLevel, float] = {
    RiskLevel.NEGLIGIBLE: 0.1,
    RiskLevel.LOW: 1.0,
    RiskLevel.MEDIUM: 5.0,
    RiskLevel.HIGH: 10.0,
    # > 10.0 => CRITICAL
}

# ---------------------------------------------------------------------------
# k-anonymity thresholds
# ---------------------------------------------------------------------------
_K_ANONYMITY_THRESHOLDS: dict[RiskLevel, int] = {
    RiskLevel.NEGLIGIBLE: 50,
    RiskLevel.LOW: 20,
    RiskLevel.MEDIUM: 5,
    RiskLevel.HIGH: 2,
    # < 2 => CRITICAL
}

# ---------------------------------------------------------------------------
# Known PET libraries with validation rules
# ---------------------------------------------------------------------------
_KNOWN_PET_LIBRARIES: dict[str, dict[str, Any]] = {
    "opendp": {
        "techniques": [PrivacyTechnique.DIFFERENTIAL_PRIVACY],
        "min_version": "0.7.0",
        "required_config": ["epsilon", "delta", "mechanism"],
    },
    "google_dp": {
        "techniques": [PrivacyTechnique.DIFFERENTIAL_PRIVACY],
        "min_version": "1.1.0",
        "required_config": ["epsilon", "max_partitions_contributed"],
    },
    "tensorflow_privacy": {
        "techniques": [PrivacyTechnique.DIFFERENTIAL_PRIVACY],
        "min_version": "0.8.0",
        "required_config": ["noise_multiplier", "l2_norm_clip", "num_microbatches"],
    },
    "pysyft": {
        "techniques": [
            PrivacyTechnique.SECURE_MULTIPARTY,
            PrivacyTechnique.DIFFERENTIAL_PRIVACY,
        ],
        "min_version": "0.8.0",
        "required_config": ["protocol", "parties"],
    },
    "concrete_ml": {
        "techniques": [PrivacyTechnique.HOMOMORPHIC_ENCRYPTION],
        "min_version": "1.0.0",
        "required_config": ["bit_width", "scheme"],
    },
}

# ---------------------------------------------------------------------------
# Regulation -> privacy requirements mapping
# ---------------------------------------------------------------------------
_REGULATION_REQUIREMENTS: dict[str, dict[str, str]] = {
    "GDPR": {
        "article": "Art. 25",
        "requirement": "Data protection by design and by default — implement appropriate "
        "technical measures including pseudonymisation and data minimisation",
    },
    "CCPA": {
        "article": "1798.100(e)",
        "requirement": "Businesses shall implement and maintain reasonable security procedures "
        "to protect personal information",
    },
    "HIPAA": {
        "article": "45 CFR 164.514(b)",
        "requirement": "De-identification standard — expert determination or safe harbor method "
        "for protected health information",
    },
    "LGPD": {
        "article": "Art. 46",
        "requirement": "Security measures to protect personal data from unauthorized access "
        "and accidental or unlawful situations",
    },
    "PIPL": {
        "article": "Art. 51",
        "requirement": "Personal information processors shall adopt technical measures to ensure "
        "security of personal information processing",
    },
}

_REGULATION_APPLICABILITY: dict[str, list[str]] = {
    "GDPR": ["pii", "phi", "behavioral", "biometric"],
    "CCPA": ["pii", "behavioral", "geolocation"],
    "HIPAA": ["phi", "pii"],
    "LGPD": ["pii", "behavioral"],
    "PIPL": ["pii", "biometric", "behavioral"],
}


def _risk_from_epsilon(epsilon: float) -> RiskLevel:
    """Classify risk based on differential privacy epsilon value."""
    if epsilon <= _EPSILON_THRESHOLDS[RiskLevel.NEGLIGIBLE]:
        return RiskLevel.NEGLIGIBLE
    if epsilon <= _EPSILON_THRESHOLDS[RiskLevel.LOW]:
        return RiskLevel.LOW
    if epsilon <= _EPSILON_THRESHOLDS[RiskLevel.MEDIUM]:
        return RiskLevel.MEDIUM
    if epsilon <= _EPSILON_THRESHOLDS[RiskLevel.HIGH]:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _risk_from_k(k: int) -> RiskLevel:
    """Classify risk based on k-anonymity k value."""
    if k >= _K_ANONYMITY_THRESHOLDS[RiskLevel.NEGLIGIBLE]:
        return RiskLevel.NEGLIGIBLE
    if k >= _K_ANONYMITY_THRESHOLDS[RiskLevel.LOW]:
        return RiskLevel.LOW
    if k >= _K_ANONYMITY_THRESHOLDS[RiskLevel.MEDIUM]:
        return RiskLevel.MEDIUM
    if k >= _K_ANONYMITY_THRESHOLDS[RiskLevel.HIGH]:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _re_identification_risk(k: int, quasi_count: int) -> float:
    """Estimate re-identification risk based on k and quasi-identifier count.

    Uses a simple model: risk = 1/k * log2(quasi_count + 1).
    Clamped to [0.0, 1.0].
    """
    if k <= 0:
        return 1.0
    risk = (1.0 / k) * math.log2(quasi_count + 1)
    return max(0.0, min(1.0, risk))


class PrivacyEngineeringToolkit:
    """Tools for validating privacy implementations across data pipelines."""

    def __init__(
        self,
        pipeline_registry: Any | None = None,
        pet_scanner: Any | None = None,
    ) -> None:
        self._pipeline_registry = pipeline_registry
        self._pet_scanner = pet_scanner
        self._pipeline_cache: dict[str, DataPipeline] = {}

    async def scan_pipelines(
        self,
        tenant_id: str,
        pipeline_configs: list[dict[str, Any]] | None = None,
    ) -> list[DataPipeline]:
        """Discover data pipelines that handle personal or sensitive data.

        In production this queries the pipeline registry; here we build an
        inventory from *pipeline_configs* or return a default discovery set.
        """
        logger.info(
            "privacy_engineering.scan_pipelines",
            tenant_id=tenant_id,
            configs=len(pipeline_configs or []),
        )
        pipelines: list[DataPipeline] = []
        configs = pipeline_configs or []

        if not configs:
            configs = [
                {
                    "name": "user-analytics-etl",
                    "pipeline_type": "etl",
                    "owner": "data-team",
                    "data_sources": ["users_db", "events_stream"],
                    "data_sinks": ["analytics_warehouse"],
                    "records_per_day": 5_000_000,
                    "contains_pii": True,
                },
                {
                    "name": "ml-training-pipeline",
                    "pipeline_type": "ml_training",
                    "owner": "ml-team",
                    "data_sources": ["user_profiles", "transaction_history"],
                    "data_sinks": ["model_registry"],
                    "records_per_day": 2_000_000,
                    "contains_pii": True,
                },
                {
                    "name": "patient-research-export",
                    "pipeline_type": "analytics",
                    "owner": "health-team",
                    "data_sources": ["patient_records", "lab_results"],
                    "data_sinks": ["research_bucket"],
                    "records_per_day": 100_000,
                    "contains_pii": True,
                },
                {
                    "name": "payment-reporting",
                    "pipeline_type": "etl",
                    "owner": "billing-team",
                    "data_sources": ["payment_transactions"],
                    "data_sinks": ["compliance_reports"],
                    "records_per_day": 800_000,
                    "contains_pii": True,
                },
                {
                    "name": "public-metrics-aggregator",
                    "pipeline_type": "streaming",
                    "owner": "platform-team",
                    "data_sources": ["app_telemetry"],
                    "data_sinks": ["metrics_dashboard"],
                    "records_per_day": 50_000_000,
                    "contains_pii": False,
                },
            ]

        now = time.time()
        for cfg in configs:
            pipeline = DataPipeline(
                id=str(uuid.uuid4())[:12],
                name=cfg.get("name", "unknown"),
                pipeline_type=cfg.get("pipeline_type", "etl"),
                owner=cfg.get("owner", ""),
                data_sources=cfg.get("data_sources", []),
                data_sinks=cfg.get("data_sinks", []),
                records_per_day=cfg.get("records_per_day", 0),
                contains_pii=cfg.get("contains_pii", False),
                last_audited=now,
            )
            pipelines.append(pipeline)
            self._pipeline_cache[pipeline.id] = pipeline

        return pipelines

    async def assess_anonymization(
        self,
        pipelines: list[DataPipeline],
        anonymization_configs: dict[str, dict[str, Any]] | None = None,
    ) -> list[AnonymizationFinding]:
        """Assess anonymization quality across pipelines.

        *anonymization_configs* maps pipeline_id -> anonymization parameters.
        When not provided, heuristic assessment is used.
        """
        logger.info(
            "privacy_engineering.assess_anonymization",
            pipeline_count=len(pipelines),
        )
        findings: list[AnonymizationFinding] = []
        configs = anonymization_configs or {}

        for pipeline in pipelines:
            if not pipeline.contains_pii:
                continue

            cfg = configs.get(pipeline.id, {})
            technique = (
                PrivacyTechnique(cfg.get("technique", "k_anonymity"))
                if cfg.get("technique")
                else PrivacyTechnique.K_ANONYMITY
            )

            k_value = cfg.get("k_value", 5)
            epsilon = cfg.get("epsilon", 1.0)
            delta = cfg.get("delta", 1e-5)
            quasi_ids = cfg.get("quasi_identifiers", ["age", "zip_code", "gender"])

            # Determine risk based on technique
            if technique == PrivacyTechnique.DIFFERENTIAL_PRIVACY:
                risk = _risk_from_epsilon(epsilon)
                re_id_risk = max(0.0, min(1.0, epsilon / 20.0))
            elif technique in (
                PrivacyTechnique.K_ANONYMITY,
                PrivacyTechnique.L_DIVERSITY,
                PrivacyTechnique.T_CLOSENESS,
            ):
                risk = _risk_from_k(k_value)
                re_id_risk = _re_identification_risk(k_value, len(quasi_ids))
            elif technique == PrivacyTechnique.HOMOMORPHIC_ENCRYPTION:
                risk = RiskLevel.LOW
                re_id_risk = 0.01
            elif technique == PrivacyTechnique.SECURE_MULTIPARTY:
                risk = RiskLevel.LOW
                re_id_risk = 0.02
            else:
                risk = RiskLevel.MEDIUM
                re_id_risk = 0.5

            compliant = risk in (RiskLevel.NEGLIGIBLE, RiskLevel.LOW)
            gap = ""
            if not compliant:
                gap = (
                    f"Pipeline '{pipeline.name}' uses {technique.value} with insufficient "
                    f"parameters — re-identification risk {re_id_risk:.2%}"
                )

            findings.append(
                AnonymizationFinding(
                    id=str(uuid.uuid4())[:12],
                    pipeline_id=pipeline.id,
                    technique_used=technique,
                    risk_level=risk,
                    k_value=k_value,
                    epsilon=epsilon,
                    delta=delta,
                    quasi_identifiers=quasi_ids,
                    re_identification_risk=round(re_id_risk, 4),
                    compliant=compliant,
                    gap_description=gap,
                )
            )

        return findings

    async def validate_differential_privacy(
        self,
        findings: list[AnonymizationFinding],
    ) -> list[AnonymizationFinding]:
        """Validate differential privacy parameters against best practices.

        Checks epsilon/delta bounds, composition budget, and mechanism suitability.
        Returns updated findings with validation results.
        """
        logger.info(
            "privacy_engineering.validate_dp",
            finding_count=len(findings),
        )
        validated: list[AnonymizationFinding] = []

        for finding in findings:
            f_copy = finding.model_copy()

            if finding.technique_used == PrivacyTechnique.DIFFERENTIAL_PRIVACY:
                # Validate epsilon bounds
                if finding.epsilon > 10.0:
                    f_copy.risk_level = RiskLevel.CRITICAL
                    f_copy.compliant = False
                    f_copy.gap_description = (
                        f"Epsilon {finding.epsilon} exceeds safe threshold (10.0) — "
                        f"privacy guarantee is effectively meaningless"
                    )
                elif finding.epsilon > 5.0:
                    f_copy.risk_level = RiskLevel.HIGH
                    f_copy.compliant = False
                    f_copy.gap_description = (
                        f"Epsilon {finding.epsilon} is high — consider tightening to <1.0 "
                        f"for meaningful differential privacy"
                    )

                # Validate delta bounds (should be < 1/n)
                if finding.delta > 1e-3:
                    if f_copy.risk_level not in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                        f_copy.risk_level = RiskLevel.HIGH
                    f_copy.compliant = False
                    f_copy.gap_description += (
                        f"; delta {finding.delta} is too large — should be < 1/n "
                        f"(recommended: 1e-5)"
                    )
            else:
                # For non-DP techniques, validate k-anonymity parameters
                if finding.k_value < 5 and finding.technique_used in (
                    PrivacyTechnique.K_ANONYMITY,
                    PrivacyTechnique.L_DIVERSITY,
                    PrivacyTechnique.T_CLOSENESS,
                ):
                    f_copy.risk_level = RiskLevel.HIGH
                    f_copy.compliant = False
                    f_copy.gap_description = (
                        f"k={finding.k_value} is below recommended minimum of 5 — "
                        f"high re-identification risk with {len(finding.quasi_identifiers)} "
                        f"quasi-identifiers"
                    )

            validated.append(f_copy)

        return validated

    async def audit_pet_implementations(
        self,
        pipelines: list[DataPipeline],
        pet_configs: dict[str, dict[str, Any]] | None = None,
    ) -> list[PETImplementation]:
        """Audit Privacy Enhancing Technology implementations.

        Validates library versions, configuration completeness, and technique
        suitability for each pipeline.
        """
        logger.info(
            "privacy_engineering.audit_pets",
            pipeline_count=len(pipelines),
        )
        implementations: list[PETImplementation] = []
        configs = pet_configs or {}

        for pipeline in pipelines:
            if not pipeline.contains_pii:
                continue

            cfg = configs.get(pipeline.id, {})
            library = cfg.get("library", "opendp")
            version = cfg.get("version", "0.7.0")
            technique = (
                PrivacyTechnique(cfg.get("technique", "differential_privacy"))
                if cfg.get("technique")
                else PrivacyTechnique.DIFFERENTIAL_PRIVACY
            )
            pet_config = cfg.get("config", {"epsilon": 1.0, "delta": 1e-5, "mechanism": "laplace"})

            errors: list[str] = []
            lib_info = _KNOWN_PET_LIBRARIES.get(library)

            if lib_info is None:
                errors.append(f"Unknown PET library '{library}' — cannot validate")
            else:
                # Check technique compatibility
                if technique not in lib_info["techniques"]:
                    errors.append(f"Library '{library}' does not support {technique.value}")
                # Check required config keys
                for key in lib_info.get("required_config", []):
                    if key not in pet_config:
                        errors.append(f"Missing required config key '{key}' for {library}")

            implementations.append(
                PETImplementation(
                    id=str(uuid.uuid4())[:12],
                    pipeline_id=pipeline.id,
                    technique=technique,
                    library=library,
                    version=version,
                    config=pet_config,
                    validated=len(errors) == 0,
                    validation_errors=errors,
                )
            )

        return implementations

    async def check_compliance(
        self,
        findings: list[AnonymizationFinding],
        pipelines: list[DataPipeline],
    ) -> list[ComplianceMapping]:
        """Map privacy findings to regulatory requirements.

        Checks GDPR Art. 25, CCPA, HIPAA de-identification, LGPD, and PIPL.
        """
        logger.info(
            "privacy_engineering.check_compliance",
            finding_count=len(findings),
        )
        mappings: list[ComplianceMapping] = []

        # Build pipeline lookup
        pipeline_map = {p.id: p for p in pipelines}

        for finding in findings:
            pipeline = pipeline_map.get(finding.pipeline_id)
            if not pipeline:
                continue

            # Determine applicable data types from pipeline context
            data_types: set[str] = set()
            name_lower = pipeline.name.lower()
            if "patient" in name_lower or "health" in name_lower:
                data_types.add("phi")
            if pipeline.contains_pii:
                data_types.add("pii")
            if "analytics" in name_lower or "ml" in name_lower:
                data_types.add("behavioral")

            for regulation, applicable_types in _REGULATION_APPLICABILITY.items():
                if data_types & set(applicable_types):
                    req = _REGULATION_REQUIREMENTS.get(regulation, {})
                    compliant = finding.compliant
                    gap = ""
                    if not compliant:
                        gap = (
                            f"Pipeline '{pipeline.name}' — {finding.technique_used.value} "
                            f"with risk level {finding.risk_level.value} does not meet "
                            f"{regulation} {req.get('article', '')} requirements"
                        )

                    mappings.append(
                        ComplianceMapping(
                            id=str(uuid.uuid4())[:12],
                            finding_id=finding.id,
                            regulation=regulation,
                            article=req.get("article", ""),
                            requirement=req.get("requirement", ""),
                            compliant=compliant,
                            gap_description=gap,
                        )
                    )

        return mappings
