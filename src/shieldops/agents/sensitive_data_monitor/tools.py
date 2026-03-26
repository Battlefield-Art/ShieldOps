"""Sensitive Data Monitor Agent — Tool functions for continuous data monitoring."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

import structlog

from .models import (
    Classification,
    ControlEnforcement,
    DataCategory,
    DataSource,
    ExposureAssessment,
    ExposureLevel,
    SensitiveDataHit,
)

logger = structlog.get_logger()

# -------------------------------------------------------------------
# Regex patterns for sensitive data detection
# -------------------------------------------------------------------

_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "drivers_license": re.compile(r"\b[A-Z]\d{7,14}\b"),
}

_PHI_PATTERNS: dict[str, re.Pattern[str]] = {
    "mrn": re.compile(r"\bMRN[-:\s]?\d{6,10}\b", re.IGNORECASE),
    "diagnosis_code": re.compile(r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b"),
    "npi": re.compile(r"\b\d{10}\b"),
    "medication": re.compile(
        r"\b(?:mg|ml|tablet|capsule|injection)\b",
        re.IGNORECASE,
    ),
}

_PCI_PATTERNS: dict[str, re.Pattern[str]] = {
    "card_number": re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b"),
    "cvv": re.compile(r"\bCVV[-:\s]?\d{3,4}\b", re.IGNORECASE),
    "expiry": re.compile(r"\b(?:0[1-9]|1[0-2])/\d{2,4}\b"),
}

_CREDENTIAL_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_secret": re.compile(
        r"(?i)(?:password|secret|token|api_key|apikey)"
        r"\s*[=:]\s*\S+"
    ),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "jwt_token": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}

_IP_PATTERNS: dict[str, re.Pattern[str]] = {
    "classified_marker": re.compile(r"\b(?:CONFIDENTIAL|TOP SECRET|SECRET|RESTRICTED)\b"),
    "patent_ref": re.compile(r"\b(?:US|EP|WO)\d{7,11}\b"),
}

_CATEGORY_PATTERNS: dict[DataCategory, dict[str, re.Pattern[str]]] = {
    DataCategory.PII: _PII_PATTERNS,
    DataCategory.PHI: _PHI_PATTERNS,
    DataCategory.PCI: _PCI_PATTERNS,
    DataCategory.CREDENTIALS: _CREDENTIAL_PATTERNS,
    DataCategory.INTELLECTUAL_PROPERTY: _IP_PATTERNS,
    DataCategory.CLASSIFIED: {
        "classified_marker": _IP_PATTERNS["classified_marker"],
    },
}

# Regulation mapping
_REGULATION_MAP: dict[str, list[DataCategory]] = {
    "GDPR": [DataCategory.PII],
    "HIPAA": [DataCategory.PHI, DataCategory.PII],
    "PCI_DSS": [DataCategory.PCI],
    "CCPA": [DataCategory.PII],
    "SOX": [DataCategory.INTELLECTUAL_PROPERTY],
    "ITAR": [DataCategory.CLASSIFIED],
}

_REGULATION_REQUIREMENTS: dict[str, str] = {
    "GDPR": (
        "Art. 30 — records of processing activities; Art. 5(1)(f) — integrity and confidentiality"
    ),
    "HIPAA": ("45 CFR 164.312 — technical safeguards for ePHI"),
    "PCI_DSS": ("Req. 3.4 — render PAN unreadable; Req. 4.1 — encrypt transmission"),
    "CCPA": ("1798.100 — right to know personal information"),
    "SOX": ("302/404 — internal controls over financial data"),
    "ITAR": ("22 CFR 120-130 — defense article controls"),
}

# Column-name heuristics for detection without samples
_COLUMN_HEURISTICS: dict[str, DataCategory] = {
    "ssn": DataCategory.PII,
    "social_security": DataCategory.PII,
    "email": DataCategory.PII,
    "phone": DataCategory.PII,
    "date_of_birth": DataCategory.PII,
    "dob": DataCategory.PII,
    "address": DataCategory.PII,
    "credit_card": DataCategory.PCI,
    "card_number": DataCategory.PCI,
    "cvv": DataCategory.PCI,
    "diagnosis": DataCategory.PHI,
    "mrn": DataCategory.PHI,
    "patient_id": DataCategory.PHI,
    "medication": DataCategory.PHI,
    "password": DataCategory.CREDENTIALS,  # noqa: S105
    "api_key": DataCategory.CREDENTIALS,
    "secret": DataCategory.CREDENTIALS,  # noqa: S105
    "token": DataCategory.CREDENTIALS,  # noqa: S105
    "private_key": DataCategory.CREDENTIALS,
    "prompt": DataCategory.INTELLECTUAL_PROPERTY,
    "embedding": DataCategory.INTELLECTUAL_PROPERTY,
    "training_data": DataCategory.INTELLECTUAL_PROPERTY,
}


def _default_exposure(
    category: DataCategory,
) -> ExposureLevel:
    """Default exposure level for a data category."""
    mapping: dict[DataCategory, ExposureLevel] = {
        DataCategory.PII: ExposureLevel.RESTRICTED,
        DataCategory.PHI: ExposureLevel.ENCRYPTED,
        DataCategory.PCI: ExposureLevel.ENCRYPTED,
        DataCategory.CREDENTIALS: ExposureLevel.ENCRYPTED,
        DataCategory.INTELLECTUAL_PROPERTY: (ExposureLevel.RESTRICTED),
        DataCategory.CLASSIFIED: ExposureLevel.ENCRYPTED,
    }
    return mapping.get(category, ExposureLevel.INTERNAL)


def _risk_score(
    category: DataCategory,
    exposure: ExposureLevel,
    confidence: float,
) -> float:
    """Calculate risk score from category, exposure, confidence."""
    cat_weight: dict[DataCategory, float] = {
        DataCategory.PII: 0.7,
        DataCategory.PHI: 0.9,
        DataCategory.PCI: 0.9,
        DataCategory.CREDENTIALS: 1.0,
        DataCategory.INTELLECTUAL_PROPERTY: 0.6,
        DataCategory.CLASSIFIED: 0.95,
    }
    exp_weight: dict[ExposureLevel, float] = {
        ExposureLevel.PUBLIC: 1.0,
        ExposureLevel.SHARED: 0.7,
        ExposureLevel.INTERNAL: 0.4,
        ExposureLevel.RESTRICTED: 0.2,
        ExposureLevel.ENCRYPTED: 0.1,
    }
    cw = cat_weight.get(category, 0.5)
    ew = exp_weight.get(exposure, 0.5)
    return round(min(cw * ew * confidence * 10, 10.0), 2)


class SensitiveDataMonitorToolkit:
    """Tools for continuous sensitive data monitoring."""

    def __init__(
        self,
        db_connector: Any | None = None,
        storage_connector: Any | None = None,
        ai_pipeline_connector: Any | None = None,
        control_api: Any | None = None,
    ) -> None:
        self._db = db_connector
        self._storage = storage_connector
        self._ai_pipeline = ai_pipeline_connector
        self._control_api = control_api
        self._source_cache: dict[str, DataSource] = {}

    # ---------------------------------------------------------------
    # Discovery
    # ---------------------------------------------------------------

    async def discover_data_sources(
        self,
        tenant_id: str,
        source_configs: (list[dict[str, Any]] | None) = None,
        include_ai_pipelines: bool = True,
    ) -> list[DataSource]:
        """Discover data sources: databases, storage, AI pipelines.

        In production calls real connectors. Returns default
        discovery set when no configs are provided.
        """
        logger.info(
            "sensitive_data_monitor.discover",
            tenant_id=tenant_id,
            configs=len(source_configs or []),
        )
        sources: list[DataSource] = []
        configs = source_configs or []

        if not configs:
            configs = self._default_discovery(include_ai_pipelines)

        now = time.time()
        for cfg in configs:
            source = DataSource(
                id=str(uuid.uuid4())[:12],
                name=cfg.get("name", "unknown"),
                source_type=cfg.get("source_type", "database"),
                location=cfg.get("location", ""),
                owner=cfg.get("owner", ""),
                records_count=cfg.get("records_count", 0),
                size_gb=cfg.get("size_gb", 0.0),
                is_ai_pipeline=cfg.get("is_ai_pipeline", False),
                pipeline_type=cfg.get("pipeline_type", ""),
                last_scanned=now,
                scan_frequency_hours=cfg.get("scan_frequency_hours", 24),
            )
            sources.append(source)
            self._source_cache[source.id] = source

        return sources

    # ---------------------------------------------------------------
    # Scanning
    # ---------------------------------------------------------------

    async def scan_for_sensitive(
        self,
        sources: list[DataSource],
        sample_data: (dict[str, list[str]] | None) = None,
    ) -> list[SensitiveDataHit]:
        """Scan sources for sensitive data using regex and heuristics.

        Supports both traditional data stores and AI pipeline
        data (prompts, RAG documents, training sets).
        """
        logger.info(
            "sensitive_data_monitor.scan",
            source_count=len(sources),
        )
        hits: list[SensitiveDataHit] = []
        sample_data = sample_data or {}

        for source in sources:
            samples = sample_data.get(source.id, [])
            if samples:
                hits.extend(self._scan_samples(source, samples))
            else:
                hits.extend(self._scan_heuristic(source))

        return hits

    # ---------------------------------------------------------------
    # Classification
    # ---------------------------------------------------------------

    async def classify_hits(
        self,
        hits: list[SensitiveDataHit],
    ) -> list[Classification]:
        """Classify sensitive hits with exposure level and regulations."""
        logger.info(
            "sensitive_data_monitor.classify",
            hit_count=len(hits),
        )
        classifications: list[Classification] = []

        for hit in hits:
            exposure = _default_exposure(hit.data_category)
            regs = [r for r, cats in _REGULATION_MAP.items() if hit.data_category in cats]
            score = _risk_score(
                hit.data_category,
                exposure,
                hit.confidence,
            )
            classifications.append(
                Classification(
                    id=str(uuid.uuid4())[:12],
                    hit_id=hit.id,
                    source_id=hit.source_id,
                    data_category=hit.data_category,
                    exposure_level=exposure,
                    risk_score=score,
                    regulations=regs,
                    requires_encryption=(
                        hit.data_category
                        in {
                            DataCategory.PHI,
                            DataCategory.PCI,
                            DataCategory.CREDENTIALS,
                            DataCategory.CLASSIFIED,
                        }
                    ),
                    requires_masking=(
                        hit.data_category
                        in {
                            DataCategory.PII,
                            DataCategory.PCI,
                        }
                    ),
                )
            )

        return classifications

    # ---------------------------------------------------------------
    # Exposure assessment
    # ---------------------------------------------------------------

    async def assess_exposure(
        self,
        classifications: list[Classification],
        sources: list[DataSource],
    ) -> list[ExposureAssessment]:
        """Assess exposure risk for each classification."""
        logger.info(
            "sensitive_data_monitor.assess_exposure",
            classification_count=len(classifications),
        )
        source_map = {s.id: s for s in sources}
        assessments: list[ExposureAssessment] = []

        for cls in classifications:
            source = source_map.get(cls.source_id)
            is_public = cls.exposure_level == ExposureLevel.PUBLIC
            has_rest = cls.exposure_level in {
                ExposureLevel.ENCRYPTED,
                ExposureLevel.RESTRICTED,
            }
            has_transit = cls.exposure_level in {
                ExposureLevel.ENCRYPTED,
            }

            # AI pipelines get higher access principal count
            principals = 5
            if source and source.is_ai_pipeline:
                principals = 25

            remediation: list[str] = []
            if is_public:
                remediation.append("Restrict public access immediately")
            if not has_rest and cls.requires_encryption:
                remediation.append("Enable encryption at rest")
            if not has_transit and cls.requires_encryption:
                remediation.append("Enable encryption in transit")
            if cls.requires_masking:
                remediation.append("Apply data masking/tokenization")
            if source and source.is_ai_pipeline:
                remediation.append("Add PII/PHI filters to AI pipeline")

            score = _risk_score(
                cls.data_category,
                cls.exposure_level,
                1.0,
            )
            if is_public:
                score = min(score * 2.5, 10.0)

            assessments.append(
                ExposureAssessment(
                    id=str(uuid.uuid4())[:12],
                    classification_id=cls.id,
                    source_id=cls.source_id,
                    exposure_level=cls.exposure_level,
                    access_principals=principals,
                    is_publicly_accessible=is_public,
                    has_encryption_at_rest=has_rest,
                    has_encryption_in_transit=has_transit,
                    risk_score=round(score, 2),
                    remediation_actions=remediation,
                )
            )

        return assessments

    # ---------------------------------------------------------------
    # Control enforcement
    # ---------------------------------------------------------------

    async def enforce_controls(
        self,
        assessments: list[ExposureAssessment],
        sources: list[DataSource],
    ) -> list[ControlEnforcement]:
        """Enforce data protection controls based on exposure assessment."""
        logger.info(
            "sensitive_data_monitor.enforce_controls",
            assessment_count=len(assessments),
        )
        source_map = {s.id: s for s in sources}
        enforcements: list[ControlEnforcement] = []

        for assessment in assessments:
            source = source_map.get(assessment.source_id)
            source_type = source.source_type if source else "unknown"

            for action in assessment.remediation_actions:
                control_type = self._map_control_type(action, source_type)
                success = True

                if self._control_api:
                    try:
                        await self._control_api.apply(
                            source_id=assessment.source_id,
                            control=control_type,
                            action=action,
                        )
                    except Exception:
                        success = False
                        logger.warning(
                            "sensitive_data_monitor.control_failed",
                            source_id=(assessment.source_id),
                            control=control_type,
                        )

                enforcements.append(
                    ControlEnforcement(
                        id=str(uuid.uuid4())[:12],
                        source_id=assessment.source_id,
                        control_type=control_type,
                        action_taken=action,
                        applied=True,
                        success=success,
                        rollback_available=(control_type != "access_restriction"),
                    )
                )

        return enforcements

    # ---------------------------------------------------------------
    # Compliance coverage
    # ---------------------------------------------------------------

    async def compute_compliance_coverage(
        self,
        classifications: list[Classification],
        assessments: list[ExposureAssessment],
    ) -> dict[str, Any]:
        """Compute per-regulation compliance coverage."""
        coverage: dict[str, dict[str, Any]] = {}

        for reg in _REGULATION_MAP:
            relevant = [c for c in classifications if reg in c.regulations]
            if not relevant:
                coverage[reg] = {
                    "total": 0,
                    "protected": 0,
                    "coverage_pct": 100.0,
                    "requirement": (_REGULATION_REQUIREMENTS.get(reg, "")),
                }
                continue

            cls_ids = {c.id for c in relevant}
            rel_assessments = [a for a in assessments if a.classification_id in cls_ids]
            protected = sum(
                1
                for a in rel_assessments
                if (a.has_encryption_at_rest and not a.is_publicly_accessible)
            )
            total = len(relevant)
            pct = (protected / total * 100.0) if total else 100.0
            coverage[reg] = {
                "total": total,
                "protected": protected,
                "coverage_pct": round(pct, 1),
                "requirement": (_REGULATION_REQUIREMENTS.get(reg, "")),
            }

        return coverage

    # ---------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------

    def _default_discovery(self, include_ai: bool) -> list[dict[str, Any]]:
        """Return default data source discovery set."""
        configs: list[dict[str, Any]] = [
            {
                "name": "users_db",
                "source_type": "database",
                "location": "us-east-1/rds/users",
                "owner": "platform-team",
                "records_count": 2_500_000,
                "size_gb": 12.4,
            },
            {
                "name": "analytics-bucket",
                "source_type": "s3_bucket",
                "location": "us-east-1/s3/analytics",
                "owner": "data-team",
                "records_count": 15_000_000,
                "size_gb": 340.0,
            },
            {
                "name": "patient-records",
                "source_type": "database",
                "location": "us-west-2/rds/patients",
                "owner": "health-team",
                "records_count": 800_000,
                "size_gb": 5.2,
            },
            {
                "name": "payments-store",
                "source_type": "database",
                "location": "eu-west-1/rds/payments",
                "owner": "billing-team",
                "records_count": 4_000_000,
                "size_gb": 18.7,
            },
            {
                "name": "backup-vault",
                "source_type": "backup_vault",
                "location": "us-east-1/backup/vault",
                "owner": "infra-team",
                "records_count": 50_000_000,
                "size_gb": 1200.0,
            },
        ]
        if include_ai:
            configs.extend(
                [
                    {
                        "name": "llm-prompt-logs",
                        "source_type": "log_store",
                        "location": "us-east-1/s3/prompts",
                        "owner": "ai-team",
                        "records_count": 5_000_000,
                        "size_gb": 45.0,
                        "is_ai_pipeline": True,
                        "pipeline_type": "llm_prompts",
                    },
                    {
                        "name": "rag-document-store",
                        "source_type": "vector_db",
                        "location": "us-east-1/pinecone",
                        "owner": "ai-team",
                        "records_count": 2_000_000,
                        "size_gb": 80.0,
                        "is_ai_pipeline": True,
                        "pipeline_type": ("rag_documents"),
                    },
                    {
                        "name": "training-dataset",
                        "source_type": "s3_bucket",
                        "location": "us-west-2/s3/training",
                        "owner": "ml-team",
                        "records_count": 10_000_000,
                        "size_gb": 500.0,
                        "is_ai_pipeline": True,
                        "pipeline_type": ("training_data"),
                    },
                ]
            )
        return configs

    def _scan_samples(
        self,
        source: DataSource,
        samples: list[str],
    ) -> list[SensitiveDataHit]:
        """Regex scan on actual sample values."""
        hits: list[SensitiveDataHit] = []
        for idx, value in enumerate(samples):
            for category, patterns in _CATEGORY_PATTERNS.items():
                for pat_name, pat in patterns.items():
                    if pat.search(value):
                        lineage = [source.name]
                        if source.is_ai_pipeline:
                            lineage.append(source.pipeline_type)
                        hits.append(
                            SensitiveDataHit(
                                id=str(uuid.uuid4())[:12],
                                source_id=source.id,
                                data_category=(category),
                                column_or_path=(f"sample[{idx}]/{pat_name}"),
                                sample_count=1,
                                confidence=0.92,
                                detection_method=("regex"),
                                regex_matched=True,
                                ml_classified=False,
                                data_lineage=lineage,
                            )
                        )
        return hits

    def _scan_heuristic(
        self,
        source: DataSource,
    ) -> list[SensitiveDataHit]:
        """Heuristic scan based on source name patterns."""
        hits: list[SensitiveDataHit] = []
        name_lower = source.name.lower()

        for keyword, category in _COLUMN_HEURISTICS.items():
            if keyword in name_lower:
                lineage = [source.name]
                if source.is_ai_pipeline:
                    lineage.append(source.pipeline_type)
                hits.append(
                    SensitiveDataHit(
                        id=str(uuid.uuid4())[:12],
                        source_id=source.id,
                        data_category=category,
                        column_or_path=(f"heuristic/{keyword}"),
                        sample_count=0,
                        confidence=0.65,
                        detection_method="heuristic",
                        regex_matched=False,
                        ml_classified=False,
                        data_lineage=lineage,
                    )
                )

        # Domain-specific heuristics
        if "patient" in name_lower:
            hits.append(
                self._make_heuristic_hit(
                    source,
                    DataCategory.PHI,
                    "patient_data",
                    0.78,
                )
            )
        if "payment" in name_lower:
            hits.append(
                self._make_heuristic_hit(
                    source,
                    DataCategory.PCI,
                    "payment_data",
                    0.80,
                )
            )
        if "backup" in name_lower:
            hits.append(
                self._make_heuristic_hit(
                    source,
                    DataCategory.PII,
                    "backup_contains_pii",
                    0.70,
                )
            )

        # AI pipeline-specific detection
        if source.is_ai_pipeline:
            if source.pipeline_type == "llm_prompts":
                hits.append(
                    self._make_heuristic_hit(
                        source,
                        DataCategory.PII,
                        "prompt_pii_leakage",
                        0.75,
                    )
                )
            if source.pipeline_type == "rag_documents":
                hits.append(
                    self._make_heuristic_hit(
                        source,
                        DataCategory.INTELLECTUAL_PROPERTY,
                        "rag_ip_exposure",
                        0.72,
                    )
                )
            if source.pipeline_type == "training_data":
                hits.append(
                    self._make_heuristic_hit(
                        source,
                        DataCategory.PII,
                        "training_pii_inclusion",
                        0.68,
                    )
                )

        return hits

    def _make_heuristic_hit(
        self,
        source: DataSource,
        category: DataCategory,
        path: str,
        confidence: float,
    ) -> SensitiveDataHit:
        """Create a heuristic-based sensitive data hit."""
        lineage = [source.name]
        if source.is_ai_pipeline:
            lineage.append(source.pipeline_type)
        return SensitiveDataHit(
            id=str(uuid.uuid4())[:12],
            source_id=source.id,
            data_category=category,
            column_or_path=f"heuristic/{path}",
            sample_count=0,
            confidence=confidence,
            detection_method="heuristic",
            regex_matched=False,
            ml_classified=False,
            data_lineage=lineage,
        )

    @staticmethod
    def _map_control_type(action: str, source_type: str) -> str:
        """Map a remediation action to a control type."""
        action_lower = action.lower()
        if "encrypt" in action_lower:
            return "encryption"
        if "mask" in action_lower or ("token" in action_lower):
            return "data_masking"
        if "restrict" in action_lower or ("access" in action_lower):
            return "access_restriction"
        if "filter" in action_lower or ("pipeline" in action_lower):
            return "ai_pipeline_filter"
        return "policy_enforcement"
