"""Data Classification Agent — Tool functions for data sensitivity scanning."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

import structlog

from .models import (
    DataAsset,
    DataCategory,
    LabelEnforcement,
    RegulatoryMapping,
    SensitiveDataFinding,
    SensitivityLevel,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Regex patterns for sensitive data detection
# ---------------------------------------------------------------------------

_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
}

_PHI_PATTERNS: dict[str, re.Pattern[str]] = {
    "mrn": re.compile(r"\bMRN[-:\s]?\d{6,10}\b", re.IGNORECASE),
    "diagnosis_code": re.compile(r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b"),
    "npi": re.compile(r"\b\d{10}\b"),
}

_PCI_PATTERNS: dict[str, re.Pattern[str]] = {
    "card_number": re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b"),
    "cvv": re.compile(r"\bCVV[-:\s]?\d{3,4}\b", re.IGNORECASE),
    "expiry": re.compile(r"\b(?:0[1-9]|1[0-2])/\d{2,4}\b"),
}

_CREDENTIAL_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_secret": re.compile(r"(?i)(?:password|secret|token|api_key|apikey)\s*[=:]\s*\S+"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}

_CATEGORY_PATTERNS: dict[DataCategory, dict[str, re.Pattern[str]]] = {
    DataCategory.PII: _PII_PATTERNS,
    DataCategory.PHI: _PHI_PATTERNS,
    DataCategory.PCI: _PCI_PATTERNS,
    DataCategory.CREDENTIALS: _CREDENTIAL_PATTERNS,
}

# Regulation → category mapping
_REGULATION_MAP: dict[str, list[DataCategory]] = {
    "GDPR": [DataCategory.PII],
    "HIPAA": [DataCategory.PHI, DataCategory.PII],
    "PCI_DSS": [DataCategory.PCI],
    "CCPA": [DataCategory.PII],
    "SOX": [DataCategory.BUSINESS_CRITICAL],
}

_REGULATION_REQUIREMENTS: dict[str, dict[str, str]] = {
    "GDPR": {
        "description": "EU General Data Protection Regulation",
        "requirement": "Art. 5(1)(f) — integrity and confidentiality of personal data",
    },
    "HIPAA": {
        "description": "Health Insurance Portability and Accountability Act",
        "requirement": "45 CFR §164.312 — technical safeguards for ePHI",
    },
    "PCI_DSS": {
        "description": "Payment Card Industry Data Security Standard",
        "requirement": "Req. 3 — protect stored cardholder data",
    },
    "CCPA": {
        "description": "California Consumer Privacy Act",
        "requirement": "§1798.100 — consumer right to know personal information",
    },
    "SOX": {
        "description": "Sarbanes-Oxley Act",
        "requirement": "§302/404 — internal controls over financial reporting",
    },
}


def _sensitivity_for_category(category: DataCategory) -> SensitivityLevel:
    """Determine default sensitivity level for a data category."""
    mapping: dict[DataCategory, SensitivityLevel] = {
        DataCategory.PII: SensitivityLevel.CONFIDENTIAL,
        DataCategory.PHI: SensitivityLevel.TOP_SECRET,
        DataCategory.PCI: SensitivityLevel.TOP_SECRET,
        DataCategory.CREDENTIALS: SensitivityLevel.TOP_SECRET,
        DataCategory.INTELLECTUAL_PROPERTY: SensitivityLevel.CONFIDENTIAL,
        DataCategory.BUSINESS_CRITICAL: SensitivityLevel.INTERNAL,
    }
    return mapping.get(category, SensitivityLevel.UNCLASSIFIED)


class DataClassificationToolkit:
    """Tools for scanning, detecting, and classifying sensitive data."""

    def __init__(
        self,
        db_connector: Any | None = None,
        storage_connector: Any | None = None,
        label_api: Any | None = None,
    ) -> None:
        self._db_connector = db_connector
        self._storage_connector = storage_connector
        self._label_api = label_api
        self._scan_cache: dict[str, DataAsset] = {}

    async def scan_data_sources(
        self,
        tenant_id: str,
        source_configs: list[dict[str, Any]] | None = None,
    ) -> list[DataAsset]:
        """Discover and catalog data assets across databases, buckets, and shares.

        In production this calls real connectors; here we build an asset inventory
        from *source_configs* or return a default discovery set.
        """
        logger.info(
            "data_classification.scan_sources",
            tenant_id=tenant_id,
            configs=len(source_configs or []),
        )
        assets: list[DataAsset] = []
        configs = source_configs or []

        if not configs:
            # Default discovery — simulates a scan returning known assets
            configs = [
                {
                    "name": "users_db",
                    "asset_type": "database",
                    "location": "us-east-1/rds/users",
                    "owner": "platform-team",
                    "records_count": 2_500_000,
                    "size_gb": 12.4,
                },
                {
                    "name": "analytics-bucket",
                    "asset_type": "s3_bucket",
                    "location": "us-east-1/s3/analytics-bucket",
                    "owner": "data-team",
                    "records_count": 15_000_000,
                    "size_gb": 340.0,
                },
                {
                    "name": "patient-records",
                    "asset_type": "database",
                    "location": "us-west-2/rds/patient-records",
                    "owner": "health-team",
                    "records_count": 800_000,
                    "size_gb": 5.2,
                },
                {
                    "name": "payments-store",
                    "asset_type": "database",
                    "location": "eu-west-1/rds/payments",
                    "owner": "billing-team",
                    "records_count": 4_000_000,
                    "size_gb": 18.7,
                },
            ]

        now = time.time()
        for cfg in configs:
            asset = DataAsset(
                id=str(uuid.uuid4())[:12],
                name=cfg.get("name", "unknown"),
                asset_type=cfg.get("asset_type", "database"),
                location=cfg.get("location", ""),
                owner=cfg.get("owner", ""),
                records_count=cfg.get("records_count", 0),
                size_gb=cfg.get("size_gb", 0.0),
                last_scanned=now,
            )
            assets.append(asset)
            self._scan_cache[asset.id] = asset

        return assets

    async def detect_sensitive_data(
        self,
        assets: list[DataAsset],
        sample_data: dict[str, list[str]] | None = None,
    ) -> list[SensitiveDataFinding]:
        """Run regex-based detection for PII, PHI, PCI, and credentials.

        *sample_data* maps ``asset_id`` → list of sampled column/field values.
        When no sample data is provided, heuristic detection is used based on
        column name patterns.
        """
        logger.info(
            "data_classification.detect_sensitive",
            asset_count=len(assets),
        )
        findings: list[SensitiveDataFinding] = []
        sample_data = sample_data or {}

        # Column-name heuristics when no sample data provided
        _column_heuristics: dict[str, DataCategory] = {
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
            "password": DataCategory.CREDENTIALS,
            "api_key": DataCategory.CREDENTIALS,
            "secret": DataCategory.CREDENTIALS,
            "token": DataCategory.CREDENTIALS,
            "private_key": DataCategory.CREDENTIALS,
        }

        for asset in assets:
            samples = sample_data.get(asset.id, [])

            if samples:
                # Regex-based detection on actual sample values
                for idx, value in enumerate(samples):
                    for category, patterns in _CATEGORY_PATTERNS.items():
                        for pat_name, pat in patterns.items():
                            if pat.search(value):
                                findings.append(
                                    SensitiveDataFinding(
                                        id=str(uuid.uuid4())[:12],
                                        asset_id=asset.id,
                                        data_category=category,
                                        sensitivity_level=(_sensitivity_for_category(category)),
                                        column_or_path=f"sample[{idx}]/{pat_name}",
                                        sample_count=1,
                                        confidence=0.92,
                                        regex_matched=True,
                                        llm_classified=False,
                                    )
                                )
            else:
                # Heuristic: infer from asset name/type
                name_lower = asset.name.lower()
                for keyword, category in _column_heuristics.items():
                    if keyword in name_lower:
                        findings.append(
                            SensitiveDataFinding(
                                id=str(uuid.uuid4())[:12],
                                asset_id=asset.id,
                                data_category=category,
                                sensitivity_level=(_sensitivity_for_category(category)),
                                column_or_path=f"heuristic/{keyword}",
                                sample_count=0,
                                confidence=0.65,
                                regex_matched=False,
                                llm_classified=False,
                            )
                        )

                # Common defaults for databases with patient/payment in name
                if "patient" in name_lower:
                    findings.append(
                        SensitiveDataFinding(
                            id=str(uuid.uuid4())[:12],
                            asset_id=asset.id,
                            data_category=DataCategory.PHI,
                            sensitivity_level=SensitivityLevel.TOP_SECRET,
                            column_or_path="heuristic/patient_data",
                            sample_count=0,
                            confidence=0.78,
                            regex_matched=False,
                            llm_classified=False,
                        )
                    )
                if "payment" in name_lower:
                    findings.append(
                        SensitiveDataFinding(
                            id=str(uuid.uuid4())[:12],
                            asset_id=asset.id,
                            data_category=DataCategory.PCI,
                            sensitivity_level=SensitivityLevel.TOP_SECRET,
                            column_or_path="heuristic/payment_data",
                            sample_count=0,
                            confidence=0.80,
                            regex_matched=False,
                            llm_classified=False,
                        )
                    )

        return findings

    async def map_to_regulations(
        self,
        findings: list[SensitiveDataFinding],
    ) -> list[RegulatoryMapping]:
        """Map sensitive data findings to applicable regulatory requirements."""
        logger.info(
            "data_classification.map_regulations",
            finding_count=len(findings),
        )
        mappings: list[RegulatoryMapping] = []

        for finding in findings:
            for regulation, categories in _REGULATION_MAP.items():
                if finding.data_category in categories:
                    req_info = _REGULATION_REQUIREMENTS.get(regulation, {})
                    # Compliance heuristic: high-confidence + regex = likely compliant
                    compliant = finding.confidence >= 0.85 and finding.regex_matched
                    gap = (
                        ""
                        if compliant
                        else (
                            f"{finding.data_category.value} data in "
                            f"{finding.column_or_path} needs encryption/masking "
                            f"per {regulation}"
                        )
                    )
                    mappings.append(
                        RegulatoryMapping(
                            id=str(uuid.uuid4())[:12],
                            finding_id=finding.id,
                            regulation=regulation,
                            requirement=req_info.get("requirement", ""),
                            compliant=compliant,
                            gap_description=gap,
                        )
                    )

        return mappings

    async def enforce_labels(
        self,
        assets: list[DataAsset],
        findings: list[SensitiveDataFinding],
    ) -> list[LabelEnforcement]:
        """Apply classification labels to assets based on findings.

        In production this calls cloud APIs (AWS Macie tags, GCS labels, etc.).
        Here we simulate label application.
        """
        logger.info(
            "data_classification.enforce_labels",
            asset_count=len(assets),
            finding_count=len(findings),
        )
        enforcements: list[LabelEnforcement] = []

        # Build per-asset highest sensitivity
        asset_sensitivity: dict[str, SensitivityLevel] = {}
        _level_order = [
            SensitivityLevel.PUBLIC,
            SensitivityLevel.UNCLASSIFIED,
            SensitivityLevel.INTERNAL,
            SensitivityLevel.CONFIDENTIAL,
            SensitivityLevel.TOP_SECRET,
        ]

        for finding in findings:
            current = asset_sensitivity.get(finding.asset_id, SensitivityLevel.UNCLASSIFIED)
            if _level_order.index(finding.sensitivity_level) > _level_order.index(current):
                asset_sensitivity[finding.asset_id] = finding.sensitivity_level

        for asset in assets:
            level = asset_sensitivity.get(asset.id, SensitivityLevel.UNCLASSIFIED)
            label = f"shieldops:classification={level.value}"

            # Determine enforcement method based on asset type
            method_map: dict[str, str] = {
                "database": "column_level_tagging",
                "s3_bucket": "aws_object_tagging",
                "gcs_bucket": "gcs_label_api",
                "blob_storage": "azure_blob_metadata",
                "file_share": "extended_attributes",
            }
            method = method_map.get(asset.asset_type, "metadata_tag")

            # Simulate label application (always succeeds in stub)
            success = True
            if self._label_api:
                try:
                    await self._label_api.apply_label(
                        asset_id=asset.id,
                        label=label,
                    )
                except Exception:
                    success = False
                    logger.warning(
                        "data_classification.label_failed",
                        asset_id=asset.id,
                    )

            enforcements.append(
                LabelEnforcement(
                    id=str(uuid.uuid4())[:12],
                    asset_id=asset.id,
                    label_applied=label,
                    enforcement_method=method,
                    applied=True,
                    success=success,
                )
            )

        return enforcements
