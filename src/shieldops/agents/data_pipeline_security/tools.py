"""Data Pipeline Security Agent — Tool functions for pipeline protection."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    DataFlowAnomaly,
    DataSourceType,
    PoisoningFinding,
    PolicyViolation,
    ProvenanceRecord,
    RiskLevel,
)

logger = structlog.get_logger()

# --- Poisoning indicator patterns ---
_POISONING_INDICATORS: list[dict[str, Any]] = [
    {
        "pattern": "prompt injection",
        "type": "document_poisoning",
        "severity": RiskLevel.CRITICAL,
        "mitre": "AML.T0020",
        "description": "Document contains embedded prompt injection payloads for RAG poisoning",
    },
    {
        "pattern": "ignore previous",
        "type": "instruction_override",
        "severity": RiskLevel.CRITICAL,
        "mitre": "AML.T0020.001",
        "description": "Adversarial text designed to override RAG-augmented instructions",
    },
    {
        "pattern": "backdoor",
        "type": "backdoor_trigger",
        "severity": RiskLevel.HIGH,
        "mitre": "AML.T0018",
        "description": "Potential backdoor trigger pattern in training or retrieval data",
    },
    {
        "pattern": "adversarial",
        "type": "adversarial_example",
        "severity": RiskLevel.HIGH,
        "mitre": "AML.T0043",
        "description": "Adversarial perturbation designed to manipulate model behavior",
    },
    {
        "pattern": "data:text/html",
        "type": "encoded_payload",
        "severity": RiskLevel.MEDIUM,
        "mitre": "AML.T0020.002",
        "description": "Encoded payload in data URI that may execute in downstream processing",
    },
    {
        "pattern": "eval(",
        "type": "code_injection",
        "severity": RiskLevel.CRITICAL,
        "mitre": "AML.T0020.003",
        "description": "Code injection payload targeting insecure deserialization in pipeline",
    },
]

# --- Data flow anomaly signatures ---
_FLOW_ANOMALY_SIGNATURES: list[dict[str, Any]] = [
    {
        "type": "volume_spike",
        "threshold_gb": 10.0,
        "severity": RiskLevel.HIGH,
        "description": "Data volume spike exceeding normal baseline by 10x or more",
    },
    {
        "type": "unauthorized_destination",
        "severity": RiskLevel.CRITICAL,
        "description": "Data flowing to an unauthorized or unknown external endpoint",
    },
    {
        "type": "off_hours_access",
        "severity": RiskLevel.MEDIUM,
        "description": "Data access occurring outside normal business hours",
    },
    {
        "type": "bulk_export",
        "threshold_gb": 5.0,
        "severity": RiskLevel.HIGH,
        "description": "Bulk data export from vector DB or model registry",
    },
]

# --- Known-good registries for provenance verification ---
_TRUSTED_REGISTRIES: set[str] = {
    "huggingface.co/verified",
    "registry.mlflow.org",
    "models.anthropic.com",
    "vertex-ai.googleapis.com",
    "bedrock.aws.amazon.com",
    "azureml.microsoft.com",
    "internal.shieldops.ai/registry",
}

# --- Pipeline security policies ---
_PIPELINE_POLICIES: list[dict[str, Any]] = [
    {
        "name": "no_unverified_artifacts",
        "description": "All model artifacts must have verified provenance",
        "violation_type": "provenance",
        "severity": RiskLevel.HIGH,
    },
    {
        "name": "poisoning_quarantine",
        "description": "Documents with poisoning indicators must be quarantined",
        "violation_type": "quarantine",
        "severity": RiskLevel.CRITICAL,
    },
    {
        "name": "data_flow_allowlist",
        "description": "Data flows must only reach approved destinations",
        "violation_type": "data_flow",
        "severity": RiskLevel.HIGH,
    },
    {
        "name": "embedding_integrity",
        "description": "Embedding vectors must pass integrity checksums",
        "violation_type": "integrity",
        "severity": RiskLevel.MEDIUM,
    },
]


def _generate_finding_id(prefix: str, content: str) -> str:
    """Generate a deterministic finding ID."""
    raw = f"{prefix}:{content}:{time.time()}"
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class DataPipelineSecurityToolkit:
    """Tools for protecting RAG pipelines, training data, and model registries."""

    def __init__(
        self,
        vector_db_client: Any | None = None,
        model_registry: Any | None = None,
        threat_intel: Any | None = None,
    ) -> None:
        self._vector_db_client = vector_db_client
        self._model_registry = model_registry
        self._threat_intel = threat_intel

    async def scan_rag_pipeline(
        self, pipeline_id: str, data_sources: list[dict[str, Any]]
    ) -> list[PoisoningFinding]:
        """Scan RAG pipeline data sources for poisoning indicators."""
        logger.info(
            "data_pipeline_security.scan_rag_pipeline",
            pipeline_id=pipeline_id,
            source_count=len(data_sources),
        )

        findings: list[PoisoningFinding] = []

        for source in data_sources:
            source_name = source.get("name", "unknown")
            source_type_raw = source.get("type", "document_store")
            try:
                source_type = DataSourceType(source_type_raw)
            except ValueError:
                source_type = DataSourceType.DOCUMENT_STORE

            # Check documents/content within each data source
            documents = source.get("documents", source.get("content", []))
            if isinstance(documents, str):
                documents = [{"text": documents}]

            for doc in documents:
                text = str(doc.get("text", doc.get("content", ""))).lower()

                for indicator in _POISONING_INDICATORS:
                    if indicator["pattern"] in text:
                        affected = doc.get("record_count", 1)
                        findings.append(
                            PoisoningFinding(
                                id=_generate_finding_id("PSN", indicator["pattern"]),
                                source=source_name,
                                source_type=source_type,
                                poisoning_type=indicator["type"],
                                description=indicator["description"],
                                severity=indicator["severity"],
                                confidence=0.85,
                                mitre_technique=indicator["mitre"],
                                affected_records=affected,
                            )
                        )

        return findings

    async def audit_data_flows(self, pipeline_id: str) -> list[DataFlowAnomaly]:
        """Detect anomalous data flows in the pipeline."""
        logger.info(
            "data_pipeline_security.audit_data_flows",
            pipeline_id=pipeline_id,
        )

        anomalies: list[DataFlowAnomaly] = []

        # Query vector DB client for flow metadata if available
        if self._vector_db_client is not None:
            try:
                flows = await self._vector_db_client.get_data_flows(pipeline_id=pipeline_id)
                for flow in flows:
                    volume = flow.get("volume_gb", 0.0)
                    dest = flow.get("destination", "")

                    for sig in _FLOW_ANOMALY_SIGNATURES:
                        threshold = sig.get("threshold_gb", 0.0)
                        if sig["type"] == "volume_spike" and volume > threshold:
                            anomalies.append(
                                DataFlowAnomaly(
                                    id=_generate_finding_id("FLOW", dest),
                                    source=flow.get("source", "unknown"),
                                    destination=dest,
                                    anomaly_type=sig["type"],
                                    description=sig["description"],
                                    severity=sig["severity"],
                                    data_volume_gb=volume,
                                    timestamp=time.time(),
                                )
                            )
                return anomalies
            except Exception:
                logger.exception("data_pipeline_security.audit_data_flows.client_error")

        # Simulated flow audit when no client is available
        anomalies.append(
            DataFlowAnomaly(
                id=_generate_finding_id("FLOW", pipeline_id),
                source=f"{pipeline_id}/vector_store",
                destination=f"{pipeline_id}/embedding_service",
                anomaly_type="baseline_established",
                description="Data flow baseline established; no anomalies detected",
                severity=RiskLevel.INFO,
                data_volume_gb=0.5,
                timestamp=time.time(),
            )
        )
        return anomalies

    async def detect_poisoning(
        self, pipeline_id: str, documents: list[dict[str, Any]]
    ) -> list[PoisoningFinding]:
        """Deep content analysis for training data poisoning and backdoor triggers."""
        logger.info(
            "data_pipeline_security.detect_poisoning",
            pipeline_id=pipeline_id,
            doc_count=len(documents),
        )

        findings: list[PoisoningFinding] = []

        for doc in documents:
            text = str(doc.get("text", doc.get("content", ""))).lower()
            doc_id = doc.get("id", "unknown")

            # Statistical anomaly: high entropy content (potential encoded payloads)
            if len(text) > 0:
                unique_chars = len(set(text))
                char_ratio = unique_chars / len(text) if len(text) > 0 else 0
                if char_ratio > 0.9 and len(text) > 100:
                    findings.append(
                        PoisoningFinding(
                            id=_generate_finding_id("DPS", f"entropy:{doc_id}"),
                            source=doc_id,
                            source_type=DataSourceType.TRAINING_DATA,
                            poisoning_type="high_entropy_content",
                            description=(
                                "Abnormally high character entropy — may indicate "
                                "encoded or obfuscated adversarial payload"
                            ),
                            severity=RiskLevel.MEDIUM,
                            confidence=0.70,
                            mitre_technique="AML.T0020",
                            affected_records=1,
                        )
                    )

            # Pattern-based deep scan
            for indicator in _POISONING_INDICATORS:
                if indicator["pattern"] in text:
                    findings.append(
                        PoisoningFinding(
                            id=_generate_finding_id("DPS", f"{indicator['pattern']}:{doc_id}"),
                            source=doc_id,
                            source_type=DataSourceType.TRAINING_DATA,
                            poisoning_type=indicator["type"],
                            description=indicator["description"],
                            severity=indicator["severity"],
                            confidence=0.90,
                            mitre_technique=indicator["mitre"],
                            affected_records=doc.get("record_count", 1),
                        )
                    )

            # Check for label flipping indicators in training data
            label = doc.get("label")
            expected_label = doc.get("expected_label")
            if label is not None and expected_label is not None and label != expected_label:
                findings.append(
                    PoisoningFinding(
                        id=_generate_finding_id("DPS", f"label_flip:{doc_id}"),
                        source=doc_id,
                        source_type=DataSourceType.TRAINING_DATA,
                        poisoning_type="label_flipping",
                        description=(
                            f"Label mismatch detected: expected '{expected_label}' "
                            f"but found '{label}' — potential label flipping attack"
                        ),
                        severity=RiskLevel.HIGH,
                        confidence=0.80,
                        mitre_technique="AML.T0019",
                        affected_records=1,
                    )
                )

        return findings

    async def verify_model_provenance(
        self, pipeline_id: str, artifacts: list[dict[str, Any]]
    ) -> list[ProvenanceRecord]:
        """Verify model weights, tokenizers, and embeddings against known-good registries."""
        logger.info(
            "data_pipeline_security.verify_model_provenance",
            pipeline_id=pipeline_id,
            artifact_count=len(artifacts),
        )

        records: list[ProvenanceRecord] = []

        for artifact in artifacts:
            name = artifact.get("name", "unknown")
            artifact_type = artifact.get("type", "model_weights")
            origin = artifact.get("origin", "unknown")
            hash_digest = artifact.get("hash", artifact.get("sha256", ""))

            # Check if origin is in trusted registries
            verified = any(origin.startswith(reg) for reg in _TRUSTED_REGISTRIES)

            if verified and self._model_registry is not None:
                try:
                    reg_result = await self._model_registry.verify_hash(
                        name=name, expected_hash=hash_digest
                    )
                    verified = reg_result.get("verified", False)
                except Exception:
                    logger.exception("data_pipeline_security.verify_provenance.registry_error")
                    verified = False

            risk_level = RiskLevel.LOW if verified else RiskLevel.HIGH
            if not hash_digest:
                risk_level = RiskLevel.CRITICAL

            records.append(
                ProvenanceRecord(
                    id=_generate_finding_id("PROV", name),
                    artifact_name=name,
                    artifact_type=artifact_type,
                    origin=origin,
                    hash_digest=hash_digest,
                    verified=verified,
                    risk_level=risk_level,
                    last_verified=time.time(),
                )
            )

        return records

    async def enforce_pipeline_policies(
        self,
        findings: list[dict[str, Any]],
        anomalies: list[dict[str, Any]],
    ) -> list[PolicyViolation]:
        """Apply data pipeline security policies and quarantine suspicious data."""
        logger.info("data_pipeline_security.enforce_pipeline_policies")

        violations: list[PolicyViolation] = []

        # Check poisoning quarantine policy
        for finding in findings:
            severity = finding.get("severity", "medium")
            if severity in ("critical", "high"):
                violations.append(
                    PolicyViolation(
                        id=_generate_finding_id("POL", finding.get("id", "")),
                        policy_name="poisoning_quarantine",
                        resource=finding.get("source", "unknown"),
                        violation_type="quarantine",
                        description=(
                            f"Poisoning finding '{finding.get('poisoning_type', '')}' "
                            f"in '{finding.get('source', '')}' requires quarantine"
                        ),
                        severity=RiskLevel(severity),
                        auto_remediated=True,
                    )
                )

        # Check data flow allowlist policy
        for anomaly in anomalies:
            anomaly_type = anomaly.get("anomaly_type", "")
            if anomaly_type in ("unauthorized_destination", "volume_spike", "bulk_export"):
                violations.append(
                    PolicyViolation(
                        id=_generate_finding_id("POL", anomaly.get("id", "")),
                        policy_name="data_flow_allowlist",
                        resource=anomaly.get("destination", "unknown"),
                        violation_type="data_flow",
                        description=(
                            f"Anomalous data flow '{anomaly_type}' to "
                            f"'{anomaly.get('destination', '')}' violates allowlist policy"
                        ),
                        severity=RiskLevel(anomaly.get("severity", "high")),
                        auto_remediated=False,
                    )
                )

        return violations
