"""Model Security Agent — Tool functions for model integrity and supply chain security."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    BackdoorIndicator,
    IntegrityAssessment,
    ModelRecord,
    ProvenanceRecord,
    ScanVerdict,
    ThreatLevel,
)

logger = structlog.get_logger()

# Simulated model registry data
_MODEL_REGISTRY: list[dict[str, Any]] = [
    {
        "model_id": "mdl-gpt-finetune-001",
        "name": "customer-support-gpt",
        "version": "2.1.0",
        "framework": "transformers",
        "source_registry": "huggingface",
        "file_hash": "sha256:a1b2c3d4e5f6...",
        "file_size_mb": 1340.0,
        "last_scanned": "2026-03-20T10:00:00Z",
        "tags": ["production", "customer-facing", "fine-tuned"],
    },
    {
        "model_id": "mdl-fraud-detect-002",
        "name": "fraud-detection-xgb",
        "version": "3.0.1",
        "framework": "xgboost",
        "source_registry": "internal-mlflow",
        "file_hash": "sha256:f7e8d9c0b1a2...",
        "file_size_mb": 45.0,
        "last_scanned": "2026-03-18T14:30:00Z",
        "tags": ["production", "financial", "compliance-critical"],
    },
    {
        "model_id": "mdl-embed-003",
        "name": "text-embeddings-custom",
        "version": "1.0.0",
        "framework": "pytorch",
        "source_registry": "s3-artifacts",
        "file_hash": "sha256:c3d4e5f6a7b8...",
        "file_size_mb": 890.0,
        "last_scanned": "2026-03-15T08:00:00Z",
        "tags": ["staging", "rag-pipeline", "third-party-base"],
    },
    {
        "model_id": "mdl-anomaly-004",
        "name": "network-anomaly-detector",
        "version": "1.2.0",
        "framework": "tensorflow",
        "source_registry": "gcr-ml-artifacts",
        "file_hash": "sha256:d5e6f7a8b9c0...",
        "file_size_mb": 210.0,
        "last_scanned": "2026-03-10T16:45:00Z",
        "tags": ["production", "security", "auto-deployed"],
    },
    {
        "model_id": "mdl-summarizer-005",
        "name": "doc-summarizer-bart",
        "version": "0.9.0",
        "framework": "transformers",
        "source_registry": "huggingface",
        "file_hash": "sha256:e7f8a9b0c1d2...",
        "file_size_mb": 1620.0,
        "last_scanned": "2026-02-28T12:00:00Z",
        "tags": ["dev", "experimental", "community-model"],
    },
]

# Backdoor indicator patterns by framework
_BACKDOOR_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "transformers": [
        {
            "indicator_type": "weight_perturbation",
            "description": "Anomalous weight distribution in attention layers",
            "trigger_pattern": "specific_token_sequence",
            "affected_layers": ["encoder.layer.11.attention", "encoder.layer.10.attention"],
            "mitre_technique": "AML.T0020",
            "base_confidence": 0.35,
        },
        {
            "indicator_type": "training_data_poisoning",
            "description": "Statistical anomaly in output distribution for rare input patterns",
            "trigger_pattern": "rare_token_combination",
            "affected_layers": ["classifier", "lm_head"],
            "mitre_technique": "AML.T0019",
            "base_confidence": 0.25,
        },
    ],
    "pytorch": [
        {
            "indicator_type": "unsafe_deserialization",
            "description": "Model uses pickle-based serialization vulnerable to code execution",
            "trigger_pattern": "pickle.loads",
            "affected_layers": ["serialization"],
            "mitre_technique": "AML.T0010",
            "base_confidence": 0.85,
        },
        {
            "indicator_type": "hidden_payload",
            "description": "Suspicious non-tensor data embedded in model checkpoint",
            "trigger_pattern": "embedded_code_object",
            "affected_layers": ["metadata", "extra_state"],
            "mitre_technique": "AML.T0010",
            "base_confidence": 0.60,
        },
    ],
    "tensorflow": [
        {
            "indicator_type": "graph_manipulation",
            "description": "Unexpected ops in saved model graph",
            "trigger_pattern": "custom_op_injection",
            "affected_layers": ["saved_model.pb"],
            "mitre_technique": "AML.T0020",
            "base_confidence": 0.40,
        },
    ],
    "xgboost": [
        {
            "indicator_type": "feature_manipulation",
            "description": "Tree splits on features not in training spec",
            "trigger_pattern": "phantom_feature_split",
            "affected_layers": ["tree_0", "tree_1"],
            "mitre_technique": "AML.T0019",
            "base_confidence": 0.30,
        },
    ],
}

# Provenance profiles per registry
_PROVENANCE_PROFILES: dict[str, dict[str, Any]] = {
    "huggingface": {
        "publisher": "community/verified",
        "signing_key": "hf-signing-key-v2",
        "signature_valid": True,
        "supply_chain_verified": False,
        "training_pipeline": "unknown",
        "license": "Apache-2.0",
    },
    "internal-mlflow": {
        "publisher": "internal-ml-team",
        "signing_key": "internal-cosign-v1",
        "signature_valid": True,
        "supply_chain_verified": True,
        "training_pipeline": "cicd-ml-pipeline-v3",
        "license": "proprietary",
    },
    "s3-artifacts": {
        "publisher": "unknown",
        "signing_key": "",
        "signature_valid": False,
        "supply_chain_verified": False,
        "training_pipeline": "unknown",
        "license": "unknown",
    },
    "gcr-ml-artifacts": {
        "publisher": "platform-team",
        "signing_key": "gcp-kms-cosign-v1",
        "signature_valid": True,
        "supply_chain_verified": True,
        "training_pipeline": "vertex-pipeline-v2",
        "license": "proprietary",
    },
}

# Threat level thresholds
_RISK_THRESHOLDS: dict[str, float] = {
    "critical": 85.0,
    "high": 65.0,
    "medium": 40.0,
    "low": 20.0,
}


def _generate_indicator_id(model_id: str, indicator_type: str, index: int) -> str:
    """Generate a deterministic backdoor indicator ID."""
    raw = f"{model_id}:{indicator_type}:{index}"
    return f"BDI-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class ModelSecurityToolkit:
    """Tools for model integrity verification and supply chain security."""

    def __init__(
        self,
        model_registry_client: Any | None = None,
        provenance_service: Any | None = None,
        scanning_engine: Any | None = None,
    ) -> None:
        self._model_registry_client = model_registry_client
        self._provenance_service = provenance_service
        self._scanning_engine = scanning_engine

    async def scan_models(self, target_models: list[str] | None = None) -> list[ModelRecord]:
        """Scan and discover model artifacts from registries.

        Uses model registry client if available, otherwise returns
        simulated model records for demonstration.
        """
        logger.info("model_security.scan_models", targets=target_models)

        if self._model_registry_client is not None:
            try:
                raw = await self._model_registry_client.list_models(filters=target_models)
                return [ModelRecord(**m) for m in raw]
            except Exception:
                logger.exception("model_security.scan_models.registry_error")

        # Simulated scan — filter by target if specified
        records = _MODEL_REGISTRY
        if target_models:
            records = [
                r for r in records if r["model_id"] in target_models or r["name"] in target_models
            ]
        if not records:
            records = _MODEL_REGISTRY

        return [ModelRecord(**r) for r in records]

    async def verify_provenance(self, models: list[ModelRecord]) -> list[ProvenanceRecord]:
        """Verify provenance and supply chain integrity for each model.

        Checks signature validity, publisher identity, and training pipeline
        traceability using provenance service if available.
        """
        logger.info(
            "model_security.verify_provenance",
            model_count=len(models),
        )

        if self._provenance_service is not None:
            try:
                raw = await self._provenance_service.verify_batch(
                    model_ids=[m.model_id for m in models]
                )
                return [ProvenanceRecord(**p) for p in raw]
            except Exception:
                logger.exception("model_security.verify_provenance.service_error")

        # Simulated provenance checks
        records: list[ProvenanceRecord] = []
        for model in models:
            profile = _PROVENANCE_PROFILES.get(
                model.source_registry,
                _PROVENANCE_PROFILES["s3-artifacts"],
            )

            vulns: list[str] = []
            if not profile["signature_valid"]:
                vulns.append("unsigned-artifact")
            if not profile["supply_chain_verified"]:
                vulns.append("unverified-supply-chain")
            if profile["training_pipeline"] == "unknown":
                vulns.append("unknown-training-provenance")

            records.append(
                ProvenanceRecord(
                    model_id=model.model_id,
                    publisher=profile["publisher"],
                    signing_key=profile["signing_key"],
                    signature_valid=profile["signature_valid"],
                    supply_chain_verified=profile["supply_chain_verified"],
                    training_data_hash=model.file_hash,
                    training_pipeline=profile["training_pipeline"],
                    license=profile["license"],
                    known_vulnerabilities=vulns,
                )
            )

        return records

    async def detect_backdoors(self, models: list[ModelRecord]) -> list[BackdoorIndicator]:
        """Detect potential backdoor indicators in model artifacts.

        Analyzes weight distributions, serialization safety, and hidden
        payloads using scanning engine if available.
        """
        logger.info(
            "model_security.detect_backdoors",
            model_count=len(models),
        )

        if self._scanning_engine is not None:
            try:
                raw = await self._scanning_engine.scan_backdoors(
                    model_ids=[m.model_id for m in models]
                )
                return [BackdoorIndicator(**b) for b in raw]
            except Exception:
                logger.exception("model_security.detect_backdoors.engine_error")

        # Simulated backdoor detection
        indicators: list[BackdoorIndicator] = []
        idx = 0

        for model in models:
            patterns = _BACKDOOR_PATTERNS.get(model.framework, [])
            for pattern in patterns:
                noise = random.gauss(0, 0.08)
                confidence = max(0.0, min(1.0, pattern["base_confidence"] + noise))

                # Determine threat level from confidence
                if confidence >= 0.75:
                    threat_level = ThreatLevel.CRITICAL
                elif confidence >= 0.55:
                    threat_level = ThreatLevel.HIGH
                elif confidence >= 0.35:
                    threat_level = ThreatLevel.MEDIUM
                else:
                    threat_level = ThreatLevel.LOW

                indicators.append(
                    BackdoorIndicator(
                        indicator_id=_generate_indicator_id(
                            model.model_id, pattern["indicator_type"], idx
                        ),
                        model_id=model.model_id,
                        indicator_type=pattern["indicator_type"],
                        description=pattern["description"],
                        confidence=round(confidence, 3),
                        trigger_pattern=pattern["trigger_pattern"],
                        affected_layers=pattern["affected_layers"],
                        mitre_technique=pattern["mitre_technique"],
                        threat_level=threat_level,
                    )
                )
                idx += 1

        return indicators

    async def assess_integrity(
        self,
        models: list[ModelRecord],
        provenance: list[ProvenanceRecord],
        backdoor_indicators: list[BackdoorIndicator],
    ) -> list[IntegrityAssessment]:
        """Assess overall integrity of each model.

        Combines provenance verification, backdoor detection, and hash
        verification into a per-model integrity assessment.
        """
        logger.info(
            "model_security.assess_integrity",
            model_count=len(models),
        )

        provenance_map = {p.model_id: p for p in provenance}
        indicator_map: dict[str, list[BackdoorIndicator]] = {}
        for ind in backdoor_indicators:
            indicator_map.setdefault(ind.model_id, []).append(ind)

        assessments: list[IntegrityAssessment] = []

        for model in models:
            prov = provenance_map.get(model.model_id)
            indicators = indicator_map.get(model.model_id, [])

            # Hash verification
            hash_verified = prov.signature_valid if prov else False

            # Weight drift — simulated score based on model age and framework
            drift_noise = random.gauss(0, 5.0)
            base_drift = 15.0 if model.framework in ("pytorch", "tensorflow") else 5.0
            weight_drift = round(max(0.0, min(100.0, base_drift + drift_noise)), 1)

            # Architecture anomalies
            anomalies: list[str] = []
            if indicators:
                max_confidence = max(i.confidence for i in indicators)
                if max_confidence >= 0.5:
                    anomalies.append(f"high_confidence_backdoor_indicator({max_confidence:.2f})")
            if prov and not prov.supply_chain_verified:
                anomalies.append("unverified_supply_chain")
            if prov and prov.training_pipeline == "unknown":
                anomalies.append("unknown_training_provenance")

            # Serialization safety
            serialization_safe = model.framework not in ("pytorch",)
            pickle_result = "unsafe_pickle_detected" if not serialization_safe else "safe"

            # Risk score calculation
            risk = 0.0
            if not hash_verified:
                risk += 25.0
            risk += weight_drift * 0.3
            if indicators:
                risk += max(i.confidence for i in indicators) * 40.0
            if not serialization_safe:
                risk += 15.0
            if anomalies:
                risk += len(anomalies) * 5.0
            risk = round(min(100.0, max(0.0, risk)), 1)

            # Verdict
            if risk >= _RISK_THRESHOLDS["critical"]:
                verdict = ScanVerdict.COMPROMISED
            elif risk >= _RISK_THRESHOLDS["high"] or risk >= _RISK_THRESHOLDS["medium"]:
                verdict = ScanVerdict.SUSPICIOUS
            elif risk >= _RISK_THRESHOLDS["low"]:
                verdict = ScanVerdict.CLEAN
            else:
                verdict = ScanVerdict.CLEAN

            assessments.append(
                IntegrityAssessment(
                    model_id=model.model_id,
                    hash_verified=hash_verified,
                    weight_drift_score=weight_drift,
                    architecture_anomalies=anomalies,
                    serialization_safe=serialization_safe,
                    pickle_scan_result=pickle_result,
                    verdict=verdict,
                    risk_score=risk,
                )
            )

        return assessments

    def evaluate_risks(
        self,
        assessments: list[IntegrityAssessment],
        backdoor_indicators: list[BackdoorIndicator],
        provenance: list[ProvenanceRecord],
    ) -> tuple[float, ScanVerdict, list[dict[str, Any]]]:
        """Evaluate overall risk across all scanned models.

        Aggregates per-model assessments into an overall risk score,
        verdict, and list of risk factors.
        """
        logger.info(
            "model_security.evaluate_risks",
            assessment_count=len(assessments),
        )

        if not assessments:
            return 0.0, ScanVerdict.UNKNOWN, []

        risk_factors: list[dict[str, Any]] = []

        # Aggregate risk from assessments
        max_risk = max(a.risk_score for a in assessments)
        avg_risk = sum(a.risk_score for a in assessments) / len(assessments)
        compromised_count = sum(1 for a in assessments if a.verdict == ScanVerdict.COMPROMISED)
        suspicious_count = sum(1 for a in assessments if a.verdict == ScanVerdict.SUSPICIOUS)

        # Risk factor: compromised models
        if compromised_count > 0:
            risk_factors.append(
                {
                    "factor": "compromised_models",
                    "severity": ThreatLevel.CRITICAL.value,
                    "detail": f"{compromised_count} model(s) flagged as compromised",
                    "model_ids": [
                        a.model_id for a in assessments if a.verdict == ScanVerdict.COMPROMISED
                    ],
                }
            )

        # Risk factor: suspicious models
        if suspicious_count > 0:
            risk_factors.append(
                {
                    "factor": "suspicious_models",
                    "severity": ThreatLevel.HIGH.value,
                    "detail": f"{suspicious_count} model(s) flagged as suspicious",
                    "model_ids": [
                        a.model_id for a in assessments if a.verdict == ScanVerdict.SUSPICIOUS
                    ],
                }
            )

        # Risk factor: unsigned artifacts
        unsigned = [p for p in provenance if not p.signature_valid]
        if unsigned:
            risk_factors.append(
                {
                    "factor": "unsigned_artifacts",
                    "severity": ThreatLevel.HIGH.value,
                    "detail": f"{len(unsigned)} model(s) lack valid signatures",
                    "model_ids": [p.model_id for p in unsigned],
                }
            )

        # Risk factor: high-confidence backdoor indicators
        critical_indicators = [i for i in backdoor_indicators if i.confidence >= 0.6]
        if critical_indicators:
            risk_factors.append(
                {
                    "factor": "backdoor_indicators",
                    "severity": ThreatLevel.CRITICAL.value,
                    "detail": (
                        f"{len(critical_indicators)} high-confidence backdoor indicator(s) detected"
                    ),
                    "indicator_ids": [i.indicator_id for i in critical_indicators],
                }
            )

        # Risk factor: unsafe deserialization
        unsafe_serial = [a for a in assessments if not a.serialization_safe]
        if unsafe_serial:
            risk_factors.append(
                {
                    "factor": "unsafe_deserialization",
                    "severity": ThreatLevel.HIGH.value,
                    "detail": (
                        f"{len(unsafe_serial)} model(s) use unsafe deserialization (pickle)"
                    ),
                    "model_ids": [a.model_id for a in unsafe_serial],
                }
            )

        # Overall risk: weighted combination of max and avg
        overall_risk = round(max_risk * 0.6 + avg_risk * 0.4, 1)
        overall_risk = min(100.0, max(0.0, overall_risk))

        # Overall verdict
        if compromised_count > 0 or overall_risk >= _RISK_THRESHOLDS["critical"]:
            overall_verdict = ScanVerdict.COMPROMISED
        elif (
            suspicious_count > 0
            or overall_risk >= _RISK_THRESHOLDS["high"]
            or overall_risk >= _RISK_THRESHOLDS["medium"]
        ):
            overall_verdict = ScanVerdict.SUSPICIOUS
        else:
            overall_verdict = ScanVerdict.CLEAN

        return overall_risk, overall_verdict, risk_factors
