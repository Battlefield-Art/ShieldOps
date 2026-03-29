"""Tests for quantum_risk_assessor."""

from __future__ import annotations

from shieldops.agents.quantum_risk_assessor.models import (
    CryptoAlgorithmType,
    QuantumAssessmentStage,
    QuantumRiskAssessorState,
    QuantumThreatLevel,
)


class TestEnums:
    def test_scan_stage(self) -> None:
        assert QuantumAssessmentStage.SCAN_INFRASTRUCTURE == "scan_infrastructure"
        assert len(QuantumAssessmentStage) >= 3

    def test_quantum_threat_level(self) -> None:
        assert QuantumThreatLevel.CRITICAL == "critical"
        assert len(QuantumThreatLevel) >= 3

    def test_crypto_algorithm_type(self) -> None:
        assert CryptoAlgorithmType.RSA == "rsa"
        assert len(CryptoAlgorithmType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = QuantumRiskAssessorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = QuantumRiskAssessorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
