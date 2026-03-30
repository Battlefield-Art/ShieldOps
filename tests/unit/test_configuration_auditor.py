"""Tests for configuration_auditor."""

from __future__ import annotations

from shieldops.agents.configuration_auditor.models import (
    CAStage,
    ConfigSource,
    ConfigurationAuditorState,
    DriftSeverity,
)


class TestEnums:
    def test_stage(self) -> None:
        assert CAStage.COLLECT_CONFIGS == "collect_configs"
        assert len(CAStage) >= 3

    def test_config_source(self) -> None:
        assert ConfigSource.KUBERNETES == "kubernetes"
        assert len(ConfigSource) >= 3

    def test_drift_severity(self) -> None:
        assert DriftSeverity.CRITICAL == "critical"
        assert len(DriftSeverity) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ConfigurationAuditorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ConfigurationAuditorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
