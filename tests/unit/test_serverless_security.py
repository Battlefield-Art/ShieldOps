"""Tests for serverless_security."""

from __future__ import annotations

from shieldops.agents.serverless_security.models import (
    ServerlessPlatform,
    ServerlessSecurityState,
    ServerlessStage,
    ServerlessThreatType,
)


class TestEnums:
    def test_serverlessplatform(self) -> None:
        assert ServerlessPlatform.AWS_LAMBDA == "aws_lambda"
        assert len(ServerlessPlatform) >= 3

    def test_serverlessstage(self) -> None:
        assert ServerlessStage.DISCOVER_FUNCTIONS == "discover_functions"
        assert len(ServerlessStage) >= 3

    def test_serverlessthreattype(self) -> None:
        assert ServerlessThreatType.OVER_PRIVILEGED == "over_privileged"
        assert len(ServerlessThreatType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ServerlessSecurityState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ServerlessSecurityState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
