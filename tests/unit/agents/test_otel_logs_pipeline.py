"""Tests for shieldops.agents.otel_logs_pipeline."""

from __future__ import annotations

from shieldops.agents.otel_logs_pipeline.models import (
    LogFormat,
    LogSource,
    LogStage,
    OTelLogsPipelineState,
)


class TestEnums:
    def test_logstage_discover(self):
        assert LogStage.DISCOVER == "discover"

    def test_logstage_configure(self):
        assert LogStage.CONFIGURE == "configure"

    def test_logstage_parse(self):
        assert LogStage.PARSE == "parse"

    def test_logstage_validate(self):
        assert LogStage.VALIDATE == "validate"

    def test_logsource_filelog(self):
        assert LogSource.FILELOG == "filelog"

    def test_logsource_syslog(self):
        assert LogSource.SYSLOG == "syslog"

    def test_logsource_otlp(self):
        assert LogSource.OTLP == "otlp"

    def test_logsource_kafka(self):
        assert LogSource.KAFKA == "kafka"

    def test_logformat_json(self):
        assert LogFormat.JSON == "json"

    def test_logformat_text(self):
        assert LogFormat.TEXT == "text"

    def test_logformat_regex(self):
        assert LogFormat.REGEX == "regex"

    def test_logformat_csv(self):
        assert LogFormat.CSV == "csv"


class TestModels:
    def test_state_defaults(self):
        s = OTelLogsPipelineState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.otel_logs_pipeline.graph import (
            create_otel_logs_pipeline_graph,
        )

        sg = create_otel_logs_pipeline_graph()
        assert sg.compile() is not None
