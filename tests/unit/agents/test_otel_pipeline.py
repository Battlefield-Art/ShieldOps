"""Tests for shieldops.agents.otel_pipeline."""

from __future__ import annotations

from shieldops.agents.otel_pipeline.models import (
    CollectorMode,
    ExporterTarget,
    OTelPipelineState,
    PipelineStage,
)


class TestEnums:
    def test_pipelinestage_discover(self):
        assert PipelineStage.DISCOVER == "discover"

    def test_pipelinestage_configure(self):
        assert PipelineStage.CONFIGURE == "configure"

    def test_pipelinestage_validate(self):
        assert PipelineStage.VALIDATE == "validate"

    def test_pipelinestage_deploy(self):
        assert PipelineStage.DEPLOY == "deploy"

    def test_collectormode_daemonset(self):
        assert CollectorMode.DAEMONSET == "daemonset"

    def test_collectormode_sidecar(self):
        assert CollectorMode.SIDECAR == "sidecar"

    def test_collectormode_gateway(self):
        assert CollectorMode.GATEWAY == "gateway"

    def test_collectormode_standalone(self):
        assert CollectorMode.STANDALONE == "standalone"

    def test_exportertarget_shieldops(self):
        assert ExporterTarget.SHIELDOPS == "shieldops"

    def test_exportertarget_splunk_hec(self):
        assert ExporterTarget.SPLUNK_HEC == "splunk_hec"

    def test_exportertarget_otlp_http(self):
        assert ExporterTarget.OTLP_HTTP == "otlp_http"

    def test_exportertarget_otlp_grpc(self):
        assert ExporterTarget.OTLP_GRPC == "otlp_grpc"


class TestModels:
    def test_state_exists(self):
        assert OTelPipelineState is not None


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.otel_pipeline.graph import build_graph
        from shieldops.agents.otel_pipeline.tools import OTelPipelineToolkit

        sg = build_graph(OTelPipelineToolkit())
        assert sg.compile() is not None
