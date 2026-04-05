"""Observability configuration."""

from pydantic import BaseModel


class ObservabilityConfig(BaseModel):
    """Observability, tracing, and monitoring settings."""

    langsmith_api_key: str = ""
    langsmith_project: str = "shieldops"
    langsmith_enabled: bool = False
    otel_exporter_endpoint: str = "http://localhost:4317"
    otel_endpoint: str = "http://localhost:4317"
    prometheus_url: str = "http://localhost:9090"
    splunk_url: str = ""
    splunk_token: str = ""
    splunk_index: str = "main"
    splunk_verify_ssl: bool = True
    datadog_api_key: str = ""
    datadog_app_key: str = ""
    datadog_site: str = "datadoghq.com"
    jaeger_url: str = ""
    newrelic_api_key: str = ""
    newrelic_account_id: str = ""
    elastic_url: str = ""
    elastic_api_key: str = ""
    tracing_enabled: bool = False
