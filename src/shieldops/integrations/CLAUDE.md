# integrations/ — External Tool Integrations

Integrations with external monitoring, CI/CD, and communication tools.

## Sub-packages
- `otel/` — OpenTelemetry tools (kafka_receiver, pipeline_processor, collector_manager, python_instrumentor)
- `grafana/` — Grafana Mimir + Loki integration
- `dynatrace/` — Dynatrace problems integration
- `ci_cd/` — CI/CD hooks (red team, deployment)
- `observability/` — Observability dashboards

## Pattern
Each integration implements async client methods for its external service.
