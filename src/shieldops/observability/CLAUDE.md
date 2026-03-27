# observability/ — Observability & Telemetry Engines

232 engine modules for alert intelligence, telemetry, SLI/SLO, and OTel pipeline management.

## Domains
- Alert intelligence + correlation
- OpenTelemetry pipeline: autoscaler, sampling, attribution, cost
- SLO-aware sampling + cardinality control
- eBPF telemetry + collector fleet management
- Backpressure analysis + span-to-metric conversion

## OTel Integration
- `otel/` — OpenTelemetry tools (kafka_receiver, pipeline_processor, collector_manager, python_instrumentor)
- `tracing.py` — Distributed tracing initialization
- `metrics.py` — Prometheus metrics collection

## Engine Pattern
Same as `security/CLAUDE.md` — 3 StrEnums, 3 Pydantic models, Engine class with ring-buffer storage.

## Key Files
- `factory.py` — Creates observability source connections
- `langsmith.py` — LangSmith agent tracing integration
