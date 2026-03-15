# OTel Pipeline Agent

Autonomous OpenTelemetry pipeline management agent that discovers services, configures collectors, validates telemetry flow, and monitors pipeline health across your infrastructure.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────────┐
│  Discover   │────▶│  Configure   │────▶│   Validate   │────▶│   Monitor   │
│  Services   │     │  Collectors  │     │  Pipelines   │     │   Health    │
└─────────────┘     └──────────────┘     └──────────────┘     └─────────────┘
       │                    │                    │                    │
       ▼                    ▼                    ▼                    ▼
  K8s/Cloud API      Collector YAML       Trace/Metric        Pipeline KPIs
  Service Mesh       Receiver Config      Validation          Backpressure
  Auto-detect        Processor Chain      End-to-End          Cost Tracking
```

## Workflow

1. **Discover** -- Scans Kubernetes namespaces, cloud services, and service meshes to identify uninstrumented or misconfigured services. Uses eBPF probes for auto-detection.
2. **Configure** -- Generates OTel Collector configurations including receivers (OTLP, Kafka, Prometheus), processors (batch, filter, tail sampling), and exporters targeting your backends.
3. **Validate** -- Sends synthetic traces and metrics through the pipeline, verifying end-to-end delivery, data fidelity, and latency. Checks for dropped spans and metric gaps.
4. **Monitor** -- Continuously tracks collector fleet health: CPU/memory usage, queue depths, backpressure signals, and export error rates. Triggers autoscaling when thresholds are breached.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `OTEL_COLLECTOR_ENDPOINT` | Collector management API | `http://localhost:4317` |
| `OTEL_KAFKA_BROKERS` | Kafka brokers for telemetry ingestion | `localhost:9092` |
| `OTEL_SAMPLING_RATE` | Default tail sampling rate | `0.1` |
| `OTEL_MAX_QUEUE_SIZE` | Max exporter queue before backpressure | `5000` |
| `OTEL_AUTOSCALE_THRESHOLD` | CPU % to trigger collector scaling | `70` |

## Usage

```bash
# Trigger via CLI
shieldops run-agent otel_pipeline --namespace production

# Trigger via API
curl -X POST /api/v1/agents/otel_pipeline/run \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"namespace": "production", "action": "discover_and_configure"}'
```

The agent returns a structured report with discovered services, applied configurations, validation results, and ongoing health metrics.
