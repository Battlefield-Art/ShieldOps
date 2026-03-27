# Manage OTel Skill

Manage OpenTelemetry pipelines — deploy collectors, configure Kafka ingestion, auto-instrument services, monitor pipeline health.

## Usage
`/manage-otel <action> [options]`

Actions: `deploy`, `instrument`, `health`, `configure`, `discover`

## Process

### Deploy Collector
1. **Check cluster access**: Verify K8s context and namespace
2. **Generate collector config**: Use `CollectorManager` from `src/shieldops/integrations/otel/collector_manager.py`
3. **Choose deployment mode**:
   - `daemonset` — one collector per node (recommended for full coverage)
   - `deployment` — centralized gateway collector
   - `sidecar` — per-pod collector injection
4. **Dry-run first**: Always preview config before applying
5. **Deploy**: Apply manifest to cluster

```python
from shieldops.integrations.otel.collector_manager import CollectorManager, CollectorSpec, DeploymentMode

mgr = CollectorManager(k8s_client=k8s)
spec = CollectorSpec(
    name="shieldops-otel",
    namespace="shieldops",
    mode=DeploymentMode.DAEMONSET,
    receivers=["otlp", "kafka"],
    exporters=["otlp"],
    resource_cpu="200m",
    resource_memory="256Mi",
)
result = await mgr.deploy(spec, dry_run=True)
```

### Auto-Instrument Python Service
1. **Detect libraries**: Scan service for supported libraries (requests, flask, django, fastapi, sqlalchemy, redis, etc.)
2. **Generate plan**: Create instrumentation plan based on detected libraries
3. **Choose mode**: `full` (all libraries), `selective` (specific libraries), `minimal` (core only)
4. **Apply**: Add K8s annotations for OTel operator injection or generate env vars for manual setup

```python
from shieldops.integrations.otel.python_instrumentor import PythonInstrumentor, InstrumentationConfig

instrumentor = PythonInstrumentor(
    config=InstrumentationConfig(
        service_name="api-server",
        environment="production",
        exporter_endpoint="http://otel-collector:4317",
    )
)
plan = instrumentor.get_instrumentation_plan()
annotations = instrumentor.generate_k8s_annotation()
env_vars = instrumentor.generate_env_vars()
```

### Configure Kafka Ingestion
1. **List topics**: Discover Kafka topics carrying telemetry data
2. **Configure receiver**: Set up Kafka receiver with topic patterns
3. **Set encoding**: `otlp_proto` (recommended), `otlp_json`, `raw_json`
4. **Wire processors**: batch → memory_limiter → resourcedetection
5. **Validate pipeline**: Check all references are valid

```python
from shieldops.integrations.otel.kafka_receiver import KafkaOTelReceiver, ReceiverConfig

receiver = KafkaOTelReceiver(
    config=ReceiverConfig(
        brokers=["kafka:9092"],
        topics=["otel.traces", "otel.metrics", "otel.logs"],
        encoding="otlp_proto",
    )
)
```

### Monitor Pipeline Health
Use the OTel Pipeline agent or engines:

```python
from shieldops.agents.otel_pipeline.runner import OTelPipelineRunner

runner = OTelPipelineRunner()
result = await runner.run(cluster_name="prod", namespace="default")
```

## Agents Used
- `otel_pipeline` — OTel pipeline health monitoring and optimization
- `otel_collector_manager` — Collector lifecycle management (deploy, upgrade, scale)
- `otel_deployer` — K8s deployment orchestration (DaemonSet, Deployment, Sidecar)
- `otel_semantic` — Semantic convention enforcement and naming standards
- `otel_tail_sampling` — Tail-based sampling policy management
- `otel_metrics_pipeline` — Golden signals, aggregation, SLI calculation
- `otel_logs_pipeline` — Log quality, trace-log correlation, cost optimization
- `telemetry_optimizer` — End-to-end telemetry optimization
- `telemetry_analyzer` — Telemetry analysis module
- `log_analyzer` — AI-powered log anomaly detection

## Key Files
- `src/shieldops/agents/otel_pipeline/` — OTel Pipeline LangGraph agent
- `src/shieldops/agents/otel_collector_manager/` — Collector manager agent
- `src/shieldops/agents/otel_deployer/` — Deployment orchestrator agent
- `src/shieldops/agents/otel_semantic/` — Semantic conventions agent
- `src/shieldops/agents/otel_tail_sampling/` — Tail sampling agent
- `src/shieldops/agents/otel_metrics_pipeline/` — Metrics pipeline agent
- `src/shieldops/agents/otel_logs_pipeline/` — Logs pipeline agent
- `src/shieldops/agents/telemetry_optimizer/` — Telemetry optimizer agent
- `src/shieldops/integrations/otel/kafka_receiver.py` — Kafka-based OTel receiver
- `src/shieldops/integrations/otel/pipeline_processor.py` — Telemetry processors
- `src/shieldops/integrations/otel/collector_manager.py` — Collector lifecycle management
- `src/shieldops/integrations/otel/python_instrumentor.py` — Python auto-instrumentation
- `src/shieldops/observability/` — 232 observability engines
- `src/shieldops/observability/otel_pipeline_health_engine.py` — Pipeline health analytics
- `src/shieldops/observability/otel_kafka_ingestion_engine.py` — Kafka ingestion analytics
- `src/shieldops/observability/auto_instrumentation_engine.py` — Instrumentation coverage

## Conventions
- Always dry-run before deploying collectors
- Use `memory_limiter` processor to prevent OOM
- Default to full-fidelity tracing (no sampling) — incident data should never be dropped
- All collector configs must include resource limits
- Kafka topics follow pattern: `otel.{signal_type}` (traces, metrics, logs)
- Semantic conventions enforced via `otel_semantic` agent before deployment
- Three-pillar completeness: all services should emit traces + metrics + logs
