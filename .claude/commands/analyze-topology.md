# Analyze Topology Skill

Analyze service topology — dependency mapping, API lifecycle, fault propagation, service catalog, and traffic intelligence.

## Usage
`/analyze-topology <action> [--service <name>] [--scope <namespace|cluster|all>]`

Actions: `map`, `dependencies`, `api-health`, `fault-propagation`, `catalog`, `traffic`, `status`

## Agents Used
- `trust_relationship_mapper` — Trust relationship mapping across services
- `it_asset_intelligence` — IT asset discovery and intelligence
- `dns_security` — DNS security analysis
- `certificate_manager` — Certificate lifecycle management

## Process

### Map (Service Topology)
1. **Discover**: Enumerate services from K8s, cloud APIs, and OTel traces
2. **Map dependencies**: Build directed graph of service-to-service calls
3. **Classify**: Label edges by protocol (gRPC, HTTP, Kafka, DB)
4. **Visualize**: Generate topology map with health overlays

```python
from shieldops.topology.comm_mapper import ServiceCommunicationMapper

mapper = ServiceCommunicationMapper()
mapper.record_item(
    source="api-gateway", target="payment-service",
    protocol="grpc", latency_p99_ms=45, error_rate=0.001,
)
report = mapper.generate_report()
```

### Dependencies (Impact Analysis)
1. **Trace dependencies**: Map upstream and downstream dependencies
2. **Score risk**: Calculate dependency risk per service
3. **Detect cycles**: Identify circular dependencies
4. **Blast radius**: Predict blast radius of service failure

```python
from shieldops.topology.service_dependency_risk_engine import ServiceDependencyRiskEngine

engine = ServiceDependencyRiskEngine()
engine.record_item(
    service="payment-service",
    dependency="database-primary", dependency_type="hard",
    health_score=0.95, criticality="high",
)
report = engine.generate_report()
```

### API Health (API Lifecycle)
1. **Inventory**: List all APIs with version, consumers, SLA
2. **Health score**: Composite health (latency, errors, availability)
3. **Deprecation**: Track deprecated APIs and consumer migration
4. **Contract drift**: Detect schema drift and breaking changes

```python
from shieldops.topology.api_health_composite_scorer import APIHealthCompositeScorer

scorer = APIHealthCompositeScorer()
scorer.record_item(
    api="/api/v1/payments", method="POST",
    latency_p99_ms=120, error_rate=0.002,
    availability=0.999, consumers=["mobile-app", "web-app"],
)
report = scorer.generate_report()
```

### Fault Propagation
1. **Model**: Build fault propagation graph from topology
2. **Simulate**: Model cascading failure scenarios
3. **Identify**: Find critical single points of failure
4. **Recommend**: Suggest resilience improvements

### Catalog (Service Catalog)
1. **Inventory**: Enumerate all services with metadata
2. **Ownership**: Map services to teams and on-call
3. **Readiness**: Score service production readiness
4. **Documentation**: Track documentation completeness

### Traffic (Traffic Intelligence)
1. **Analyze patterns**: Identify normal traffic patterns and anomalies
2. **Rate limits**: Monitor API rate limit utilization
3. **Circuit breakers**: Track circuit breaker state and triggers
4. **Load distribution**: Analyze traffic distribution across instances

## Key Files
- `src/shieldops/topology/` — 65 topology engines
- `src/shieldops/topology/comm_mapper.py` — Service communication mapping
- `src/shieldops/topology/service_dependency_risk_engine.py` — Dependency risk scoring
- `src/shieldops/topology/api_health_composite_scorer.py` — API health scoring
- `src/shieldops/topology/api_lifecycle_engine.py` — API lifecycle management
- `src/shieldops/topology/fault_propagation_engine.py` — Fault propagation modeling
- `src/shieldops/topology/service_catalog_intelligence_engine.py` — Service catalog
- `src/shieldops/topology/traffic_pattern_intelligence.py` — Traffic patterns
- `src/shieldops/topology/circuit_breaker_intelligence_engine.py` — Circuit breaker intel
- `src/shieldops/topology/api_consumer_impact_analyzer.py` — Consumer impact analysis
- `src/shieldops/topology/api_rate_limit_intelligence.py` — Rate limit intelligence
- `src/shieldops/topology/internal_developer_portal_engine.py` — Developer portal
- `src/shieldops/topology/otel_service_graph_engine.py` — OTel service graph
- `src/shieldops/topology/asset_inventory_reconciler.py` — Asset inventory

## Related Agents
- `src/shieldops/agents/trust_relationship_mapper/` — Trust mapping agent
- `src/shieldops/agents/it_asset_intelligence/` — Asset intelligence agent
- `src/shieldops/agents/dns_security/` — DNS security agent
- `src/shieldops/agents/certificate_manager/` — Certificate management agent

## Conventions
- All topology engines follow the standard pattern: record_item → process → generate_report
- Service dependencies classified as hard (critical) or soft (degraded)
- API health scores on 0-1 scale; <0.9 triggers investigation
- Fault propagation models updated on every topology change
- Service catalog must include: owner, team, on-call, SLO, dependencies
- Traffic anomalies alert within 5 minutes of detection
