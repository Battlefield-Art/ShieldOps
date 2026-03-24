# Agent Firewall

The Agent Firewall provides runtime interception, behavioral analysis, and circuit breaking
for all AI agent calls across the ShieldOps platform. It acts as a security enforcement
layer between agents and the infrastructure they operate on.

---

## Purpose

- Intercept all outbound agent calls before they reach target infrastructure
- Enforce behavioral baselines and detect anomalous agent behavior
- Provide circuit breaker protection to prevent cascading failures
- Enable a global kill switch to halt all agent actions in emergencies
- Support multiple AI frameworks (LangChain, CrewAI, LlamaIndex) via SDK hooks
- Generate audit trails for every intercepted call with decision reasoning

---

## Architecture

```
                  ┌─────────────────────────────┐
                  │        Agent Runtime         │
                  └──────────────┬───────────────┘
                                 │
                                 ▼
                  ┌─────────────────────────────┐
                  │     Firewall Interceptor     │
                  │  (SDK hooks / sidecar proxy) │
                  └──────────────┬───────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                   ▼
     ┌────────────────┐ ┌───────────────┐ ┌─────────────────┐
     │ Policy Engine  │ │   Behavioral  │ │ Circuit Breaker │
     │   (OPA eval)   │ │   Analyzer    │ │    Manager      │
     └───────┬────────┘ └───────┬───────┘ └────────┬────────┘
              │                  │                   │
              └──────────────────┼──────────────────┘
                                 ▼
                       ┌─────────────────┐
                       │ Decision Engine  │
                       │ (allow/block/    │
                       │  escalate)       │
                       └────────┬────────┘
                                ▼
                       ┌─────────────────┐
                       │ Target Infra /  │
                       │ Cloud APIs      │
                       └─────────────────┘
```

### LangGraph Nodes

| Node | Description |
|------|-------------|
| `intercept_call` | Capture the outbound agent action with full context (agent ID, target, parameters) |
| `evaluate_policy` | Run OPA policy evaluation against the action (blast radius, permissions, environment) |
| `analyze_behavior` | Compare action against the agent's behavioral baseline (frequency, targets, timing) |
| `check_circuit_breaker` | Verify the circuit breaker state for the target service is not OPEN |
| `make_decision` | Combine policy, behavior, and circuit breaker signals into allow/block/escalate |
| `execute_or_block` | Forward allowed calls to target infrastructure or block with reason |
| `record_audit` | Write immutable audit record of the interception decision and outcome |

---

## Key Features

### Runtime Interception
All agent-to-infrastructure calls pass through the firewall before reaching their target.
The interceptor operates as either an SDK-level hook (in-process) or a sidecar proxy
(Kubernetes), depending on deployment mode.

### Behavioral Baselines
The firewall maintains per-agent behavioral profiles tracking call frequency, target
resources, action types, and timing patterns. Deviations beyond configurable thresholds
trigger anomaly alerts or automatic blocking.

### Circuit Breaker
Each target service has an independent circuit breaker. When error rates exceed the
configured threshold (default: 50% over 30 seconds), the breaker trips to OPEN state,
blocking further calls until the half-open probe succeeds.

### Kill Switch
A global kill switch can be activated via API or CLI to immediately halt all agent actions
platform-wide. This is designed for incident response scenarios where agent behavior must
be stopped pending human review.

---

## SDK Integration

### LangChain

```python
from shieldops.integrations.agent_firewall import ShieldOpsFirewallCallback

llm = ChatAnthropic(model="claude-sonnet-4-20250514")
chain = prompt | llm | parser
result = chain.invoke(input, config={"callbacks": [ShieldOpsFirewallCallback()]})
```

### CrewAI

```python
from shieldops.integrations.agent_firewall import ShieldOpsFirewallMiddleware

crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, write_task],
    middleware=[ShieldOpsFirewallMiddleware()],
)
```

### LlamaIndex

```python
from shieldops.integrations.agent_firewall import ShieldOpsFirewallHandler

service_context = ServiceContext.from_defaults(
    callback_manager=CallbackManager([ShieldOpsFirewallHandler()])
)
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_FIREWALL_MODE` | `monitor` | Mode: `monitor` (log only), `enforce` (block), `kill` (block all) |
| `AGENT_FIREWALL_ANOMALY_THRESHOLD` | `2.5` | Standard deviations from baseline before flagging |
| `AGENT_FIREWALL_CIRCUIT_BREAKER_THRESHOLD` | `0.5` | Error rate to trip circuit breaker |
| `AGENT_FIREWALL_CIRCUIT_BREAKER_TIMEOUT` | `60` | Seconds before half-open probe |
| `AGENT_FIREWALL_POLICY_BUNDLE` | `agent-firewall` | OPA policy bundle name |
| `AGENT_FIREWALL_AUDIT_RETENTION_DAYS` | `90` | Days to retain audit records |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/agent-firewall/status` | Current firewall status, circuit breaker states |
| `GET` | `/api/v1/agent-firewall/audit` | Query audit log with filters |
| `POST` | `/api/v1/agent-firewall/kill-switch` | Activate/deactivate kill switch |
| `GET` | `/api/v1/agent-firewall/baselines/{agent_id}` | View behavioral baseline for an agent |
| `POST` | `/api/v1/agent-firewall/baselines/{agent_id}/reset` | Reset behavioral baseline |
| `GET` | `/api/v1/agent-firewall/circuit-breakers` | List all circuit breaker states |
| `POST` | `/api/v1/agent-firewall/circuit-breakers/{service}/reset` | Manually reset a circuit breaker |

---

## Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `shieldops_agent_firewall_calls_total` | Counter | Total intercepted calls |
| `shieldops_agent_firewall_calls_blocked_total` | Counter | Total blocked calls |
| `shieldops_agent_firewall_anomalies_total` | Counter | Behavioral anomalies detected |
| `shieldops_agent_firewall_circuit_breakers` | Gauge | Circuit breaker states by service |
| `shieldops_agent_firewall_intercept_duration_seconds` | Histogram | Interception latency overhead |
| `shieldops_agent_firewall_kill_switch` | Gauge | Kill switch state (0=inactive, 1=active) |

---

## Related Engines

- `src/shieldops/security/agent_firewall_analytics.py` — Firewall analytics engine
- `src/shieldops/security/behavioral_baseline.py` — Behavioral baseline engine
- `src/shieldops/security/circuit_breaker_analytics.py` — Circuit breaker analytics

---

## Integration with Other Agents

The Agent Firewall integrates with the [SOC Brain](soc-brain.md) for escalation of
blocked actions that may indicate an active attack. Anomaly detections are forwarded
to the [Adaptive Security Agent](../agents/security.md) for threshold tuning.
