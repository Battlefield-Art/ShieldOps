# ShieldOps Agent Firewall SDK -- Quickstart

Secure your AI agents in 5 minutes. The ShieldOps SDK intercepts every
tool call your AI agent makes, detects anomalies, and enforces policies
before they reach external systems.

## Installation

```bash
pip install shieldops[sdk]
```

For framework-specific extras:

```bash
pip install shieldops[sdk,langchain]   # LangChain integration
pip install shieldops[sdk,crewai]      # CrewAI integration
pip install shieldops[sdk,llamaindex]  # LlamaIndex integration
```

---

## LangChain Integration (Recommended)

Add ShieldOps to any LangChain agent with a single callback handler.

```python
from langchain.agents import create_openai_functions_agent
from langchain_openai import ChatOpenAI
from shieldops.sdk.langchain import ShieldOpsCallbackHandler

# Add ShieldOps to your agent in one line
handler = ShieldOpsCallbackHandler(
    api_key="sk-your-shieldops-key",
    mode="audit",  # "audit" (observe) or "enforce" (block risky calls)
)

agent = create_openai_functions_agent(
    llm=ChatOpenAI(),
    tools=[...],
    callbacks=[handler],
)

# Every tool call is now intercepted, audited, and policy-gated
result = agent.invoke({"input": "Query the database for user records"})

# View audit report
report = handler.get_audit_report()
print(f"Total calls: {report['total_calls']}")
print(f"Blocked: {report['blocked_calls']}")
print(f"Anomalies: {report['anomaly_count']}")
```

### LangGraph Integration

For LangGraph-based agents, wrap your tool nodes:

```python
from langgraph.graph import StateGraph
from shieldops.sdk.langgraph import ShieldOpsToolGuard

guard = ShieldOpsToolGuard(
    api_key="sk-your-shieldops-key",
    mode="enforce",
)

# Wrap any tool-calling node
graph = StateGraph(AgentState)
graph.add_node("tools", guard.wrap_node(tool_node))
graph.add_node("agent", agent_node)
# ... add edges as usual
```

---

## CrewAI Integration

Wrap individual agents or an entire crew.

```python
from crewai import Agent, Crew, Task
from shieldops.sdk.crewai import ShieldOpsCrewAIWrapper
from shieldops.sdk.config import SDKConfig

config = SDKConfig(api_key="sk-your-shieldops-key", mode="enforce")
wrapper = ShieldOpsCrewAIWrapper(config)

# Wrap a single agent
researcher = Agent(
    role="Security Researcher",
    goal="Investigate threats",
    tools=[search_tool, scrape_tool],
)
secured_researcher = wrapper.wrap_agent(researcher)

# Or wrap an entire crew
crew = Crew(
    agents=[secured_researcher],
    tasks=[Task(description="Analyze recent CVEs", agent=secured_researcher)],
)
result = crew.kickoff()

# Audit trail is available after execution
print(wrapper.get_audit_report())
```

---

## LlamaIndex Integration

Use the interceptor to wrap tool calls in LlamaIndex query engines
and agents.

```python
from llama_index.core.agent import ReActAgent
from shieldops.sdk.llamaindex import ShieldOpsToolWrapper
from shieldops.sdk.config import SDKConfig

config = SDKConfig(api_key="sk-your-shieldops-key", mode="audit")
tool_wrapper = ShieldOpsToolWrapper(config)

# Wrap your tools before passing to agent
raw_tools = [query_tool, search_tool, calculator_tool]
secured_tools = [tool_wrapper.wrap(t) for t in raw_tools]

agent = ReActAgent.from_tools(secured_tools, llm=llm, verbose=True)
response = agent.chat("What is the P99 latency for the payments service?")

print(tool_wrapper.get_audit_report())
```

---

## Generic Python Integration

For any framework or custom agent loop, use the base interceptor directly.

```python
from shieldops.sdk.config import SDKConfig
from shieldops.sdk.interceptor import ShieldOpsInterceptor

config = SDKConfig(
    api_key="sk-your-shieldops-key",
    mode="enforce",
    agent_id="my-custom-agent",
)
interceptor = ShieldOpsInterceptor(config)

# Before executing any tool call
decision = interceptor.check_tool_call(
    tool_name="execute_sql",
    arguments={"query": "SELECT * FROM users LIMIT 10"},
    context={"agent_id": "my-custom-agent", "session_id": "sess-123"},
)

if decision.allowed:
    # Proceed with tool execution
    result = execute_sql("SELECT * FROM users LIMIT 10")
    interceptor.record_result(decision.call_id, result)
else:
    print(f"Blocked: {decision.reason}")
    # Handle blocked call (fallback, escalate, etc.)
```

---

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `api_key` | Required | Your ShieldOps API key |
| `endpoint` | `https://api.shieldops.io` | ShieldOps API endpoint |
| `mode` | `audit` | `audit` (log only) or `enforce` (block risky calls) |
| `agent_id` | Auto-generated | Unique ID for this agent instance |
| `flush_interval_seconds` | `10` | How often to send batched events |
| `timeout_seconds` | `5` | API call timeout |
| `retry_count` | `3` | Number of retries on transient failures |
| `fail_open` | `true` | If ShieldOps is unreachable, allow calls (`true`) or block (`false`) |
| `buffer_size` | `1000` | Max events to buffer before force-flush |

### Configuration via Environment Variables

All options can be set via environment variables with the `SHIELDOPS_` prefix:

```bash
export SHIELDOPS_API_KEY="sk-your-shieldops-key"
export SHIELDOPS_ENDPOINT="https://api.shieldops.io"
export SHIELDOPS_MODE="enforce"
export SHIELDOPS_AGENT_ID="my-agent"
export SHIELDOPS_FAIL_OPEN="false"
```

### Configuration via File

```yaml
# shieldops.yaml
api_key: "${SHIELDOPS_API_KEY}"
endpoint: "https://api.shieldops.io"
mode: "enforce"
agent_id: "production-agent-01"
fail_open: false
flush_interval_seconds: 5
policies:
  - name: "block-destructive-sql"
    tool_pattern: "execute_sql"
    block_patterns: ["DROP", "DELETE", "TRUNCATE", "ALTER"]
  - name: "block-shell-injection"
    tool_pattern: "run_command"
    block_patterns: ["rm -rf", "wget", "curl.*|.*sh"]
```

---

## Modes Explained

### Audit Mode (Default)

- All tool calls are allowed to proceed
- Every call is logged with a risk score (0.0 to 1.0)
- Anomalies are flagged but not blocked
- Use for: initial deployment, understanding agent behavior baseline

```python
handler = ShieldOpsCallbackHandler(api_key="sk-...", mode="audit")
```

### Enforce Mode

- Risky tool calls are blocked based on policy rules
- Circuit breaker trips on anomaly storms (5+ anomalies in 60 seconds)
- Kill switch available for emergency shutdown of any agent
- Use for: production workloads after 2+ weeks of audit data

```python
handler = ShieldOpsCallbackHandler(api_key="sk-...", mode="enforce")
```

### Transitioning from Audit to Enforce

1. Run in audit mode for at least 2 weeks
2. Review the audit dashboard for false positives
3. Tune policies based on observed tool call patterns
4. Switch to enforce mode with `fail_open=true` initially
5. After 1 week of stable enforcement, set `fail_open=false`

---

## OpenTelemetry Telemetry

The SDK automatically exports tool call events as OpenTelemetry spans,
letting you correlate agent behavior with your existing observability stack.

```python
from shieldops.sdk.telemetry import ShieldOpsTelemetryExporter
from shieldops.sdk.config import SDKConfig

config = SDKConfig(api_key="sk-your-shieldops-key")
exporter = ShieldOpsTelemetryExporter(config)

# Events are automatically exported as OTel spans to your collector
# Configure your OTel collector endpoint:
exporter.configure(
    collector_endpoint="http://localhost:4317",
    service_name="my-ai-agent",
    export_interval_seconds=10,
)
```

Exported span attributes include:

| Attribute | Description |
|-----------|-------------|
| `shieldops.tool.name` | Name of the tool called |
| `shieldops.tool.risk_score` | Computed risk score (0.0-1.0) |
| `shieldops.tool.decision` | `allowed`, `blocked`, or `flagged` |
| `shieldops.agent.id` | Agent instance identifier |
| `shieldops.policy.matched` | Policy rule that matched (if any) |

---

## Generating Audit Reports

### Programmatic Access

```python
report = handler.get_audit_report()
print(f"Total calls: {report['total_calls']}")
print(f"Blocked: {report['blocked_calls']}")
print(f"Anomalies: {report['anomaly_count']}")
print(f"Risk distribution: {report['risk_distribution']}")

# Export as JSON for compliance
import json
with open("audit-report.json", "w") as f:
    json.dump(report, f, indent=2)
```

### API Access

```bash
# Get audit report for a specific agent
curl https://your-shieldops.com/api/v1/agent-firewall/agents/my-agent/audit \
  -H "Authorization: Bearer sk-your-shieldops-key" \
  -G -d "start=2026-03-01T00:00:00Z" -d "end=2026-03-25T23:59:59Z"
```

### Report Fields

| Field | Description |
|-------|-------------|
| `total_calls` | Total tool calls intercepted |
| `blocked_calls` | Calls blocked by policy |
| `anomaly_count` | Calls flagged as anomalous |
| `risk_distribution` | Histogram of risk scores |
| `top_tools` | Most frequently called tools |
| `top_blocked_reasons` | Most common block reasons |
| `timeline` | Hourly breakdown of activity |

---

## Error Handling

The SDK is designed to be resilient. By default, if the ShieldOps API
is unreachable, tool calls proceed normally (`fail_open=true`).

```python
from shieldops.sdk.exceptions import (
    ShieldOpsConnectionError,
    ShieldOpsPolicyViolation,
    ShieldOpsKillSwitchActive,
)

try:
    result = agent.invoke({"input": "Run the migration script"})
except ShieldOpsPolicyViolation as e:
    print(f"Policy violated: {e.policy_name} - {e.reason}")
    # Handle gracefully -- escalate to human
except ShieldOpsKillSwitchActive as e:
    print(f"Agent {e.agent_id} is killed -- emergency shutdown active")
    # All tool calls blocked until kill switch is released
except ShieldOpsConnectionError:
    # Only raised if fail_open=false and API is unreachable
    print("Cannot reach ShieldOps API -- calls are blocked")
```

---

## Next Steps

- [Agent Firewall Dashboard](https://your-shieldops.com/app/agent-firewall) -- visual policy management
- [Firewall Policies API](/api/v1/agent-firewall/policies) -- CRUD for policy rules
- [Kill Switch API](/api/v1/agent-firewall/agents/{id}/kill-switch) -- emergency agent shutdown
- [MCP Security Gateway](../integrations/mcp-security-setup.md) -- secure MCP tool servers
- [Vendor Webhooks](../integrations/vendor-webhooks.md) -- ingest security events from CrowdStrike, Defender, Wiz
