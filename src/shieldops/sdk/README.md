# ShieldOps Agent Firewall SDK

The ShieldOps SDK intercepts AI agent tool calls in real time, evaluates them against security policies, and records an immutable audit trail. Drop it into any LangChain, CrewAI, LlamaIndex, OpenAI Agents, or AutoGen project with one line of code. Run in **audit** mode to observe, or **enforce** mode to block risky operations before they execute.

## Install

```bash
pip install shieldops-sdk
```

With framework extras:

```bash
pip install shieldops-sdk[langchain]
pip install shieldops-sdk[crewai]
pip install shieldops-sdk[llamaindex]
pip install shieldops-sdk[all]
```

## Quick Start

```python
from shieldops_sdk import ShieldOpsInterceptor, SDKConfig

config = SDKConfig(
    api_key="your-api-key",
    mode="enforce",        # "audit" (log only) or "enforce" (block risky calls)
    agent_id="my-agent",
)

interceptor = ShieldOpsInterceptor(config)

# Evaluate a tool call before executing it
result = interceptor.intercept("delete_database", args={"target": "prod"})
if result.decision == "block":
    print(f"Blocked: {result.reasons}")
else:
    # proceed with tool execution
    ...
```

## LangChain Integration

```python
from shieldops_sdk.langchain import ShieldOpsCallbackHandler
from shieldops_sdk import SDKConfig

handler = ShieldOpsCallbackHandler(
    config=SDKConfig(api_key="your-key", mode="enforce")
)
chain = LLMChain(..., callbacks=[handler])
```

## CrewAI Integration

```python
from shieldops_sdk.crewai import ShieldOpsCrewAIWrapper
from shieldops_sdk import SDKConfig

wrapper = ShieldOpsCrewAIWrapper(
    config=SDKConfig(api_key="your-key", mode="audit")
)
```

## Modes

| Mode | Behavior |
|------|----------|
| `audit` | Logs all tool calls and risk scores but never blocks execution |
| `enforce` | Blocks tool calls that match blocked patterns (e.g., `delete_database`, `drop_table`, `rm_rf`) |

## Telemetry

The SDK exports OpenTelemetry-compatible telemetry. Send traces to any OTEL collector (Splunk, Datadog, etc.):

```python
from shieldops_sdk.telemetry import ShieldOpsTelemetryExporter
from shieldops_sdk import SDKConfig

exporter = ShieldOpsTelemetryExporter(
    config=SDKConfig(api_key="your-key"),
    otel_endpoint="http://localhost:4317",
)
```

## Documentation

Full documentation: [docs.shieldops.io/sdk](https://docs.shieldops.io/sdk)

## License

Apache-2.0
