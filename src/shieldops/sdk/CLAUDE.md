# sdk/ — Agent Firewall SDK

One-line integration SDK for AI agent frameworks.

## Supported Frameworks
- **LangChain**: `ShieldOpsCallbackHandler`
- **CrewAI**: `ShieldOpsCrewAIWrapper`
- **LlamaIndex**: Integration hooks

## Modes
- **Audit** — Observe only, log all tool calls
- **Enforce** — Block risky calls based on policy

## Key Files
- `interceptor.py` — Tool call interception + risk scoring
- `callback.py` — LangChain callback handler
- `crewai.py` — CrewAI wrapper
- `telemetry.py` — OTEL-compatible telemetry export

## Usage
```python
from shieldops.sdk import ShieldOpsCallbackHandler
handler = ShieldOpsCallbackHandler(mode="enforce")
chain = LLMChain(..., callbacks=[handler])
```
