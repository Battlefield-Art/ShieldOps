# Add Integration Skill

Scaffold a new external integration — billing, notification, CVE source, credential store, or enterprise tool.

## Usage
`/add-integration <type> <provider-name> [--bidirectional] [--webhook]`

Types: `billing`, `notification`, `cve`, `credential`, `cost-forecast`, `enterprise`

## Agents Used
- `enterprise_integration` — Bidirectional enterprise tool integration (ITSM, SIEM, CMDB)
- `chatops` — Slack/Teams integration for ChatOps workflows
- `automation_orchestrator` — Multi-system automation chaining

## Process

### 1. Read Existing Patterns
Review `src/shieldops/integrations/` for the integration type's base protocol:
- Billing: `src/shieldops/integrations/billing/base.py` — `BillingSource.query()`
- Notification: `src/shieldops/integrations/notifications/base.py` — `NotificationChannel.send()`
- CVE: `src/shieldops/integrations/cve/` — `CVESource.scan()`
- Credential: `src/shieldops/integrations/credentials/` — `CredentialStore.list_credentials()`

### 2. Create the Integration

```python
# src/shieldops/integrations/{type}/{provider}.py
from shieldops.integrations.{type}.base import {BaseProtocol}

class {Provider}{Type}Integration({BaseProtocol}):
    def __init__(self, config: dict | None = None):
        self._client = None  # Lazy initialization
        self._config = config or {}

    async def _get_client(self):
        if self._client is None:
            import provider_sdk
            self._client = provider_sdk.Client(**self._config)
        return self._client

    async def query(self, **kwargs) -> dict:
        client = await self._get_client()
        # Implementation here
        ...
```

### 3. Configure & Register
- Add provider config to `src/shieldops/config/settings.py`
- Wire into app lifespan in `src/shieldops/api/app.py`
- Add health check endpoint

### 4. Set Up Webhooks (if bidirectional)

```python
# Slack webhook example
# src/shieldops/integrations/notifications/slack.py

from shieldops.integrations.notifications.base import NotificationChannel

class SlackNotification(NotificationChannel):
    async def send(self, channel: str, message: str, **kwargs) -> dict:
        client = await self._get_client()
        return await client.chat_postMessage(channel=channel, text=message)
```

### 5. Add OPA Policy
- Create policy: `playbooks/policies/integration_{provider}.rego`
- Define allowed actions, data access scope, rate limits
- Wire policy evaluation via `src/shieldops/policy/opa_client.py`

### 6. Write Tests
- Unit tests: `tests/unit/test_{provider}_{type}.py` with mocked API calls
- Integration tests: verify webhook delivery and error handling

## Key Files
- `src/shieldops/integrations/` — All integration implementations
- `src/shieldops/integrations/billing/` — Billing integrations (Stripe)
- `src/shieldops/integrations/notifications/` — Notification channels (Slack, Teams, PagerDuty, email, SMS)
- `src/shieldops/integrations/cve/` — CVE source integrations
- `src/shieldops/integrations/credentials/` — Credential store integrations
- `src/shieldops/integrations/otel/` — OTel integrations (Kafka, collector, instrumentor)
- `src/shieldops/agents/enterprise_integration/` — Enterprise integration agent
- `src/shieldops/agents/chatops/` — ChatOps agent
- `src/shieldops/config/settings.py` — Provider configuration
- `src/shieldops/policy/opa_client.py` — OPA policy evaluation
- `src/shieldops/utils/circuit_breaker.py` — Circuit breaker for external calls

## Conventions
- All I/O is async (use `run_in_executor` for sync SDKs)
- Graceful error handling — return empty/default on failure, never crash
- Structured logging with structlog
- Type hints on all public methods
- Every integration MUST have an OPA policy in `playbooks/policies/`
- Circuit breaker pattern required for all external API calls
- Dead-letter queue for failed events (Kafka topic: `integration.{provider}.dlq`)
- Health monitoring: error rate >5%, latency p99 >2s, queue depth >100
