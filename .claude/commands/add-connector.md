# Add Connector Skill

Scaffold a new infrastructure connector following the `InfraConnector` protocol.

## Usage
`/add-connector <provider-name> [--type <cloud|security|observability|incident|itsm>]`

Provider types: `cloud` (AWS, GCP, Azure, K8s), `security` (CrowdStrike, Defender, Wiz), `observability` (Splunk, Elastic, Datadog, New Relic), `incident` (PagerDuty, OpsGenie), `itsm` (ServiceNow, Jira)

## Agents Used
- `enterprise_integration` — Bidirectional enterprise tool integration
- `cross_vendor_correlator` — OCSF normalization across vendor connectors
- `vendor_normalizer` — Vendor telemetry mapping and normalization

## Process

1. **Read the base protocol**: Review `src/shieldops/connectors/base.py` for the `InfraConnector` ABC
2. **Study existing connectors**: Review `src/shieldops/connectors/aws/connector.py` for the reference pattern
3. **Create the connector module**:
   - Create directory: `src/shieldops/connectors/{provider}/`
   - Create `__init__.py` with connector export
   - Create `connector.py` implementing all 7 `InfraConnector` methods:
     - `get_health(resource_id)` — Check resource health status
     - `list_resources(resource_type, environment, filters)` — List resources with filtering
     - `get_events(resource_id, time_range)` — Query audit/activity events
     - `execute_action(action)` — Execute remediation action
     - `create_snapshot(resource_id)` — Snapshot current state for rollback
     - `rollback(snapshot_id)` — Restore from snapshot
     - `validate_health(resource_id, timeout)` — Post-action health validation
4. **Register in factory**: Add to `src/shieldops/connectors/factory.py`
5. **Add settings**: Add provider config to `src/shieldops/config/settings.py`
6. **Write tests**: Unit tests in `tests/unit/test_{provider}_connector.py`
7. **Create fake connector**: Integration test fake in `tests/integration/fakes/{provider}_fake.py`

## Connector Template

```python
from shieldops.connectors.base import InfraConnector

class MyProviderConnector(InfraConnector):
    provider = "my_provider"

    def __init__(self, config: dict | None = None):
        self._client = None  # Lazy initialization
        self._config = config or {}

    async def _get_client(self):
        if self._client is None:
            import my_sdk
            self._client = my_sdk.Client(**self._config)
        return self._client

    async def get_health(self, resource_id: str) -> dict:
        client = await self._get_client()
        # Implementation here
        ...
```

## Key Files
- `src/shieldops/connectors/base.py` — `InfraConnector` ABC (7 methods)
- `src/shieldops/connectors/factory.py` — Connector factory/registry
- `src/shieldops/connectors/aws/connector.py` — Reference implementation (boto3)
- `src/shieldops/connectors/gcp/connector.py` — GCP implementation
- `src/shieldops/connectors/azure/connector.py` — Azure implementation
- `src/shieldops/connectors/kubernetes/connector.py` — Kubernetes implementation
- `src/shieldops/connectors/crowdstrike/connector.py` — CrowdStrike Falcon (OAuth2 + RTR)
- `src/shieldops/connectors/defender/connector.py` — Microsoft Defender (MSAL + KQL)
- `src/shieldops/connectors/wiz/connector.py` — Wiz (GraphQL + attack paths)
- `src/shieldops/connectors/splunk/connector.py` — Splunk (REST + HEC + SPL)
- `src/shieldops/connectors/elastic/connector.py` — Elastic (DSL + EQL)
- `src/shieldops/config/settings.py` — Provider configuration
- `tests/unit/` — Unit test location
- `tests/integration/fakes/` — Fake connector location

## Conventions
- Use lazy client initialization (don't create SDK clients in `__init__`)
- All methods are async
- Use `asyncio.get_event_loop().run_in_executor()` for sync SDK calls
- Set `provider` class attribute to the provider string
- Use structlog for all logging
- Handle ImportError gracefully for optional SDK dependencies
- Normalize events to OCSF schema via `vendor_normalizer` when possible
- Include rate limiting and retry logic for external API calls
- Document required environment variables in connector docstring
