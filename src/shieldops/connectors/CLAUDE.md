# connectors/ — Vendor Connectors

18 connectors for cloud, security, observability, incident, and ITSM platforms.

## Connector Architecture

```
connectors/
├── factory.py          # Connector factory + router
├── aws/                # AWS (boto3)
├── gcp/                # Google Cloud
├── azure/              # Azure
├── kubernetes/         # Kubernetes (kubernetes-client)
├── linux/              # Linux (SSH/subprocess)
├── windows/            # Windows (WinRM)
├── crowdstrike/        # EDR platform (OAuth2 + RTR)
├── microsoft_defender/ # Endpoint protection (MSAL + KQL)
├── wiz/                # Cloud security scanner (GraphQL + attack paths)
├── splunk/             # Splunk (REST + HEC + SPL)
├── elastic/            # Elastic (DSL + EQL + SIEM)
├── datadog/            # Datadog (metrics + logs)
├── newrelic/           # New Relic (NerdGraph + NRQL)
├── pagerduty/          # PagerDuty (REST + Events v2)
├── opsgenie/           # OpsGenie (alerts + on-call)
├── servicenow/         # ServiceNow (Table API + CMDB)
└── jira/               # Jira (REST v3 + JQL)
```

## Connector Pattern

Each connector implements:
```python
class {Vendor}Connector:
    async def connect() -> dict        # Health check
    async def collect_events() -> list  # Pull telemetry
    async def execute_action() -> dict  # Take action
    async def get_inventory() -> list   # Asset discovery
```

## Adding a New Connector
1. Create directory under `connectors/`
2. Implement connector class with async methods
3. Register in `factory.py`
4. Add credentials to environment variables
5. Never hardcode credentials
