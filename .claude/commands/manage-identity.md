# Manage Identity Skill

Manage non-human identity (NHI) governance, identity threat detection, and credential lifecycle across the platform.

## Usage
`/manage-identity <action> [--entity <type>] [--provider <idp>] [--scope <environment>]`

Actions: `inventory`, `risk`, `rotate`, `review`, `detect`, `oauth-audit`, `status`

Entity types: `service_account`, `api_key`, `oauth_client`, `machine_identity`, `agent_identity`, `mcp_client`

## Agents Used
- `nhi_registry` — Non-human identity inventory and risk scoring
- `identity_graph` — Identity relationship mapping and cross-cloud correlation
- `identity_protection` — Multi-IdP identity threat detection (Okta, Entra, IAM)
- `oauth_analyzer` — OAuth grant risk analysis and SaaS permission auditing
- `service_account_tracker` — Service account lifecycle and dormancy detection
- `credential_lifecycle` — JIT credential issuance and rotation scheduling
- `access_review` — Access certification and recertification workflows
- `lateral_movement` — Identity-based lateral movement detection

## Process

### Inventory (NHI Registry)
1. **Discover**: Scan all environments for non-human identities
2. **Classify**: Categorize by type (service account, API key, OAuth, machine, agent)
3. **Score risk**: Assess each identity's privilege level, last used, rotation status
4. **Map relationships**: Build identity graph showing access paths

```python
from shieldops.agents.nhi_registry.runner import NHIRegistryRunner

runner = NHIRegistryRunner(connectors={"aws": aws, "gcp": gcp, "azure": azure})
result = await runner.inventory(
    scope="all_environments",
    include_dormant=True,
    risk_scoring=True,
)
```

### Rotate (Credential Lifecycle)
1. **Identify targets**: Find credentials due for rotation or compromised
2. **Issue JIT**: Generate just-in-time credentials with minimal scope
3. **Rotate**: Execute rotation with zero-downtime strategy
4. **Verify**: Confirm old credential revoked, new credential operational

```python
from shieldops.agents.credential_lifecycle.runner import CredentialLifecycleRunner

runner = CredentialLifecycleRunner()
result = await runner.rotate(
    credential_type="service_account",
    target="payment-service-sa",
    environment="production",
    jit=True,
)
```

### OAuth Audit
1. **Enumerate grants**: List all OAuth grants across SaaS applications
2. **Assess risk**: Score each grant by scope, sensitivity, last used
3. **Detect overprivilege**: Identify grants with excessive permissions
4. **Recommend**: Suggest scope reduction or revocation

```python
from shieldops.agents.oauth_analyzer.runner import OAuthAnalyzerRunner

runner = OAuthAnalyzerRunner()
result = await runner.audit(
    providers=["okta", "entra_id", "google_workspace"],
    include_dormant=True,
)
```

### Detect (Identity Threats)
1. **Monitor authentication**: Watch for anomalous login patterns
2. **Cross-cloud correlation**: Detect identity pivoting across cloud providers
3. **Lateral movement**: Identify credential hopping and privilege escalation
4. **Alert**: Generate identity-specific threat alerts

## Key Files
- `src/shieldops/agents/nhi_registry/` — NHI registry agent
- `src/shieldops/agents/identity_graph/` — Identity graph agent
- `src/shieldops/agents/identity_protection/` — Identity threat detection agent
- `src/shieldops/agents/oauth_analyzer/` — OAuth analysis agent
- `src/shieldops/agents/service_account_tracker/` — Service account agent
- `src/shieldops/agents/credential_lifecycle/` — Credential lifecycle agent
- `src/shieldops/agents/lateral_movement/` — Lateral movement detection agent
- `src/shieldops/security/identity_analytics_engine.py` — Identity analytics
- `src/shieldops/security/entity_risk_scoring_engine.py` — Entity risk scoring
- `src/shieldops/security/oauth_grant_risk.py` — OAuth grant risk engine
- `src/shieldops/security/identity_lateral_movement.py` — Lateral movement engine

## Conventions
- All NHIs must be inventoried and risk-scored within 24 hours of creation
- Service accounts dormant >90 days flagged for review, >180 days auto-disabled
- OAuth grants with admin/write scopes require quarterly recertification
- JIT credentials default to 1-hour TTL unless explicitly extended
- Credential rotation must be zero-downtime (new issued before old revoked)
- Identity threats escalate automatically at confidence >0.85
