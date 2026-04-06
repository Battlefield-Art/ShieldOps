# Agent Specification Format

> **Status:** Design (future) — Issue #232
> **See also:** [design.md](./design.md), [certification-process.md](./certification-process.md)

Every agent published to the ShieldOps Marketplace ships with an `agent.yaml` manifest
at the root of its package. The manifest is the single source of truth that the
registry, certification pipeline, and runtime use to install, govern, and bill the
agent. Agents must be implemented on top of `define_agent()`
(`src/shieldops/agents/framework.py`) so they plug into the existing OPA, fitness
tracker, and evolution subsystems.

## 1. Schema Overview

```
agent.yaml
├── apiVersion         (required)
├── kind               (required, == "Agent")
├── metadata           (required)
│   ├── name
│   ├── version
│   ├── author
│   ├── description
│   ├── license
│   ├── category
│   ├── tags
│   ├── homepage
│   ├── repository
│   └── support
├── spec               (required)
│   ├── framework      (required, == "shieldops-define-agent")
│   ├── entrypoint     (required, Python dotted path to define_agent() call)
│   ├── capabilities
│   │   ├── connectors
│   │   ├── permissions
│   │   └── opa_policies
│   ├── resources
│   │   ├── max_memory_mb
│   │   ├── max_cpu_cores
│   │   ├── expected_latency_ms
│   │   ├── llm_preference
│   │   └── max_concurrent
│   ├── inputs
│   ├── outputs
│   └── tests
│       ├── coverage_threshold
│       ├── fixtures
│       └── examples
├── pricing            (optional)
│   ├── model          (free | one_time | subscription | usage_based)
│   ├── price_usd
│   ├── usage_unit
│   └── trial_period_days
└── compliance         (optional)
    ├── data_residency
    ├── export_controls
    ├── certifications
    └── sbom_url
```

## 2. Field Reference

### `apiVersion` (required)
Schema version. Currently `marketplace.shieldops.ai/v1alpha1`.

### `kind` (required)
Always `Agent` at launch. Reserved for future `AgentBundle`, `Connector`, etc.

### `metadata` (required)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Unique, lowercase, hyphenated. `^[a-z][a-z0-9-]{2,63}$` |
| `version` | string | yes | SemVer. `MAJOR.MINOR.PATCH`. |
| `author` | object | yes | `{ name, email, org, verified_id }` |
| `description` | string | yes | Single-line summary (<=140 chars). |
| `long_description` | markdown | no | Full description shown on detail page. |
| `license` | string | yes | SPDX identifier (`MIT`, `Apache-2.0`, `Commercial`). |
| `category` | enum | yes | `security`, `compliance`, `observability`, `operations`, `ai-governance`, `vertical`. |
| `subcategory` | enum | no | e.g., `security/threat-hunting`, `vertical/healthcare`. |
| `tags` | list<string> | no | Up to 10 free-form tags for search. |
| `homepage` | URL | no | Marketing page. |
| `repository` | URL | no | Public source repo (required for Community tier). |
| `support` | object | yes | `{ email, url, sla_hours }` |
| `icon` | path | no | 256x256 PNG in package. |

### `spec.framework` (required)
Must be `shieldops-define-agent`. Reserved for future frameworks.

### `spec.entrypoint` (required)
Dotted path to the `define_agent()` call. Example:
`myorg.swift_fraud.agent:build_agent`. The target must return a compiled
LangGraph `StateGraph`.

### `spec.capabilities.connectors`
List of ShieldOps connectors the agent needs. The runtime will refuse to install if
any are missing or if the customer has not granted the agent access.

```yaml
connectors:
  - name: splunk
    access: read            # read | write | admin
    required: true
  - name: crowdstrike
    access: read
    required: true
  - name: pagerduty
    access: write
    required: false         # degraded mode if missing
```

Allowed connectors at Community tier: read-only connectors from the 17-connector list
(see `src/shieldops/connectors/`). Write or admin access requires Verified+.

### `spec.capabilities.permissions`
Fine-grained runtime permissions. Mirrors the OPA input format.

```yaml
permissions:
  - action: incident.create
    scope: tenant
  - action: alert.acknowledge
    scope: tenant
  - action: ec2.terminate       # DENIED at Community tier
    scope: account
    justification: "Required for auto-containment of compromised instances."
```

Any permission not listed here is implicitly denied by OPA, even if the underlying
connector allows it.

### `spec.capabilities.opa_policies`
List of OPA policy packages the agent depends on. The registry verifies these exist
in the customer's policy set at install time.

```yaml
opa_policies:
  - shieldops.policies.blast_radius
  - shieldops.policies.approval_required
  - myorg.swift.fraud            # custom policy shipped with the agent
```

Custom policies must live under `policies/` in the agent package and conform to the
ShieldOps OPA conventions.

### `spec.resources`

```yaml
resources:
  max_memory_mb: 512
  max_cpu_cores: 1.0
  expected_latency_ms: 3000      # median, for SLA tracking
  llm_preference:
    model: claude-sonnet         # haiku | sonnet | opus | auto
    max_tokens_per_run: 8000
    fallback: gpt-4o-mini
  max_concurrent: 10             # per tenant
```

The runtime enforces `max_memory_mb`, `max_cpu_cores`, and `max_concurrent`.
`expected_latency_ms` is used for fitness tracking and alerting; exceeding it
repeatedly degrades the agent's fitness score.

### `spec.inputs` / `spec.outputs`
Pydantic model references (dotted path) or inline JSON schema. Used to:
- Validate the agent in the sandbox.
- Generate API docs on the detail page.
- Enable cross-agent composition (outputs of agent A feed inputs of agent B).

```yaml
inputs:
  schema: myorg.swift_fraud.models:FraudCheckInput
outputs:
  schema: myorg.swift_fraud.models:FraudCheckReport
```

### `spec.tests`

```yaml
tests:
  coverage_threshold: 0.80
  fixtures: tests/fixtures/
  examples:
    - name: "Basic fraud alert"
      input: tests/examples/basic_input.json
      expected_output_schema: myorg.swift_fraud.models:FraudCheckReport
      expected_outcome: fraud_detected
    - name: "Clean transaction"
      input: tests/examples/clean_input.json
      expected_outcome: no_action
```

The certification pipeline runs these examples in the sandbox. Community tier
requires at least 3 examples; Verified requires 10 + adversarial examples.

### `pricing` (optional)

```yaml
pricing:
  model: subscription
  price_usd: 2000
  billing_period: monthly
  trial_period_days: 14
```

Usage-based example:
```yaml
pricing:
  model: usage_based
  price_usd: 0.10
  usage_unit: scan
  included_per_month: 1000
```

### `compliance` (optional)

```yaml
compliance:
  data_residency:
    - us
    - eu
  export_controls:
    denied_countries: [CU, IR, KP, SY]
  certifications:
    - SOC2
    - HIPAA
    - PCI-DSS
  sbom_url: https://myorg.example/sbom/swift-fraud-1.2.0.spdx.json
```

## 3. Example Manifest

```yaml
apiVersion: marketplace.shieldops.ai/v1alpha1
kind: Agent
metadata:
  name: swift-fraud-hunter
  version: 1.2.0
  author:
    name: Alex Chen
    email: alex@fintech-sec.example
    org: FinTech Security Labs
    verified_id: author_01H9X...
  description: "Detects anomalous SWIFT MT103/MT202 messages using behavioral baselines."
  long_description: |
    SWIFT Fraud Hunter ingests SWIFT MT messages from your SIEM, builds a behavioral
    baseline per correspondent bank, and flags anomalies indicative of BEC, APT, or
    insider-driven wire fraud. Integrates with PagerDuty for incident creation and
    ServiceNow for case management.
  license: Commercial
  category: vertical
  subcategory: vertical/fintech
  tags: [swift, fraud, bec, wire-transfer, banking]
  homepage: https://fintech-sec.example/swift-fraud-hunter
  repository: https://github.com/fintech-sec/swift-fraud-hunter
  support:
    email: support@fintech-sec.example
    url: https://fintech-sec.example/support
    sla_hours: 4
  icon: assets/icon.png

spec:
  framework: shieldops-define-agent
  entrypoint: fintech_sec.swift_fraud.agent:build_agent

  capabilities:
    connectors:
      - name: splunk
        access: read
        required: true
      - name: pagerduty
        access: write
        required: true
      - name: servicenow
        access: write
        required: false
    permissions:
      - action: incident.create
        scope: tenant
      - action: alert.enrich
        scope: tenant
    opa_policies:
      - shieldops.policies.blast_radius
      - shieldops.policies.approval_required
      - fintech_sec.swift.fraud_detection

  resources:
    max_memory_mb: 1024
    max_cpu_cores: 2.0
    expected_latency_ms: 5000
    llm_preference:
      model: claude-sonnet
      max_tokens_per_run: 12000
      fallback: gpt-4o
    max_concurrent: 20

  inputs:
    schema: fintech_sec.swift_fraud.models:SwiftMessageBatch
  outputs:
    schema: fintech_sec.swift_fraud.models:FraudAnalysisReport

  tests:
    coverage_threshold: 0.85
    fixtures: tests/fixtures/
    examples:
      - name: "Known BEC pattern"
        input: tests/examples/bec_pattern.json
        expected_outcome: fraud_detected
      - name: "Anomalous correspondent"
        input: tests/examples/new_correspondent.json
        expected_outcome: review_required
      - name: "Normal high-value wire"
        input: tests/examples/normal_wire.json
        expected_outcome: no_action

pricing:
  model: subscription
  price_usd: 2000
  billing_period: monthly
  trial_period_days: 14

compliance:
  data_residency: [us, eu]
  export_controls:
    denied_countries: [CU, IR, KP, SY, RU]
  certifications: [SOC2, PCI-DSS]
  sbom_url: https://fintech-sec.example/sbom/swift-fraud-hunter-1.2.0.spdx.json
```

## 4. Package Layout

```
swift-fraud-hunter/
├── agent.yaml                     # the manifest above
├── README.md                      # long_description source
├── LICENSE
├── assets/
│   └── icon.png
├── fintech_sec/
│   └── swift_fraud/
│       ├── __init__.py
│       ├── agent.py               # define_agent() entry point
│       ├── nodes.py
│       ├── tools.py
│       ├── models.py              # Pydantic inputs/outputs
│       └── prompts.py
├── policies/
│   └── swift_fraud.rego           # custom OPA policies
└── tests/
    ├── fixtures/
    ├── examples/
    │   ├── bec_pattern.json
    │   ├── new_correspondent.json
    │   └── normal_wire.json
    └── test_agent.py
```

## 5. Validation

The `shieldops agent validate` CLI command (to be built) checks:

- Manifest schema compliance (JSON Schema).
- `entrypoint` resolves to a `define_agent()` call and returns a compiled graph.
- Declared connectors exist in the ShieldOps connector registry.
- Declared OPA policies parse successfully.
- Test examples execute against the sandbox.
- Coverage meets `tests.coverage_threshold`.
- License is a valid SPDX identifier.
- SBOM URL (if set) resolves and is a valid SPDX 2.3 document.

Validation runs locally via CLI and is re-run by the certification pipeline (see
[certification-process.md](./certification-process.md)).
