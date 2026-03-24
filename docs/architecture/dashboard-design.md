# ShieldOps Unified Dashboard — Design Specification

## Overview
The unified dashboard provides real-time visibility into all ShieldOps agents across managed environments. It serves as the command center for SRE teams to monitor, control, and audit autonomous agent operations.

## Information Architecture

```
ShieldOps Dashboard
├── Fleet Overview (Home)          ← Real-time agent status, live feed
├── Investigations                  ← Active/historical investigation details
│   └── Investigation Detail        ← Full reasoning chain, evidence
├── Remediations                    ← Action timeline, rollback controls
│   └── Remediation Detail          ← Before/after diff, audit trail
├── Analytics                       ← MTTR trends, resolution rates, ROI
├── Security                        ← CVE heatmap, compliance scores
└── Settings                        ← Policies, thresholds, integrations
```

## Page Designs

### Page 1: Fleet Overview (Home)

```
┌──────────────────────────────────────────────────────────────────┐
│  SHIELDOPS COMMAND CENTER                                        │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐                 │
│  │ All  │ │ AWS  │ │ GCP  │ │Azure │ │OnPrem│  [+ Add Env]    │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘                 │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌────────────┐│
│  │ AGENTS      │ │ ACTIVE NOW  │ │ RESOLVED    │ │ MTTR       ││
│  │    24       │ │    4        │ │   47 today  │ │  4.2 min   ││
│  │ 23●  1▲    │ │ 3 invest    │ │ ↓32% vs     │ │ ↓58% vs    ││
│  │ healthy err │ │ 1 remediate │ │ last week   │ │ last month ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └────────────┘│
│                                                                  │
│  ┌────────────────────────────────────┬─────────────────────────┐│
│  │  ENVIRONMENT MAP                   │  AGENT HEALTH           ││
│  │                                    │                         ││
│  │  AWS us-east-1  [8 agents]        │  Investigation  6 ●●●●●●││
│  │    ●●●●●●●● (all healthy)        │  Remediation   4 ●●●●  ││
│  │                                    │  Security      8 ●●●●●●●●│
│  │  AWS us-west-2  [4 agents]        │  Learning      6 ●●●●●● ││
│  │    ●●●▲ (1 error)                │                         ││
│  │                                    │  ● Healthy  ▲ Error    ││
│  │  On-Prem DC1   [6 agents]        │  ◆ Idle     ■ Disabled  ││
│  │    ●●●●●● (all healthy)          │                         ││
│  │                                    │                         ││
│  │  GCP us-central [6 agents]        │                         ││
│  │    ●●●●●● (all healthy)          │                         ││
│  └────────────────────────────────────┴─────────────────────────┘│
│                                                                  │
│  LIVE ACTIVITY FEED                              [filter ▾]      │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │ ● 14:23  INVESTIGATING  High latency on payment-svc         ││
│  │          Confidence: 0.78  Step: Analyzing traces            ││
│  │          AWS us-east-1 / production                          ││
│  │                                          [View] [Take Over] ││
│  ├──────────────────────────────────────────────────────────────┤│
│  │ ✓ 14:18  RESOLVED  Restarted cart-svc pod (crash loop)      ││
│  │          Auto-resolved  Health check passed  Duration: 3.2m ││
│  │          AWS us-east-1 / production                          ││
│  │                                          [View] [Rollback]  ││
│  ├──────────────────────────────────────────────────────────────┤│
│  │ ✓ 14:05  PATCHED  CVE-2026-1234 on 3 hosts                 ││
│  │          Security agent  All validations passed              ││
│  │          On-Prem DC1 / production                            ││
│  │                                                    [View]   ││
│  ├──────────────────────────────────────────────────────────────┤│
│  │ ⏳ 14:01  AWAITING APPROVAL  Scale order-svc to 8 replicas  ││
│  │          Risk: MEDIUM  Requested by: investigation-agent-7   ││
│  │          AWS us-east-1 / production                          ││
│  │                                       [Approve] [Deny]     ││
│  └──────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

### Page 2: Investigation Detail View

```
┌──────────────────────────────────────────────────────────────────┐
│  ← Back to Investigations                                        │
│                                                                  │
│  INVESTIGATION: High latency on payment-svc                      │
│  Alert: HighP99Latency | Severity: Critical | Duration: 4m 23s  │
│  Environment: AWS us-east-1 / production                         │
│                                                                  │
│  ┌──────────────────────────┬───────────────────────────────────┐│
│  │  REASONING CHAIN         │  EVIDENCE PANEL                   ││
│  │                          │                                   ││
│  │  1. ● Gather Context     │  [Logs] [Metrics] [Traces]       ││
│  │     Service topology     │                                   ││
│  │     loaded, 3 deps found │  Metric: P99 Latency             ││
│  │     Duration: 1.2s       │  ┌──────────────────────┐        ││
│  │                          │  │     ╱‾‾‾‾‾╲          │        ││
│  │  2. ● Analyze Logs       │  │    ╱       ╲  ← alert│        ││
│  │     Found 47 error       │  │───╱         ╲────────│        ││
│  │     entries in last 5m   │  │  baseline    current  │        ││
│  │     Pattern: "conn       │  └──────────────────────┘        ││
│  │     timeout to db-main"  │                                   ││
│  │     Duration: 3.4s       │  Log Samples:                    ││
│  │                          │  14:21:03 ERROR conn timeout      ││
│  │  3. ● Analyze Metrics    │  14:21:05 ERROR conn timeout      ││
│  │     CPU: 45% (normal)    │  14:21:07 WARN pool exhausted    ││
│  │     Memory: 72% (normal) │  14:21:09 ERROR conn timeout      ││
│  │     DB conn pool: 100%   │                                   ││
│  │     ← ANOMALY            │  Trace: request-id-xyz           ││
│  │     Duration: 2.1s       │  payment-svc ──→ db-main (5.2s)  ││
│  │                          │  ↑ bottleneck                     ││
│  │  4. ● Analyze Traces     │                                   ││
│  │     Bottleneck: db-main  │                                   ││
│  │     Slow span: 5.2s      │                                   ││
│  │     Duration: 4.5s       │                                   ││
│  │                          │                                   ││
│  │  5. ● Correlate          │                                   ││
│  │     DB conn pool         │                                   ││
│  │     exhausted → timeouts │                                   ││
│  │     → high latency       │                                   ││
│  │                          │                                   ││
│  │  6. ● Hypothesis         │                                   ││
│  │     Generated 2 hypos    │                                   ││
│  └──────────────────────────┴───────────────────────────────────┘│
│                                                                  │
│  HYPOTHESES                                                      │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │  #1  Connection pool exhaustion (confidence: 0.91)           ││
│  │      DB connection pool saturated at 100%. Recent traffic    ││
│  │      spike exceeded pool capacity. All new requests timeout. ││
│  │      Recommended: Increase pool size from 20 → 30            ││
│  │                                                              ││
│  │      [Approve Remediation]  [Modify]  [Reject]              ││
│  ├──────────────────────────────────────────────────────────────┤│
│  │  #2  Database performance degradation (confidence: 0.34)     ││
│  │      Possible slow query or lock contention on db-main.      ││
│  │                                                              ││
│  │      [Investigate Further]                                   ││
│  └──────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

### Page 3: Analytics Dashboard

```
┌──────────────────────────────────────────────────────────────────┐
│  ANALYTICS                     Period: [7d] [30d] [90d] [Custom]│
│                                                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │ MTTR         │ │ AUTO-RESOLVE │ │ COST SAVINGS │            │
│  │  4.2 min     │ │    67%       │ │  $142K       │            │
│  │  ↓58% MoM    │ │  ↑12% MoM   │ │  ↑23% MoM   │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
│                                                                  │
│  MTTR TREND                                                      │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │ 60m ┤                                                        ││
│  │ 50m ┤  ╲                                                     ││
│  │ 40m ┤   ╲                                                    ││
│  │ 30m ┤    ╲     before ShieldOps                              ││
│  │ 20m ┤     ╲                                                  ││
│  │ 10m ┤      ╲───── ShieldOps deployed ─── ─── ───            ││
│  │  5m ┤                                      ╲___╱  ← current ││
│  │     └──────────────────────────────────────────────          ││
│  │      Jan    Feb    Mar    Apr    May    Jun                   ││
│  └──────────────────────────────────────────────────────────────┘│
│                                                                  │
│  RESOLUTION BREAKDOWN              AGENT ACCURACY                │
│  ┌────────────────────────┐       ┌────────────────────────┐    │
│  │  ██████████░░ Auto 67% │       │  Correct:     78%      │    │
│  │  ████░░░░░░░░ Appr 22% │       │  Partially:   15%      │    │
│  │  ██░░░░░░░░░░ Esc  11% │       │  Incorrect:    7%      │    │
│  └────────────────────────┘       └────────────────────────┘    │
│                                                                  │
│  [Export PDF Report]  [Export CSV]  [Schedule Weekly Report]     │
└──────────────────────────────────────────────────────────────────┘
```

## Component Hierarchy (React)

```
App
├── Layout
│   ├── Sidebar (navigation)
│   ├── Header (env selector, user, notifications)
│   └── Main Content
├── Pages
│   ├── FleetOverview
│   │   ├── StatsCards (agents, active, resolved, mttr)
│   │   ├── EnvironmentMap
│   │   ├── AgentHealthGrid
│   │   └── LiveActivityFeed
│   │       └── ActivityFeedItem (investigation/remediation/security)
│   ├── Investigations
│   │   ├── InvestigationList
│   │   └── InvestigationDetail
│   │       ├── ReasoningChain
│   │       ├── EvidencePanel (tabs: logs, metrics, traces)
│   │       └── HypothesisList
│   ├── Remediations
│   │   ├── RemediationTimeline
│   │   └── RemediationDetail
│   │       ├── ActionDiff (before/after)
│   │       ├── ApprovalTrail
│   │       └── RollbackControl
│   ├── Analytics
│   │   ├── MTTRTrendChart
│   │   ├── ResolutionBreakdown
│   │   ├── AgentAccuracyChart
│   │   └── CostSavingsCalculator
│   ├── Security
│   │   ├── CVEHeatmap
│   │   ├── ComplianceGauges
│   │   └── CredentialRotationStatus
│   └── Settings
│       ├── PolicyEditor
│       ├── ThresholdConfig
│       ├── IntegrationManager
│       └── ApprovalWorkflowBuilder
└── Shared Components
    ├── StatusBadge
    ├── ConfidenceBar
    ├── RiskLevelBadge
    ├── EnvironmentTag
    ├── TimeAgo
    ├── Chart (Recharts wrapper)
    └── WebSocketProvider (real-time updates)
```

## Real-Time Architecture

```
Agent Events (Kafka) → WebSocket Gateway (FastAPI) → React Dashboard
                              │
                              ▼
                       Event Types:
                       - agent.status_change
                       - investigation.started
                       - investigation.step_completed
                       - investigation.hypothesis_generated
                       - remediation.requested
                       - remediation.approved
                       - remediation.executed
                       - remediation.validated
                       - security.cve_detected
                       - security.patch_applied
```

## Design System (v2 — Surface-Based Architecture)

The dashboard uses a premium dark-theme design system inspired by Linear, Vercel, and Raycast.

### Color Tokens

| Token | Value | Usage |
|-------|-------|-------|
| `surface-0` | `#0a0e17` | Page background, deepest layer |
| `surface-1` | `#0f1420` | Sidebar, header, recessed panels |
| `surface-2` | `#151b2b` | Cards, modals, elevated surfaces |
| `surface-3` | `#1c2333` | Dropdowns, hover states, active surfaces |
| `surface-4` | `#232b3e` | Highest elevation (tooltips, popovers) |
| `brand-400` | `#22d3ee` | Primary accent (active states, links) |
| `brand-600` | `#0891b2` | Buttons, interactive elements |

### Border System

Borders use white opacity rather than hard gray values for a premium feel:

| Token | Value | Usage |
|-------|-------|-------|
| `--border-subtle` | `rgba(255,255,255,0.06)` | Dividers, section separators |
| `--border-default` | `rgba(255,255,255,0.08)` | Card borders, input borders |
| `--border-strong` | `rgba(255,255,255,0.12)` | Hover states, active borders |

### Component Classes

| Class | Description |
|-------|-------------|
| `btn-primary` | Gradient button with inset highlight + glow hover |
| `btn-secondary` | Surface-3 background with depth shadow |
| `btn-ghost` | Transparent with hover background |
| `card-surface` | Static card with surface-2 bg + gradient border |
| `card-interactive` | Clickable card with hover-lift effect |
| `tab-bar` / `tab-item` | Segmented control with surface-1 inset |
| `section-heading` | 11px uppercase tracking label |
| `metric-value` | Tabular-nums with tight tracking |
| `text-gradient-brand` | Cyan gradient text |
| `text-gradient-white` | White-to-gray gradient heading text |
| `bg-hero-mesh` | Multi-stop radial gradient for hero sections |
| `nav-active-line` | Left-side cyan indicator bar for active nav items |
| `hover-lift` | Subtle translateY(-1px) on hover |

### Typography

- **Display/Headings**: Inter, bold, tight tracking, `text-gradient-white`
- **Body**: Inter, regular, gray-400 to gray-100
- **Labels**: Inter, 11px, uppercase, `tracking-[0.08em]`, gray-500/600
- **Code/Mono**: JetBrains Mono, `tabular-nums`

### Shadows

| Name | Usage |
|------|-------|
| `shadow-depth` | Default card shadow (0 0 0 1px white/0.03 + 0 1px 2px black/0.4) |
| `shadow-card-hover` | Elevated hover state |
| `shadow-elevated` | Modals, dropdowns |
| `shadow-glow-brand` | Focus/active state glow |
| `shadow-inner-light` | Inset top highlight for buttons |

### Animation Principles

- **Transitions**: 150-200ms for interactions, 250ms for state changes
- **Easing**: ease-out for entries, ease-in for exits
- **Stagger**: 40ms delay per item for list animations (`stagger-item`)
- **No** scroll hijacking, heavy glassmorphism, or distracting background effects
- **Functional only**: animations serve navigation and state feedback

## Accessibility Requirements
- WCAG 2.1 AA compliance
- Keyboard navigation for all interactive elements
- Screen reader support for status changes
- Color-blind safe color palette for status indicators
- High contrast mode support

## Performance Targets
| Metric | Target |
|--------|--------|
| Initial Load (LCP) | < 2s |
| Event Latency (agent → dashboard) | < 500ms |
| Dashboard refresh rate | 1s (WebSocket) |
| Supports concurrent agents displayed | 500+ |
| Historical data query | < 3s for 90-day range |

## Situations Queue (Phase 5 — Outcome-Centric UX)

### Concept

The Situations Queue replaces traditional widget-based SOC dashboards with an AI-curated, outcome-centric feed. Instead of scattering alerts across dozens of panels and forcing analysts to mentally correlate signals, the SOC Brain agent automatically groups related findings into **Situations** — single units of work that represent a real security incident or concern across any combination of vendors (CrowdStrike, Microsoft Defender, Wiz, Splunk, etc.).

The queue is the analyst's primary workspace. Every situation has a clear status, severity, recommended actions, and a measurable outcome (resolved, false positive, escalated). This design eliminates context-switching and ensures every alert is accounted for in a trackable workflow.

### Situation Card Anatomy

Each situation appears as a card in the queue, ordered by risk score (highest first).

```
┌──────────────────────────────────────────────────────────────────┐
│  ● CRITICAL                                      2m ago  [Assign]│
│                                                                  │
│  Lateral movement: finance-db → hr-app → admin-panel             │
│                                                                  │
│  Vendors: CrowdStrike, Microsoft Defender    Findings: 7         │
│  Entities: svc-acct-payments, ip-203.0.113.42                    │
│  MITRE: T1021 (Remote Services), T1078 (Valid Accounts)          │
│                                                                  │
│  Risk Score: 87.4        Status: ● Investigating                 │
│                                                                  │
│  Recommended:  [Contain entity]  [Escalate to Tier-3]            │
└──────────────────────────────────────────────────────────────────┘
```

**Card fields:**
- **Severity badge** — CRITICAL / HIGH / MEDIUM / LOW / INFO (color-coded)
- **Title** — AI-generated summary of the situation
- **Vendors** — which security tools contributed findings
- **Findings count** — number of correlated alerts/detections
- **Entities** — affected users, hosts, IPs, service accounts
- **MITRE ATT&CK techniques** — mapped from findings
- **Risk score** — composite score from SOC Brain (0-100)
- **Status** — NEW / TRIAGING / INVESTIGATING / CONTAINING / REMEDIATED / CLOSED / FALSE_POSITIVE
- **Recommended actions** — AI-suggested next steps (investigate, contain, remediate, escalate, dismiss)

### Detail View Layout

Clicking a situation card opens the detail view with full context.

```
┌──────────────────────────────────────────────────────────────────┐
│  ← Back to Queue                                                 │
│                                                                  │
│  SITUATION: Lateral movement across finance services             │
│  Severity: CRITICAL  |  Risk: 87.4  |  Status: Investigating    │
│  Created: 14:21  |  Acknowledged: 14:23 (MTTA: 2m)              │
│                                                                  │
│  ┌──────────────────────────┬───────────────────────────────────┐│
│  │  FINDINGS TIMELINE       │  ENTITY GRAPH                     ││
│  │                          │                                   ││
│  │  14:18  CrowdStrike      │    [svc-acct-payments]            ││
│  │    Process injection on  │        │                          ││
│  │    finance-db (T1055)    │        ▼                          ││
│  │                          │    [finance-db] ──→ [hr-app]      ││
│  │  14:19  Microsoft Defender│       │                          ││
│  │    Unusual auth from     │        ▼                          ││
│  │    svc-acct-payments     │    [admin-panel]                  ││
│  │                          │                                   ││
│  │  14:20  CrowdStrike      │  Legend:                          ││
│  │    Lateral movement to   │  ● Compromised  ○ At-risk        ││
│  │    hr-app (T1021)        │                                   ││
│  │                          │                                   ││
│  │  14:21  Wiz              │                                   ││
│  │    Excessive IAM perms   │                                   ││
│  │    on svc-acct-payments  │                                   ││
│  └──────────────────────────┴───────────────────────────────────┘│
│                                                                  │
│  RECOMMENDED ACTIONS                                             │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │  #1  Contain svc-acct-payments via CrowdStrike (conf: 0.85) ││
│  │      [Execute]  [Modify]  [Skip]                             ││
│  │                                                              ││
│  │  #2  Escalate to SOC Tier-3 / Incident Commander (conf: 0.90)││
│  │      [Execute]  [Skip]                                       ││
│  │                                                              ││
│  │  #3  Apply remediation playbook for T1021 (conf: 0.80)       ││
│  │      [Execute]  [Modify]  [Skip]                             ││
│  └──────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ACTIONS TAKEN                                                   │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │  14:23  INVESTIGATE  Analyst opened situation (auto)         ││
│  │  14:25  CONTAIN      Disabled svc-acct-payments (manual)     ││
│  └──────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

### MTTD / MTTA / MTTR Tracking

Every situation automatically tracks three key metrics through its lifecycle:

| Metric | Definition | Tracked By |
|--------|-----------|------------|
| **MTTD** (Mean Time to Detect) | Time from first anomalous signal to situation creation | `timestamps["created"] - first_finding_time` |
| **MTTA** (Mean Time to Acknowledge) | Time from situation creation to first analyst action (triage/investigate) | `timestamps["investigating"] - timestamps["created"]` |
| **MTTR** (Mean Time to Resolve) | Time from situation creation to remediation/close | `timestamps["remediated"] - timestamps["created"]` |

These metrics are:
- Displayed per-situation in the detail view header
- Aggregated across all situations in the SOC metrics dashboard
- Broken down by severity, vendor, and team for trend analysis
- Used by the SOC Brain agent to optimize future response recommendations
- Exported to the SLA engine for SLO compliance tracking

### Integration with SOC Brain Agent

The SOC Brain agent (`src/shieldops/agents/soc_brain/`) drives the Situations Queue:

1. **Ingestion** — Receives normalized findings from CrowdStrike, Defender, Wiz, Splunk, and other vendor connectors
2. **Correlation** — Groups related findings into situations using entity overlap, temporal proximity, and MITRE technique chains
3. **Scoring** — Calculates risk scores using vendor severity weights, multi-vendor multipliers, and MITRE coverage depth
4. **Recommendation** — Generates prioritized action recommendations (investigate, contain, remediate, escalate) with confidence scores
5. **Learning** — Tracks analyst decisions (accept/modify/skip) on recommendations to improve future suggestions
6. **Automation** — For high-confidence actions (>0.85), auto-executes containment via the appropriate vendor connector without human approval

## New Dashboard Pages (AI Security Control Plane)

### Agent Firewall Monitor

The Agent Firewall Monitor provides real-time visibility into AI agent tool call interception across the enterprise.

**Layout:** Tab-based navigation with four primary views:

- **Agents Tab** — Live inventory of all monitored AI agents (LangChain, CrewAI, LlamaIndex), showing framework, mode (audit/enforce), tool calls per minute, and blocked call count. Each row expands to show recent tool call history.
- **Anomalies Tab** — Behavioral anomaly feed. Displays agents whose tool call patterns deviate from established baselines (e.g., sudden spike in database queries, first-time access to sensitive APIs). Each anomaly card shows the agent ID, deviation type, severity, and baseline comparison chart.
- **Policies Tab** — Policy editor for tool call rules. Supports allow/deny lists per agent, rate limits, resource scope restrictions, and time-of-day constraints. Policies are OPA-backed and version-controlled.
- **Audit Tab** — Immutable audit log of every intercepted tool call with timestamp, agent ID, tool name, parameters (redacted where sensitive), policy decision (allow/block), and latency overhead.

**Key UI elements:**
- Circuit breaker indicators per agent (green/yellow/red) showing current enforcement state
- Kill switch button (prominent, red) to immediately halt all tool calls for a specific agent or globally
- Real-time tool call throughput sparkline in the header

### NHI Registry

The NHI (Non-Human Identity) Registry provides a searchable inventory of all service accounts, API keys, OAuth apps, bot tokens, and machine identities across the enterprise.

**Layout:**

- **Inventory View** — Searchable, filterable table of all NHIs. Columns: name, type (service account / API key / OAuth app / bot token / machine cert), provider (AWS IAM, Azure AD, GCP SA, GitHub, Slack), risk score (0-100 gauge), last active, credential age, permissions scope, owner team.
- **Shadow AI Section** — Dedicated panel highlighting discovered shadow AI agents (unauthorized LLM API keys, unregistered MCP clients, rogue automation scripts). Each entry shows discovery method, risk assessment, and recommended action (register, revoke, or quarantine).
- **Filters** — Type filter (service account, API key, OAuth app, bot token, machine cert), provider filter (AWS, Azure, GCP, GitHub, Slack, custom), risk level filter (critical/high/medium/low), status filter (active, stale, expiring, revoked).
- **Risk Gauges** — Per-NHI circular gauge showing composite risk score based on: permission scope breadth, credential age, usage anomalies, and owner attribution.

### MCP Security

The MCP Security page provides governance over the Model Context Protocol ecosystem — MCP servers, client connections, and tool permissions.

**Layout:**

- **Server Inventory** — Table of all registered MCP servers with name, version, tool count, connection count, trust level (verified/unverified/quarantined), and last security scan timestamp. Expandable rows show individual tool definitions and permission scopes.
- **God Key Detection** — Prominent alert panel that flags MCP configurations where a single credential or token grants unrestricted access across multiple MCP servers ("God Keys"). Each detection shows the credential scope, affected servers, blast radius estimate, and remediation steps (rotate, scope-reduce, or revoke).
- **Supply Chain Scan** — Results from automated scanning of MCP server packages and dependencies. Shows vulnerability counts (critical/high/medium/low), outdated dependencies, unsigned packages, and known-malicious indicators. Integrates with Wiz and Snyk scan results.
- **Zero-Trust Compliance** — Dashboard showing per-server compliance with zero-trust policies: mutual TLS status, token rotation compliance, least-privilege tool access, connection allowlisting, and audit log completeness. Non-compliant servers are flagged with specific remediation guidance.
