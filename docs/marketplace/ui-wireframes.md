# UI Wireframes

> **Status:** Design (future) — Issue #232
> **See also:** [design.md](./design.md)

Low-fidelity ASCII wireframes for the marketplace surfaces. Production implementation
will use the existing ShieldOps design system (surface-0..4 depth hierarchy,
opacity-based borders, brand cyan accent, Inter + JetBrains Mono).

## 1. Marketplace Browse Page

Route: `/marketplace`

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  ShieldOps  │  Situations │ Agents │ Marketplace* │ Fleet │ Settings  │ 👤   │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Agent Marketplace                                                          │
│   Extend your ShieldOps deployment with vertical and community agents.       │
│                                                                              │
│   ┌──────────────────────────────────────────────────────┐  ┌──────────┐    │
│   │ 🔍  Search 412 agents...                             │  │ Publish  │    │
│   └──────────────────────────────────────────────────────┘  └──────────┘    │
│                                                                              │
│   Filters:  [All] [Security] [Compliance] [Cloud] [Observability] [AI Gov]  │
│             [Vertical] [Free] [Paid] [✓ Verified] [⭐ Premier]              │
│                                                                              │
│   ──────────────────────────────────────────────────────────────────────    │
│                                                                              │
│   Editor's Picks                                                             │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│   │ [icon] Premier  │  │ [icon] Verified │  │ [icon] Verified │             │
│   │ SWIFT Fraud     │  │ HIPAA Audit     │  │ K8s Drift       │             │
│   │ Hunter          │  │ Bundle          │  │ Sentinel        │             │
│   │ ★ 4.8 · 127     │  │ ★ 4.6 · 89      │  │ ★ 4.9 · 340     │             │
│   │ $2,000/mo       │  │ $499 one-time   │  │ Free            │             │
│   │ FinTech Labs    │  │ HealthSec Inc   │  │ CloudNative Co  │             │
│   └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                              │
│   Recommended for you (based on Splunk + CrowdStrike + AWS)                  │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│   │ ...             │  │ ...             │  │ ...             │             │
│   └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                              │
│   All Agents  ·  Sort: [Relevance ▾]  Showing 1-24 of 412                   │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│   │ ...             │  │ ...             │  │ ...             │             │
│   └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│   │ ...             │  │ ...             │  │ ...             │             │
│   └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                              │
│                        ◀ Prev   1  2  3  ...  18   Next ▶                   │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 2. Agent Detail Page

Route: `/marketplace/:agent-slug`

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  ← Back to Marketplace                                                       │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   [icon]  SWIFT Fraud Hunter   [✓ Verified]                                  │
│           v1.2.0 · Updated 3 days ago · by FinTech Security Labs             │
│                                                                              │
│           Detects anomalous SWIFT MT103/MT202 messages using behavioral      │
│           baselines. Integrates with Splunk, PagerDuty, and ServiceNow.      │
│                                                                              │
│           ★ 4.8 (127 reviews)  ·  1,340 installs  ·  $2,000/mo              │
│                                                                              │
│           ┌────────────────────┐  ┌────────────────────┐                    │
│           │   Install   →      │  │  Start 14-day trial│                    │
│           └────────────────────┘  └────────────────────┘                    │
│                                                                              │
│   ────────────────────────────────────────────────────────────────          │
│                                                                              │
│   [Overview] [Capabilities] [Pricing] [Reviews] [Changelog] [Support]       │
│                                                                              │
│   Overview                                                                   │
│   ─────────────                                                              │
│   SWIFT Fraud Hunter ingests SWIFT MT messages from your SIEM, builds a     │
│   behavioral baseline per correspondent bank, and flags anomalies...        │
│                                                                              │
│   Key capabilities                                                           │
│   • BEC pattern detection across correspondent banks                         │
│   • Behavioral baselines with 14-day rolling window                          │
│   • Auto-enrichment from threat intel feeds                                  │
│   • PagerDuty incident creation with evidence bundle                         │
│                                                                              │
│   Required connectors                                                        │
│   ✓ Splunk         (read)     — already installed                            │
│   ✓ PagerDuty      (write)    — already installed                            │
│   ⚠ ServiceNow     (write)    — optional, not installed                      │
│                                                                              │
│   Permissions requested                                                      │
│   • incident.create (tenant scope)                                           │
│   • alert.enrich    (tenant scope)                                           │
│                                                                              │
│   Resources                                                                  │
│   Memory: 1GB · CPU: 2 cores · Latency: ~5s · LLM: Claude Sonnet             │
│                                                                              │
│   Compliance                                                                 │
│   Certifications: SOC 2, PCI-DSS  ·  Data residency: US, EU                  │
│   SBOM: download SPDX                                                        │
│                                                                              │
│   Fitness score (last 30 days across all tenants)                            │
│   ████████████████████░░  0.87 / 1.0                                         │
│                                                                              │
│   ────────────────────────────────────────────────────────────────          │
│   Recent reviews                                                             │
│                                                                              │
│   ★★★★★  "Caught a BEC attempt in week 2. Paid for itself."                 │
│           — sec-lead at RegionalBank  ·  2 weeks ago                         │
│                                                                              │
│   ★★★★☆  "Great detection, wish tuning was easier."                          │
│           — soc-analyst at CreditCo   ·  1 month ago                         │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 3. Install Confirmation Modal

```
┌──────────────────────────────────────────────────────────────┐
│  Install SWIFT Fraud Hunter v1.2.0                      ×    │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  You are about to install a third-party agent. Review        │
│  what it can do in your environment.                         │
│                                                              │
│  Author          FinTech Security Labs  (✓ Verified)         │
│  Certification   Verified (reviewed 2026-03-22)              │
│  License         Commercial                                  │
│  SBOM            View                                        │
│                                                              │
│  ─────────────────────────────────────────────────────────   │
│  This agent WILL be allowed to:                              │
│    ✓ Read from Splunk (tenant scope)                         │
│    ✓ Write to PagerDuty (tenant scope)                       │
│    ✓ Create incidents                                        │
│    ✓ Enrich alerts                                           │
│                                                              │
│  This agent WILL NOT be allowed to:                          │
│    ✗ Modify infrastructure                                   │
│    ✗ Access connectors not listed above                      │
│    ✗ Bypass OPA policies                                     │
│  ─────────────────────────────────────────────────────────   │
│                                                              │
│  Billing                                                     │
│  Plan:           $2,000 / month                              │
│  Trial:          14 days free                                │
│  First charge:   2026-04-19 (unless cancelled)               │
│                                                              │
│  Initial mode                                                │
│  ◉ Evaluation (dry-run, 7 days)  — recommended               │
│  ○ Live immediately                                          │
│                                                              │
│  ☐ I have read the author's Terms of Service                 │
│                                                              │
│              [ Cancel ]     [ Confirm Install ]              │
└──────────────────────────────────────────────────────────────┘
```

## 4. Author Dashboard

Route: `/marketplace/author/dashboard`

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Author Dashboard   ·   FinTech Security Labs                                │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  [Overview] [Agents] [Revenue] [Reviews] [Support tickets] [Settings]       │
│                                                                              │
│  Summary (last 30 days)                                                      │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐    │
│  │  Gross rev    │ │  Net payout   │ │  Active       │ │  Avg fitness  │    │
│  │  $54,200      │ │  $37,940      │ │  tenants      │ │  0.87         │    │
│  │  ▲ 12%        │ │  (30% fee)    │ │  217 ▲ 8      │ │  ▲ 0.03       │    │
│  └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘    │
│                                                                              │
│  Your agents                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Name                    Version  Status      Installs  Rev 30d     │   │
│  │ ───────────────────────────────────────────────────────────────────│   │
│  │ SWIFT Fraud Hunter      1.2.0    ✓ Published  1,340    $54,200     │   │
│  │ SEPA Anomaly Detector   0.9.3    ⧗ In review  —        —           │   │
│  │ Wire Transfer Watchdog  2.0.0    ✎ Draft      —        —           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Revenue chart (12 months)                                                   │
│   $60k ┤                                         ▃▄█                         │
│   $40k ┤                                  ▂▃▅▅▇▇█                            │
│   $20k ┤                          ▁▂▃▅▇▇                                     │
│    $0  └─────────────────────────────────────────                            │
│         Apr Jun Aug Oct Dec Feb                                              │
│                                                                              │
│  Next payout                                                                 │
│  $37,940 on Apr 15  (Stripe Connect acct_1X...)   [View statement]           │
│                                                                              │
│  Recent reviews                                                              │
│  ★★★★★ "Caught a BEC attempt..." — sec-lead at RegionalBank                 │
│  ★★★★☆ "Great detection..."      — soc-analyst at CreditCo                  │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 5. Reviewer Dashboard

Route: `/marketplace/reviewer/queue` (ShieldOps internal)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Reviewer Dashboard                              Assigned to you: 3 · Queue: 11 │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Tier:  [All] [Verified] [Premier]    SLA: [Any] [<2d] [Breached]           │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Agent                       Author          Tier       Age   Status │   │
│  │ ───────────────────────────────────────────────────────────────────│   │
│  │ 🔴 SEPA Anomaly Detector    FinTech Labs    Verified   9d   BREACH │   │
│  │ 🟡 CMMC Level 2 Auditor     GovSec Inc      Verified   4d   On SLA │   │
│  │ 🟢 Shadow IT Discover       DevOps Co       Verified   1d   New    │   │
│  │ 🟢 IoT Protocol Watcher     OT Security     Premier    0d   New    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ─ Selected: SEPA Anomaly Detector v0.9.3 ─────────────────────────         │
│                                                                              │
│  Automated checks                                                            │
│   ✓ Lint     ✓ Type    ✓ Manifest    ✓ OPA    ⚠ Dep CVE (CVSS 6.1)         │
│   ✓ Semgrep  ✓ Sandbox exec (3/3 examples pass)                              │
│                                                                              │
│  Manual checklist                                      6/15 complete         │
│   ☑ Behavior matches description                                             │
│   ☑ Connectors used as declared                                              │
│   ☑ Examples cover edge cases                                                │
│   ☑ Idempotent                                                               │
│   ☑ Graceful failure                                                         │
│   ☐ Prompt injection resistance                                              │
│   ☐ Secrets handling                                                         │
│   ☐ PII handling                                                             │
│   ...                                                                        │
│                                                                              │
│  [ View code ]  [ View sandbox traces ]  [ Request changes ]  [ Certify ]   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 6. Customer Search & Filter (expanded)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  🔍  swift                                                             ×     │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Filters                                                                    │
│   ───────                                                                    │
│   Category                                                                   │
│     ☐ Security (203)                                                         │
│     ☐ Compliance (84)                                                        │
│     ☐ Observability (51)                                                     │
│     ☑ Vertical (39)                                                          │
│     ☐ AI Governance (22)                                                     │
│                                                                              │
│   Certification                                                              │
│     ☐ Community (180)                                                        │
│     ☑ Verified (203)                                                         │
│     ☐ Premier (29)                                                           │
│                                                                              │
│   Pricing                                                                    │
│     ☐ Free (142)                                                             │
│     ☐ One-time                                                               │
│     ☑ Subscription                                                           │
│     ☐ Usage-based                                                            │
│                                                                              │
│   Required connectors                                                        │
│     ☑ Splunk (only show agents compatible with my stack)                     │
│     ☑ CrowdStrike                                                            │
│     ☐ Datadog                                                                │
│                                                                              │
│   Minimum rating                                                             │
│     ○ Any  ○ ★★★+  ◉ ★★★★+  ○ ★★★★★                                         │
│                                                                              │
│   Region / data residency                                                    │
│     ☑ US  ☑ EU  ☐ APAC                                                       │
│                                                                              │
│   ────────────────────────────────────────                                  │
│   Results (3 agents match)                                                   │
│                                                                              │
│   1. SWIFT Fraud Hunter              ★ 4.8  $2,000/mo  Verified              │
│   2. SWIFT Sanctions Screener        ★ 4.5  $1,500/mo  Verified              │
│   3. SWIFT MT Message Validator      ★ 4.6  $299 once  Verified              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Notes on production implementation

- All surfaces reuse existing tokens: `--surface-0..4`, `--border-subtle/default/strong`.
- Primary CTAs use `btn-primary` (gradient + glow); secondary uses `btn-secondary`.
- Agent cards use `card-interactive` with hover-lift.
- Tab bars use `tab-bar`.
- Typography: Inter for UI, JetBrains Mono for code / version strings / connector
  lists.
- Certification badges: gray (Community), cyan (Verified), gold (Premier). Gold uses
  a subtle animated shimmer, matching the evolution champion badge pattern.
