# ShieldOps Agent Marketplace — Design Document

> **Issue:** #232
> **Status:** Design (future)
> **Author:** Platform Team
> **Reviewers:** Security, Legal, GTM

## 1. Vision

ShieldOps today ships 499 LangGraph agents across security, compliance, observability,
and operations. They are excellent horizontal primitives — but every enterprise we talk
to asks the same next question:

> "Can it understand my _specific_ environment? SWIFT MT messages? FDA 21 CFR Part 11?
> SCADA Modbus traffic? The weird in-house IAM system we built in 2012?"

The honest answer is: we will never ship 10,000 vertical agents ourselves. But we can
build the **distribution rail** that lets 10,000 vertical experts ship them on top of us.

**The marketplace is ShieldOps' bet on network effects.** A vendor who publishes a
"SWIFT Fraud Hunter" agent on ShieldOps reaches every bank customer instantly, without
having to build their own control plane. A Fortune 500 SOC can publish a private agent
to their internal registry and reuse it across business units. A community author can
build a niche tool and earn revenue.

### Why a marketplace, not a plugin folder?

1. **Network effects** — every new agent makes the platform more valuable to every
   existing customer. Every new customer is a bigger distribution pool for every
   existing agent author.
2. **Vertical coverage without core team scaling** — we stay focused on the control
   plane; partners handle vertical depth.
3. **Partner enablement** — CrowdStrike, Wiz, Splunk, Snyk all want to ship value into
   the AI security workflow. A marketplace gives them a legitimate channel.
4. **Data flywheel** — marketplace usage telemetry (install counts, fitness scores,
   ratings) feeds back into our own agent quality and prompt evolution.
5. **Revenue line** — platform fee on paid agents becomes a high-margin revenue stream
   as the catalog grows.

### Non-goals

- Replacing our 10 launch agents. Those remain bundled and free.
- Becoming an app store for generic LLM prompts. We distribute **executable, policy-
  governed, fitness-tracked LangGraph agents** — not GPTs.
- Hosting arbitrary containers. Agents must be implemented on the `define_agent()`
  framework so we can govern them.

## 2. User Personas

### P1 — Agent Author (developer)
- **Examples:** security engineer at a MSSP, indie researcher, CrowdStrike PM,
  Fortune 500 detection engineer.
- **Goals:** ship a vertical agent quickly, earn revenue or reputation, iterate based
  on customer feedback.
- **Pains today:** no distribution channel for LangGraph-based security automation;
  forced to maintain forks of ShieldOps or ship standalone products.
- **Needs from marketplace:** clear spec, fast certification, analytics, payouts.

### P2 — Agent Consumer (SOC analyst / security engineer / platform operator)
- **Examples:** Tier-2 SOC analyst at a bank, DevSecOps lead at a SaaS company, MSSP
  operator managing 30 tenants.
- **Goals:** solve a specific problem (fraud, insider threat, compliance gap) without
  writing code or waiting for the ShieldOps roadmap.
- **Pains today:** have to file feature requests, wait quarters, or build in-house.
- **Needs from marketplace:** trustworthy agents, one-click install, clear pricing,
  easy rollback.

### P3 — Platform Operator (ShieldOps admin at customer org)
- **Examples:** Security architect responsible for the ShieldOps deployment.
- **Goals:** govern what agents are allowed, enforce approval workflows, audit third-
  party code, manage spend.
- **Pains today:** N/A (no marketplace yet).
- **Needs from marketplace:** certification signals, policy controls, install gating,
  budget caps, bulk revocation, SBOM, CVE alerts.

### P4 — Marketplace Reviewer (ShieldOps internal role)
- **Goals:** ensure certified agents are safe, performant, correct, documented.
- **Needs:** reviewer dashboard, automated check results, audit trail, escalation
  path to legal/security.

## 3. High-Level Architecture

```
                    ┌────────────────────────────────────┐
                    │    marketplace.shieldops.ai (UI)   │
                    │  browse / detail / author dashboard│
                    └────────────────┬───────────────────┘
                                     │
                ┌────────────────────┼────────────────────┐
                │                    │                    │
        ┌───────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
        │ Registry API   │  │ Cert Pipeline   │  │ Billing/Payouts │
        │ (FastAPI)      │  │ (GitHub Actions │  │ (Stripe Connect)│
        │                │  │  + reviewer UI) │  │                 │
        └───────┬────────┘  └────────┬────────┘  └────────┬────────┘
                │                    │                    │
                └─────────┬──────────┴────────────────────┘
                          │
                ┌─────────▼──────────┐
                │ Postgres + S3      │
                │ - agent metadata   │
                │ - versions         │
                │ - signed artifacts │
                │ - reviews/ratings  │
                └─────────┬──────────┘
                          │
           ┌──────────────┴───────────────┐
           │                              │
    ┌──────▼───────┐              ┌───────▼────────┐
    │ Customer     │              │ Sandbox Eval   │
    │ Tenant       │              │ Environment    │
    │ (installs)   │              │ (pre-publish)  │
    └──────────────┘              └────────────────┘
```

### Components

**Registry Service** — authoritative catalog. Stores agent manifests, versions,
signed artifacts (S3), ratings, install counts, and metadata. REST API at
`/api/v1/marketplace/`. Reuses ShieldOps' existing FastAPI + Postgres stack.

**Certification Pipeline** — GitHub Actions workflow triggered on agent submission.
Runs lint, type check, OPA policy validation, dependency CVE scan, malicious-pattern
scan (semgrep rules), and deploys to the sandbox for behavioral tests. Produces a
signed certification report.

**Sandbox Evaluation Environment** — an isolated ShieldOps tenant (separate Postgres
schema, fake connectors, scripted fixtures) where agents are executed pre-publish.
Uses the existing `define_agent()` runtime with resource quotas enforced.

**Runtime Sandbox (at customer)** — when an agent is installed at a customer tenant,
it runs in the same process as core ShieldOps but with a restricted connector set
(declared in its manifest), enforced OPA policies, and its fitness tracked via the
existing `fitness_tracker.py`. Community-tier agents cannot access connectors not
listed in their manifest; Verified/Premier agents may request elevated scopes.

**Billing & Payouts** — Stripe Connect for author payouts. Existing ShieldOps Stripe
integration handles customer-side billing; we extend it with marketplace line items
and author Connect accounts. See [revenue-model.md](./revenue-model.md).

**Marketplace UI** — new pages under `dashboard-ui/src/pages/marketplace/`: browse,
detail, install, author dashboard, reviewer dashboard. Reuses the existing surface/
depth design system.

## 4. Trust Model

Trust in the marketplace is layered. No single mechanism is sufficient; we combine
all of them.

### Layer 1 — Signed agents
Every published agent artifact is signed by the ShieldOps signing key (for
certification attestation) and optionally co-signed by the author's key. The signature
covers the manifest, node code, prompts, and test fixtures. Installation verifies the
signature before loading; tampered artifacts are refused.

### Layer 2 — Certification tiers
Three tiers with escalating trust (see [certification-process.md](./certification-process.md)):

| Tier | Review | Badge | Sandbox scope | Allowed connectors |
|------|--------|-------|---------------|---------------------|
| **Community** | Automated only | gray | Restricted | Read-only, non-destructive |
| **Verified** | Manual review + automated | blue | Standard | Declared in manifest |
| **Premier** | Partnership, continuous audit | gold | Full | Any (with customer consent) |

### Layer 3 — Runtime OPA policies
Every marketplace agent action is evaluated against the customer's OPA policy set
before execution, identical to first-party agents. A malicious agent cannot bypass
the policy layer because it runs in the same execution harness.

### Layer 4 — Reputation
Install counts, star ratings, abuse reports, and aggregate fitness scores (pulled
from `fitness_tracker.py`) are shown on the agent detail page. Low-fitness or high-
abuse agents are auto-flagged for review and can be unlisted.

### Layer 5 — Revocation
Any agent can be revoked (see [certification-process.md](./certification-process.md)).
Revoked agents are blocklisted globally — customer tenants refuse to execute them on
next heartbeat, and the UI shows a red banner with migration guidance.

## 5. Submission Flow

```
Author                           ShieldOps                        Customer
------                           ---------                        --------

1. `shieldops agent init` ──►
   scaffolds agent.yaml + nodes
2. local dev + test
3. `shieldops agent publish` ──► 4. Upload to staging bucket
                                 5. Trigger cert pipeline
                                    - lint
                                    - type check
                                    - OPA validate
                                    - dep CVE scan
                                    - semgrep rules
                                    - sandbox exec
                                 6. If Community tier: auto-publish
                                    If Verified: queue for reviewer
                                 7. Reviewer dashboard ──► manual
                                    checklist, sign-off
                                 8. Sign artifact, write to registry
                                 9. Publish webhook ──►────────────► 10. Visible in
                                                                         marketplace
                                                                     11. One-click install
                                                                     12. Runtime sandbox
                                                                         + OPA gates
```

## 6. Discovery

Customers discover agents through:

- **Browse by category** — security (threat hunting, IR, forensics, DLP), compliance,
  cloud, observability, AI governance, vertical (healthcare, fintech, ICS/OT).
- **Search** — full-text over name, description, author, tags. Typo tolerance.
- **Filters** — certification tier, pricing model, required connectors, supported
  regions, minimum rating.
- **Recommended for you** — based on the customer's installed connectors, industry
  tag, and current agent fleet. Surfaces complementary agents (e.g., if you have
  Splunk + CrowdStrike, recommend agents that use both).
- **Install count & rating** — social proof.
- **Editor's picks** — curated by the ShieldOps team (weekly rotation).
- **"Used by similar orgs"** — aggregate signal, respects tenant privacy (only shown
  once N≥50 installs across tenants of similar industry/size).

## 7. Installation

One-click install flow:

1. Customer clicks **Install** on agent detail page.
2. System checks:
   - Required connectors are present in the tenant. Missing → prompt to install.
   - Required OPA policies are compatible with tenant policy set.
   - Tenant has budget for paid agents.
   - Platform operator approval (if gated).
3. Show install confirmation with scope summary: "This agent will be allowed to read
   from Splunk and CrowdStrike, and write incidents to PagerDuty. It will NOT be
   allowed to terminate EC2 instances."
4. User confirms.
5. System pulls signed artifact, verifies signature, registers with agent fleet.
6. First execution runs in **evaluation mode** (dry-run, no external side effects)
   for a configurable trial period (default 7 days or 100 executions).
7. After trial, agent graduates to live mode pending operator sign-off.

### Dependency resolution
Agents can declare dependencies on other marketplace agents (e.g., a compliance agent
might depend on `evidence_collector`). Dependency graph is resolved at install time;
transitive deps must themselves be certified at the same or higher tier.

## 8. Updates

### Versioning
Semantic versioning: `MAJOR.MINOR.PATCH`.
- **Patch** — bug fix, prompt tweak. Backward compatible. Auto-updates default on.
- **Minor** — new capability, new optional config. Backward compatible. Auto-update
  configurable.
- **Major** — breaking change (new required connector, changed output schema). Always
  opt-in. Old version remains installable for 90 days.

### Update channels
- **Stable** (default) — patch + minor auto-updates after 48h soak.
- **Edge** — immediate updates, for power users.
- **Pinned** — manual updates only.

### Deprecation policy
Authors must give **90 days notice** before deprecating a version. Deprecation banner
shows in the dashboard. After 90 days, deprecated version stops receiving updates but
remains executable; after 180 days, it is removed from the catalog (existing installs
continue to function with a warning until customer migrates).

## 9. Revenue Model (summary)

See [revenue-model.md](./revenue-model.md) for full details.

| Model | Example | Platform fee |
|-------|---------|--------------|
| Free | Community-contributed threat feeds agent | N/A |
| One-time purchase | "HIPAA Audit Bundle" — $499 | 30% |
| Monthly subscription | "SWIFT Fraud Hunter" — $2,000/mo | 30% → 15% after $100k/yr |
| Usage-based | "Deepfake Detector" — $0.10/scan | 30% → 15% |
| Enterprise license | "ICS/OT Bundle" — custom | Negotiated |

Payouts via Stripe Connect, monthly, $100 minimum threshold.

## 10. Competitive Landscape

| Platform | What they distribute | Trust model | Monetization | Lessons for us |
|----------|---------------------|-------------|--------------|----------------|
| **OpenAI GPT Store** | System prompts + tools | Light review, no revenue share initially | Rev share launched late | Don't ship without a monetization story; authors lose motivation |
| **Hugging Face** | Models + datasets | Community ratings, no certification | Mostly free, Spaces paid | Discovery UX is excellent; certification is a gap |
| **Cursor extensions / VSCode marketplace** | IDE extensions | Publisher verification, telemetry-based trust | Free (VSCode), mixed (Cursor) | Publisher verification is table stakes; review must be fast |
| **Salesforce AppExchange** | CRM apps | Rigorous security review (6-12 weeks) | 15-25% platform fee | Gold standard for enterprise trust; too slow for indie devs |
| **AWS Marketplace** | SaaS, AMIs, ML models | AWS-managed review, contractual liability | 3% platform fee | Enterprise procurement integration (PO flow) is critical |
| **Snowflake Native Apps** | Data apps in-tenant | Manual review, runs in customer's Snowflake | Revenue share via Snowflake billing | Great model for in-tenant execution — closest to ours |

### Our differentiators
1. **Executable agents**, not prompts — richer value, higher trust requirements.
2. **Policy-governed runtime** — we can enforce safety the way GPT Store cannot.
3. **Fitness-tracked** — objective quality signal from `fitness_tracker.py`, not
   just star ratings.
4. **Enterprise-first** — SOC 2 + OPA + audit trail + SBOM from day one.
5. **In-tenant execution** — the agent runs inside the customer's ShieldOps deployment,
   so data never leaves their environment (similar to Snowflake Native Apps).

## 11. Open Questions

- **Liability** — when a marketplace agent causes an incident, who is liable? Current
  thinking: author liable for code, ShieldOps liable for runtime enforcement, customer
  liable for approval decisions. Needs legal review.
- **Cross-tenant learning** — can marketplace agents contribute to the fleet-wide
  learning bus? Probably no by default, yes with explicit author + customer consent.
- **Private marketplaces** — should enterprise customers be able to run their own
  private marketplace for internal agents? Yes, post-GA.
- **Air-gapped customers** — offline catalog snapshot + manual signature verification.
  Post-GA.
- **LLM cost attribution** — marketplace agents consume LLM tokens. Who pays? Proposal:
  customer pays LLM costs at their negotiated rate, author sees anonymized usage stats.
- **Export controls** — some vertical agents (e.g., cryptography, dual-use) may be
  subject to export controls. Need country allowlists in the manifest.
