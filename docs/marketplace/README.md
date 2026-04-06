# ShieldOps Agent Marketplace

> **Status:** Design phase (Issue #232). No implementation yet.
> **Owner:** Platform PM
> **Last updated:** 2026-04-05

The ShieldOps Agent Marketplace is the planned distribution channel for third-party and
first-party LangGraph agents that plug into the ShieldOps AI Security Control Plane. It
turns our 499 built-in agents from a monolithic product into an **extensible platform**
where partners, customers, and the community can ship vertical security agents, share
revenue, and compound the data flywheel.

## Document Index

| Doc | Purpose |
|-----|---------|
| [design.md](./design.md) | Vision, architecture, trust model, competitive landscape |
| [agent-spec.md](./agent-spec.md) | `agent.yaml` manifest schema and examples |
| [certification-process.md](./certification-process.md) | Community / Verified / Premier tiers and review workflow |
| [revenue-model.md](./revenue-model.md) | Pricing models, platform fee, payouts, tax |
| [ui-wireframes.md](./ui-wireframes.md) | ASCII wireframes for browse, detail, install, dashboards |
| [developer-guide.md](./developer-guide.md) | "Build your first agent" tutorial outline |

## Roadmap

### Phase 1 — Design (Q2 2026, current)
- [x] Issue #232 design docs (this folder)
- [ ] Internal design review (Platform + Security + Legal)
- [ ] Design partner interviews (5 security vendors, 3 MSSPs)
- [ ] Finalize manifest schema, certification tiers, revenue split

### Phase 2 — MVP (Q3 2026)
- Registry service (Postgres + S3 artifact store)
- `shieldops agent publish` CLI command
- Community tier automated checks (lint, type, OPA, dep scan)
- Marketplace browse page (read-only, internal catalog only)
- First 10 internal agents re-packaged as marketplace entries (dogfooding)
- Sandboxed install into customer tenants

### Phase 3 — GA (Q4 2026 / Q1 2027)
- Verified tier (manual reviewer workflow)
- Stripe Connect payouts + revenue share
- Public marketplace launch (external authors)
- Reputation system (ratings, install counts, abuse reports)
- Premier tier (vendor partnerships: CrowdStrike, Wiz, etc.)
- Auto-update channels + deprecation policy

## FAQ

**Q: Why not just merge agents into the core repo like we do today?**
A: 499 agents is already near the ceiling for monolithic governance. A marketplace
lets vertical experts (healthcare, fintech, ICS/OT) ship without PR review bottlenecks,
and gives customers choice without bloat.

**Q: How does this relate to the `define_agent()` framework?**
A: `define_agent()` is the *authoring* contract. The marketplace is the *distribution*
channel. A marketplace agent **must** be implemented using `define_agent()` so it plugs
into the existing OPA, fitness tracker, and evolution subsystems. See
[agent-spec.md](./agent-spec.md).

**Q: Will customers be able to run arbitrary code from strangers?**
A: No. Community-tier agents run in a sandboxed evaluation environment with restricted
connectors and enforced OPA policies. Verified/Premier agents go through manual review.
See [certification-process.md](./certification-process.md).

**Q: How is this different from the OpenAI GPT Store?**
A: GPT Store distributes prompts. We distribute **full LangGraph state machines** with
tools, policies, fitness metrics, and audit trails. Our agents can take infrastructure
actions — so trust, certification, and revocation are first-class, not afterthoughts.

**Q: Does this cannibalize our own agents?**
A: No — it extends them. Our 10 launch agents remain bundled in every tier. The
marketplace targets long-tail verticals we will never build ourselves (e.g., SWIFT
fraud detection, HIPAA-specific breach response, SCADA anomaly hunting).

**Q: What's the revenue split?**
A: 70/30 (author/platform) standard, dropping to 85/15 after an author crosses $100k/yr
in marketplace revenue. See [revenue-model.md](./revenue-model.md).

**Q: Is this public?**
A: Not yet. This is internal design documentation. Do not share outside the company
until the Phase 1 design review completes.
