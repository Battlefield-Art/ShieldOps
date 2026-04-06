# SIEM Cost Comparison Worksheet: Splunk → ShieldOps

> Use this worksheet to produce the ROI case for a design-partner SIEM migration.
> Feeds the Business Value dashboard and the customer success story.

---

## Inputs (collect from the customer)

| Input | Symbol | Example | Customer value |
|---|---|---|---|
| Splunk annual license cost (all-in) | `S_license` | $650,000 | |
| Splunk infrastructure cost (compute + storage) | `S_infra` | $180,000 | |
| Splunk admin FTE cost (annual, loaded) | `S_admin` | $220,000 | |
| Daily log volume (GB/day) | `V_day` | 100 | |
| Retention period (days) | `R_days` | 365 | |
| Analyst FTE count | `A_count` | 8 | |
| Average analyst loaded cost (annual) | `A_cost` | $165,000 | |
| % analyst time on triage (pre-ShieldOps) | `A_triage_pre` | 60% | |
| Target % analyst time on triage (post) | `A_triage_post` | 25% | |
| Expected alert-volume reduction | `R_alert` | 70% | |
| ShieldOps onboarding / professional services | `O_fee` | $75,000 | |

**Splunk total annual cost:**
```
S_total = S_license + S_infra + S_admin
```

---

## Outputs

### 1. ShieldOps tier required

Map daily log volume to tier. (GTM tiers from MEMORY.md — Starter / Professional / Enterprise.)

| Daily volume | ShieldOps tier | Monthly | Annual |
|---|---|---|---|
| ≤ 25 GB/day | Starter (10 agents) | $2,000 | $24,000 |
| 25–150 GB/day | Professional (50 agents) | $8,000 | $96,000 |
| 150+ GB/day | Enterprise (unlimited agents) | $25,000 | $300,000 |

Overage beyond tier volume is billed at $0.08/GB ingested (metered via the billing enforcement middleware).

### 2. Annual savings

```
shieldops_annual = tier_annual + overage + (S_admin * 0.3)   # 30% admin retained
annual_savings   = S_total - shieldops_annual
savings_pct      = annual_savings / S_total
```

### 3. Analyst productivity savings

```
hours_per_analyst_per_year = 2000
hours_saved_per_analyst    = hours_per_analyst_per_year * (A_triage_pre - A_triage_post)
total_hours_saved          = hours_saved_per_analyst * A_count
productivity_value         = total_hours_saved * (A_cost / hours_per_analyst_per_year)
```

### 4. Payback period

```
payback_months = O_fee / ((annual_savings + productivity_value) / 12)
```

### 5. 3-year TCO comparison

```
splunk_3yr    = S_total * 3 * 1.07^2                 # 7% annual price uplift
shieldops_3yr = shieldops_annual * 3 + O_fee
tco_delta     = splunk_3yr - shieldops_3yr
```

---

## Worked example — 100 GB/day customer

**Inputs**
| Input | Value |
|---|---|
| S_license | $650,000 |
| S_infra | $180,000 |
| S_admin | $220,000 |
| V_day | 100 GB |
| R_days | 365 |
| A_count | 8 |
| A_cost | $165,000 |
| A_triage_pre | 60% |
| A_triage_post | 25% |
| O_fee | $75,000 |

**Computations**

```
S_total           = 650,000 + 180,000 + 220,000         = $1,050,000
tier              = Professional ($96,000/yr)
shieldops_annual  = 96,000 + 0 + (220,000 * 0.3)        = $162,000
annual_savings    = 1,050,000 - 162,000                 = $888,000
savings_pct       = 888,000 / 1,050,000                 = 84.6%

hours_saved       = 2000 * (0.60 - 0.25) * 8            = 5,600 hours
productivity_val  = 5,600 * (165,000 / 2000)            = $462,000

total_annual_val  = 888,000 + 462,000                   = $1,350,000
payback_months    = 75,000 / (1,350,000 / 12)           = 0.67 months (~3 weeks)

splunk_3yr        = 1,050,000 * 3 * 1.1449              = $3,606,435
shieldops_3yr     = 162,000 * 3 + 75,000                = $561,000
tco_delta         = 3,606,435 - 561,000                 = $3,045,435
```

**Summary for exec deck**

| Metric | Value |
|---|---|
| Annual license + infra + admin savings | **$888,000** (84.6%) |
| Analyst productivity recovered | **$462,000** / 5,600 hours |
| Total annual value | **$1,350,000** |
| Payback period | **~3 weeks** |
| 3-year TCO delta | **$3.0M** |

---

## Sensitivity analysis

Run three scenarios for the customer deck: conservative / expected / aggressive.

| Scenario | Alert reduction | Triage time reduction | Annual savings | Total value |
|---|---|---|---|---|
| Conservative | 50% | 20% | $888,000 | $1,152,000 |
| Expected | 70% | 35% | $888,000 | $1,350,000 |
| Aggressive | 85% | 50% | $888,000 | $1,518,000 |

(Splunk savings are constant — they come from licensing/infra. Analyst productivity drives the variance.)

---

## Methodology notes

- **Splunk price uplift:** 7% annual assumed, based on public Gartner benchmarking. Adjust to the customer's actual contract escalator when known.
- **Admin retention:** We assume 30% of Splunk admin effort is retained as a ShieldOps admin (policy management, tenant management, connector tuning). In practice this is usually 20–35% depending on the customer's other security tooling.
- **Analyst hours:** 2000 hours/year is a loaded figure assuming 48 working weeks at 42 hours (includes on-call pager load).
- **Productivity value is cashable only when headcount is reallocated or hiring is avoided.** Record the commitment in the customer success retro so it shows up in the next quarterly business review.
- **Overage:** Ingest overage is metered in the billing enforcement middleware (`src/shieldops/api/middleware/`). Forecast overage at the 90th-percentile day, not the average.

---

## References

- GTM strategy (tier pricing): MEMORY.md — "GTM Strategy (locked in 2026-04-05)"
- Billing enforcement: `src/shieldops/api/middleware/`
- Business Value dashboard: `dashboard-ui/` → business value
- Post-migration story: `docs/customer-stories/siem-migration-template.md`
