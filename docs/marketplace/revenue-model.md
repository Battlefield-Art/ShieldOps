# Revenue Share Model

> **Status:** Design (future) — Issue #232
> **See also:** [design.md](./design.md), [certification-process.md](./certification-process.md)

The marketplace is both a customer value multiplier and a revenue line. This document
specifies how authors price agents, how ShieldOps takes a platform fee, and how money
moves from customer to author.

## 1. Pricing Models

Authors choose one of five pricing models per agent version. The choice is declared
in `agent.yaml` under `pricing.model`.

### 1.1 Free
No charge to the customer. Useful for community contributions, open-source tools,
and lead-generation offerings. Platform fee: **N/A**.

### 1.2 One-time purchase
Single flat payment. Customer owns the agent perpetually for the purchased major
version. Minor and patch updates are included; major version upgrades require a new
purchase or an explicit upgrade price.

- Minimum price: **$19**
- Maximum price: **$10,000**
- Refund window: **14 days** (see §5)

### 1.3 Monthly subscription
Recurring monthly charge per tenant. Pro-rated on install date. Cancellable at any
time with service continuing until the end of the current period.

- Minimum: **$10/mo**
- Maximum: **$50,000/mo** (above this, use Enterprise license)
- Trial period: up to **30 days** configurable via `pricing.trial_period_days`

### 1.4 Annual subscription
Same as monthly but billed annually upfront, typically at a 15-20% discount.
Automatic renewal unless cancelled 30 days before term end.

### 1.5 Usage-based
Customer is billed per unit of consumption. Units are defined by the author
(`pricing.usage_unit`): scan, event, incident, MB, GB, etc. Usage is metered by the
ShieldOps runtime via `fitness_tracker.py` execution records and reported to Stripe
as metered billing events.

- Minimum unit price: **$0.001**
- Included allotment: optional `pricing.included_per_month`
- Hard cap: customer can set a monthly spend cap; requests beyond the cap are
  queued or rejected per customer preference.

### 1.6 Enterprise license (custom)
Negotiated deals above the public pricing ceiling. Handled via ShieldOps Sales with
a co-selling motion. Revenue split is contract-specific.

## 2. Platform Fee

ShieldOps takes a platform fee off the top of all paid transactions.

### 2.1 Standard tier: 30%
Applies to all authors by default. Covers:
- Payment processing (Stripe fees absorbed by ShieldOps — authors see gross price).
- Registry hosting and distribution.
- Certification review.
- Fraud protection, chargeback handling.
- Customer support for billing disputes.
- Marketplace UI, discovery, and recommendation engine.
- SBOM and compliance tooling.

### 2.2 Graduated tier: 15%
Kicks in automatically once an author crosses **$100,000 in gross marketplace revenue
in a trailing 12-month window**. The reduced fee applies to incremental revenue above
the threshold. Resets if the author drops below the threshold for two consecutive
quarters.

Example:
- Author earns $120k gross in a year.
- First $100k → $70k to author (30% fee).
- Next $20k → $17k to author (15% fee).
- Total author payout: **$87k**.

### 2.3 Premier tier: negotiated
Premier partners negotiate platform fees as part of their partnership agreement,
typically in the 15-25% range, sometimes with volume rebates, co-marketing credits,
or minimum commitments.

### 2.4 Fee on free agents
None. Free agents incur no platform fee even if they drive LLM costs — those are
passed through to the customer at their negotiated LLM rate.

## 3. Payout Schedule & Mechanics

### 3.1 Stripe Connect
Authors onboard through **Stripe Connect (Express accounts)**. ShieldOps remains the
merchant of record for customer transactions; Stripe Connect handles the downstream
split to authors. This gives us:
- Tax handling (1099 for US, VAT for EU) managed by Stripe.
- Automatic KYC/AML on the author side.
- PCI scope minimized.

### 3.2 Payout cadence
- **Monthly**, on the 15th of each month.
- Covers revenue collected for the prior calendar month, minus:
  - Platform fee
  - Refunds issued in the period
  - Chargebacks and disputes
  - Tax withholding where applicable

### 3.3 Minimum payout threshold
**$100**. Balances below the threshold roll over to the next month. Authors can
request a manual payout of any balance (including below threshold) once per
quarter.

### 3.4 Payout currency
USD by default. Stripe Connect handles FX conversion for non-US authors at
interbank rates plus a Stripe FX fee.

### 3.5 Holdback reserve
For new authors (first 6 months, or first $10k in revenue, whichever comes later),
ShieldOps holds back **10% of payouts in a reserve** to cover chargebacks and
refunds. The reserve is released after the holdback period subject to no open
disputes.

## 4. Tax Handling

### 4.1 US authors
- Stripe Connect issues **1099-K** annually for authors who exceed IRS reporting
  thresholds.
- ShieldOps does not withhold US income tax; authors are responsible for their own
  self-employment and income taxes.
- Sales tax collection: ShieldOps, as merchant of record, collects and remits US
  sales tax on customer transactions where required.

### 4.2 EU authors
- **VAT** collected by ShieldOps at customer checkout based on customer location,
  remitted by ShieldOps under the EU OSS scheme.
- Author receives net-of-VAT amounts.
- Author is responsible for their own corporate tax on payouts.

### 4.3 Other jurisdictions
- ShieldOps collects GST for Canada, Australia, India (GSTIN required), Singapore,
  Japan, and the UK.
- For jurisdictions without a direct ShieldOps registration, authors are
  responsible for their own compliance.

### 4.4 Tax documentation
Authors can download annual statements, 1099s, and per-transaction receipts from
the Author Dashboard at any time.

## 5. Refund Policy

### 5.1 One-time purchases
- **14-day unconditional refund** from date of purchase.
- After 14 days, refunds are at author discretion with ShieldOps support as
  mediator.
- Refunded amounts are clawed back from the author's next payout.

### 5.2 Subscriptions
- **Pro-rated refund** for the unused portion of a monthly subscription if
  cancelled due to a documented agent defect.
- Otherwise, no refund for the current period; service continues until end of
  period.
- Annual subscriptions: refundable within 30 days, pro-rated thereafter for
  documented defects only.

### 5.3 Usage-based
- No refund for consumed usage.
- Metering errors (confirmed by ShieldOps) result in credit to the customer's
  account and a corresponding debit to the author.

### 5.4 Fraud and chargebacks
- Chargebacks are clawed back from the author's payout, plus a **$15 dispute fee**.
- ShieldOps works with authors to contest fraudulent chargebacks; successful
  disputes return the funds to the author minus the dispute fee.
- Pattern of high chargeback rate (>1%) may result in author account review and
  potential suspension.

## 6. Revenue Reporting

Authors see a real-time dashboard with:
- Gross revenue (by day, week, month, year)
- Platform fee
- Net payout
- Installs, active tenants, churn
- Per-agent, per-version breakdown
- Refunds and chargebacks
- Next payout date and amount
- Lifetime payout total
- Downloadable CSV and PDF statements

## 7. Worked Examples

### Example A — Indie author, one-time purchase
- Agent: `hipaa-audit-bundle`, one-time $499.
- Month 1: 20 sales, 2 refunds (1 within 14 days, 1 denied).
- Gross revenue: 20 × $499 = $9,980
- Refund: 1 × $499 = $499
- Net revenue: $9,481
- Platform fee (30%): $2,844
- Author payout: **$6,637**

### Example B — Commercial vendor, subscription, graduated tier
- Agent: `swift-fraud-hunter`, $2,000/mo subscription.
- Year 1: growing from 5 to 50 customers linearly → roughly 330 customer-months.
- Gross revenue: 330 × $2,000 = $660,000
- First $100k: 30% fee → author keeps $70k
- Remaining $560k: 15% fee → author keeps $476k
- **Author payout: $546k / year** (ignoring refunds)

### Example C — Usage-based
- Agent: `deepfake-detector`, $0.10/scan, 1,000 included/mo.
- Customer scans: 5,000/mo → 4,000 billable → $400/mo.
- Gross revenue across 100 customers: $40,000/mo.
- Platform fee (30% assuming below graduated tier): $12,000
- Author payout: **$28,000/mo**

### Example D — Free agent
- Agent: `community-threat-feed-ingestor`, free.
- 2,000 installs, $0 revenue, $0 fee, $0 payout.
- Author gets install-count reputation and may upsell to a paid premium version.

## 8. Open Questions

- **LLM cost pass-through** — should authors see gross revenue before or after LLM
  costs? Proposal: LLM costs are the customer's (billed at their negotiated rate),
  author sees their gross unchanged.
- **Bundle discounts** — should we support bundles (e.g., "HIPAA + PCI + SOC 2" at
  a combined discount)? Post-GA.
- **Affiliate / referral** — should there be a referral program where MSSPs earn
  a cut for driving installs? Post-GA.
- **Reseller tier** — MSSPs wanting to white-label marketplace agents for their
  customers. Enterprise deal, handled case-by-case.
