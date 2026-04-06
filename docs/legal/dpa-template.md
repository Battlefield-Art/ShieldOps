# Data Processing Agreement (DPA) Template

This Data Processing Agreement ("DPA") forms part of the Master Subscription
Agreement ("MSA") between **Customer** ("Controller") and **ShieldOps, Inc.**
("Processor"). Capitalized terms not defined here have the meaning given
in the MSA.

This DPA is updated for compliance with GDPR (Regulation (EU) 2016/679),
UK GDPR, the Swiss Federal Act on Data Protection, and the California
Consumer Privacy Act / California Privacy Rights Act (CCPA/CPRA).

---

## 1. Definitions

- **Personal Data** — as defined in GDPR Article 4(1).
- **Processing** — as defined in GDPR Article 4(2).
- **Sub-processor** — any third party engaged by ShieldOps to Process
  Personal Data on behalf of Customer.
- **Customer Data** — data submitted by Customer or its end users to the
  Service, including any Personal Data contained therein.
- **Standard Contractual Clauses (SCCs)** — Module 2 (Controller to
  Processor) of the EU Commission Implementing Decision 2021/914.

## 2. Scope and roles

### 2.1 Scope
This DPA applies to ShieldOps' Processing of Personal Data on behalf of
Customer in connection with the Service.

### 2.2 Roles
- **Customer** is the Data Controller
- **ShieldOps** is the Data Processor
- For end users of Customer (e.g. Customer's employees logging into the
  ShieldOps dashboard), Customer remains the Controller

### 2.3 Categories of Data Subjects
- Customer's authorized users (employees, contractors)
- Subjects of security telemetry ingested by Customer (employees, system users)

### 2.4 Categories of Personal Data
- Account info: name, work email, role
- Authentication metadata: timestamps, IP addresses, user agents
- Telemetry references in Customer-ingested security data (usernames,
  hostnames, IP addresses)

### 2.5 Nature and purpose of Processing
- Providing the AI Security Control Plane Service
- Authentication, authorization, audit logging
- Operating the agent fleet, dashboards, and integrations
- Billing and account management
- Customer support

## 3. Customer instructions

ShieldOps will Process Personal Data only on documented instructions from
Customer, including:
- The MSA and this DPA
- Configuration choices made through the Service
- Reasonable written instructions from Customer's authorized representative

If Processor believes an instruction violates law, it will inform
Customer.

## 4. Sub-processors

### 4.1 General authorization
Customer authorizes ShieldOps to use the Sub-processors listed at
https://shieldops.io/sub-processors and any future Sub-processors added
in accordance with Section 4.2.

### 4.2 Notice of new Sub-processors
ShieldOps will notify Customer at least 30 days before adding a new
Sub-processor (via email and dashboard banner). Customer may object on
reasonable grounds (data protection or security). If the parties cannot
resolve, Customer may terminate the affected portion of the Service
without penalty.

### 4.3 Sub-processor obligations
ShieldOps will:
- Have a written agreement with each Sub-processor
- Impose data protection obligations equivalent to this DPA
- Remain fully liable to Customer for Sub-processor performance

## 5. Confidentiality

ShieldOps will ensure that personnel authorized to Process Personal Data
are bound by confidentiality obligations.

## 6. Security measures

ShieldOps implements appropriate technical and organizational measures,
including:

| Domain | Measure |
|---|---|
| Encryption | TLS 1.3 in transit; AES-256 at rest |
| Access control | Least-privilege RBAC, MFA for all employees |
| Tenant isolation | Database, query, WebSocket, rate-limit, audit-log scoped by org_id |
| Audit logging | Append-only, tenant-scoped, queryable via API |
| Backups | Encrypted, daily, 30-day retention, weekly restore tests |
| Vulnerability management | Annual third-party pentest, ongoing dependency scanning |
| Incident response | 72-hour breach notification SLA |
| Personnel | Background checks, security training annually, NDA |
| Physical | Cloud-only; AWS data center physical security |
| Disaster recovery | Multi-AZ deployment, RPO 1h, RTO 4h |

A complete description is available at
https://shieldops.io/security/measures.

## 7. Data subject rights

ShieldOps will, taking into account the nature of Processing, assist
Customer by appropriate technical and organizational measures, insofar as
possible, in fulfilling Customer's obligation to respond to data subject
requests for access, rectification, erasure, restriction, portability,
and objection.

The Service provides self-serve APIs for the following:
- Export of all Personal Data for a given user (`GET /api/v1/admin/users/{id}/export`)
- Deletion of a user (`DELETE /api/v1/admin/users/{id}`)
- Bulk Customer Data export per tenant
- Bulk tenant deletion on termination

## 8. Personal Data breach notification

ShieldOps will notify Customer without undue delay (no later than 72
hours) after becoming aware of a Personal Data Breach affecting Customer
Data. The notification will include:
- Nature of the breach (categories and approximate number of affected
  records and data subjects)
- Likely consequences
- Measures taken or proposed to address the breach
- Contact information for follow-up

## 9. Data Protection Impact Assessment (DPIA)

ShieldOps will provide reasonable assistance to Customer for any DPIA
required under GDPR Article 35.

## 10. Audits and inspections

### 10.1 Audit reports
ShieldOps maintains the following annual independent audits, which it
will share under NDA:
- SOC 2 Type II report
- Annual third-party penetration test report
- ISO 27001 (planned 2027)

### 10.2 Customer audits
Customer may audit ShieldOps' compliance with this DPA once per year, at
Customer's expense, with at least 30 days written notice, during business
hours, in a manner that does not disrupt the Service or violate other
customers' confidentiality. The above audit reports satisfy this
obligation in most cases.

## 11. International data transfers

### 11.1 Default
ShieldOps Processes Personal Data in the United States. ShieldOps offers
EU-region hosting via the Enterprise plan (additional fees apply).

### 11.2 Standard Contractual Clauses (SCCs)
For transfers of Personal Data from the EEA, UK, or Switzerland to the
United States, the parties enter into the SCCs (Module 2: Controller to
Processor) by reference. The SCCs are incorporated into this DPA as
Annex A.

### 11.3 Transfer Impact Assessment (TIA)
ShieldOps has performed a TIA confirming that the SCCs provide adequate
protection in conjunction with the technical and organizational measures
in Section 6. The TIA is available under NDA.

## 12. Return and deletion

Upon termination of the MSA:
- ShieldOps will, at Customer's choice, return or delete all Customer Data
  within 30 days
- Default behavior is deletion after 30 days unless Customer requests
  otherwise
- Backup copies are deleted within 90 days
- ShieldOps will provide written confirmation of deletion upon request

## 13. CCPA / CPRA addendum

To the extent ShieldOps Processes "personal information" of California
residents on behalf of Customer:
- ShieldOps acts as a "service provider" under CCPA
- ShieldOps will not sell or share personal information
- ShieldOps will only Process personal information for the business
  purposes described in the MSA and this DPA
- ShieldOps will assist Customer in responding to consumer requests
- Customer retains the right to take reasonable steps to ensure
  ShieldOps' compliance

## 14. Liability

The liability provisions of the MSA apply to this DPA. Nothing in this
DPA limits liability for violations of GDPR or other data protection law
where such limitation is prohibited.

## 15. Term and termination

This DPA enters into force on the Effective Date of the MSA and remains
in force for as long as ShieldOps Processes Personal Data on behalf of
Customer.

## 16. Order of precedence

In case of conflict between the MSA and this DPA, this DPA prevails for
matters of data protection. The SCCs prevail over both for transfers of
Personal Data from the EEA/UK/Switzerland.

---

## Annex A — Standard Contractual Clauses (SCCs)

Module 2 (Controller to Processor) of the EU Commission Implementing
Decision 2021/914, available at:
https://eur-lex.europa.eu/eli/dec_impl/2021/914/oj

Module clauses are incorporated by reference. The required Annexes are:

### Annex I.A — List of Parties
- **Controller:** Customer (as identified in the MSA)
- **Processor:** ShieldOps, Inc., [Address], United States

### Annex I.B — Description of Transfer
- See DPA Sections 2.3, 2.4, 2.5

### Annex I.C — Competent Supervisory Authority
- The supervisory authority of the EU Member State where Customer is
  established, or the EDPB if Customer has no establishment in the EU.

### Annex II — Technical and Organizational Measures
- See DPA Section 6

### Annex III — List of Sub-processors
- See https://shieldops.io/sub-processors

---

## Signatures

This DPA is signed electronically along with the MSA and is binding on
both parties without requiring physical signature.
