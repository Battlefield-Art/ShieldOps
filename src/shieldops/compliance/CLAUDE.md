# compliance/ — Compliance Engine Modules

100+ compliance engines for evidence collection, audit, regulatory policy, and AI compliance.

## Domains
- Evidence collection + packaging
- Audit trail + compliance mapping
- Regulatory policy enforcement
- Cost governance
- AI compliance (EU AI Act, NIST AI RMF, ISO 42001)
- Data encryption + PII detection

## Key Frameworks
- HIPAA (6yr retention)
- SOC 2 (1yr retention)
- PCI DSS (1yr retention)
- GDPR (right to deletion)
- FedRAMP (NIST 800-53)

## Engine Pattern
Same as `security/CLAUDE.md` — 3 StrEnums, 3 Pydantic models, Engine class.

Use `add_record(**kwargs)` for compliance engines.

## Key Files
- `ai_act_compliance_engine.py` — EU AI Act (Articles 6/9/10/13/14)
- `nist_ai_rmf_engine.py` — NIST AI Risk Management Framework
- `data_encryption.py` — AES field encryption
- `pii_detector.py` — PII detection (SSN, CC, email, phone, AWS keys, PHI)
