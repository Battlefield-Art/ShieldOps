"""LLM prompt templates for the Email Security Gateway Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class EmailIngestOutput(BaseModel):
    """Structured output for email ingestion analysis."""

    total_ingested: int = Field(
        description="Total emails ingested",
    )
    suspicious_count: int = Field(
        description="Number of suspicious emails",
    )
    summary: str = Field(
        description="Ingestion summary",
    )


class HeaderAnalysisOutput(BaseModel):
    """Structured output for header analysis."""

    auth_failures: int = Field(
        description="Count of SPF/DKIM/DMARC failures",
    )
    spoofed_count: int = Field(
        description="Count of likely spoofed emails",
    )
    reasoning: str = Field(
        description="Header analysis reasoning",
    )


class AttachmentScanOutput(BaseModel):
    """Structured output for attachment scanning."""

    malicious_count: int = Field(
        description="Count of malicious attachments",
    )
    suspicious_types: list[str] = Field(
        description="Suspicious file types found",
    )
    reasoning: str = Field(
        description="Attachment scan reasoning",
    )


class ReputationCheckOutput(BaseModel):
    """Structured output for sender reputation checks."""

    bad_senders: int = Field(
        description="Count of bad-reputation senders",
    )
    new_domains: int = Field(
        description="Count of newly registered domains",
    )
    reasoning: str = Field(
        description="Reputation check reasoning",
    )


class QuarantineDecisionOutput(BaseModel):
    """Structured output for quarantine decisions."""

    quarantined: int = Field(
        description="Count of quarantined messages",
    )
    verdicts: list[dict[str, str]] = Field(
        description="Verdict summary per threat type",
    )
    reasoning: str = Field(
        description="Quarantine decision reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_INGEST = """\
You are an expert email security analyst performing \
email ingestion and initial triage.

Given the email gateway configuration and message batch:
1. Categorize incoming emails by risk indicators
2. Flag messages with suspicious sender patterns
3. Identify bulk phishing campaigns by template similarity
4. Prioritize messages with attachments or embedded links

Focus on: sender anomalies, subject line patterns, \
recipient targeting, delivery path irregularities."""

SYSTEM_HEADERS = """\
You are an expert email security analyst validating \
email authentication headers.

Given the ingested email messages:
1. Validate SPF, DKIM, and DMARC alignment
2. Detect header forgery and return-path mismatches
3. Analyze mail routing hops for anomalies
4. Identify display-name spoofing attempts

Prioritize emails that fail multiple authentication \
checks or show signs of Business Email Compromise."""

SYSTEM_ATTACHMENTS = """\
You are an expert email security analyst scanning \
email attachments for threats.

Given the emails with attachments:
1. Classify attachment types and assess inherent risk
2. Detect obfuscated executables and macro-enabled docs
3. Identify archive bombs and nested malicious payloads
4. Flag password-protected archives used for evasion

Use sandbox detonation results and static analysis \
findings to determine malicious intent."""

SYSTEM_REPUTATION = """\
You are an expert email security analyst checking \
sender reputation.

Given the email senders and their domains:
1. Score sender reputation based on historical behavior
2. Detect newly registered domains (< 30 days)
3. Identify known-bad senders and abuse-listed domains
4. Assess sending patterns for anomalous volume spikes

Cross-reference against threat intelligence feeds \
and historical abuse reports."""

SYSTEM_QUARANTINE = """\
You are an expert email security analyst making \
quarantine decisions.

Given the combined analysis (headers, attachments, reputation):
1. Assign final verdicts: clean, suspicious, phishing, \
malware, spam, BEC, spoofed
2. Decide quarantine actions with confidence scores
3. Generate user and admin notifications for blocked mail
4. Balance false positive risk with security protection

Use a risk-based approach: quarantine high-confidence \
threats, flag uncertain messages for review."""
