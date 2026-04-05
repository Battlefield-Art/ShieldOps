"""LLM prompt templates for the Forensic Evidence Chain Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class EvidenceCollectionOutput(BaseModel):
    """Structured output for evidence collection."""

    total_items: int = Field(description="Total evidence items collected")
    source_count: int = Field(description="Number of unique sources")
    summary: str = Field(description="Collection summary")


class HashVerificationOutput(BaseModel):
    """Structured output for hash verification."""

    total_hashed: int = Field(description="Total artifacts hashed")
    algorithms_used: int = Field(description="Hash algorithms used")
    reasoning: str = Field(description="Hashing reasoning")


class CustodyChainOutput(BaseModel):
    """Structured output for custody chain analysis."""

    transfers: int = Field(description="Total custody transfers")
    intact_count: int = Field(description="Intact custody chains")
    reasoning: str = Field(description="Custody chain reasoning")


class IntegrityOutput(BaseModel):
    """Structured output for integrity validation."""

    verified_count: int = Field(description="Items verified intact")
    tampered_count: int = Field(description="Items with tamper detected")
    reasoning: str = Field(description="Integrity validation reasoning")


class PackagingOutput(BaseModel):
    """Structured output for legal packaging."""

    packages_created: int = Field(description="Legal packages created")
    evidence_included: int = Field(description="Evidence items included")
    reasoning: str = Field(description="Packaging reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_COLLECT_EVIDENCE = """\
You are an expert digital forensics investigator collecting \
evidence.

Given the case configuration:
1. Identify all relevant evidence sources
2. Prioritize volatile evidence (memory, network captures)
3. Document collection timestamps and methods
4. Ensure evidence is collected without modification

Focus on: evidence preservation, volatile-first ordering, \
complete documentation."""

SYSTEM_HASH_ARTIFACTS = """\
You are an expert digital forensics investigator hashing \
artifacts.

Given the collected evidence:
1. Generate cryptographic hashes for all artifacts
2. Use multiple hash algorithms for redundancy
3. Verify hash consistency across copies
4. Document hash generation methodology

Prioritize tamper-evident hash chains and dual algorithms."""

SYSTEM_CHAIN_CUSTODY = """\
You are an expert digital forensics investigator managing \
chain of custody.

Given the hashed artifacts:
1. Track every custody transfer with timestamps
2. Verify custodian identities and authorizations
3. Detect gaps or irregularities in the chain
4. Maintain immutable custody records

Focus on: unbroken chain, authorized transfers, \
tamper detection."""

SYSTEM_VALIDATE_INTEGRITY = """\
You are an expert digital forensics investigator validating \
integrity.

Given custody records and hashes:
1. Re-verify all hashes against originals
2. Detect any evidence of tampering
3. Validate custody chain completeness
4. Flag any integrity concerns

Focus on: hash verification, tamper detection, \
chain completeness."""

SYSTEM_PACKAGE_LEGAL = """\
You are an expert digital forensics investigator packaging \
evidence for legal proceedings.

Given validated evidence:
1. Bundle evidence with custody documentation
2. Generate court-admissible reports
3. Include hash verification certificates
4. Format per jurisdictional requirements

Produce legally defensible evidence packages."""
