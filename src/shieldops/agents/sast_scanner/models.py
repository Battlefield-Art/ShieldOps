"""SAST Scanner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SASTStage(StrEnum):
    DISCOVER_FILES = "discover_files"
    PARSE_AST = "parse_ast"
    SCAN_PATTERNS = "scan_patterns"
    ANALYZE_DATAFLOW = "analyze_dataflow"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class VulnCategory(StrEnum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    BUFFER_OVERFLOW = "buffer_overflow"
    HARDCODED_SECRET = "hardcoded_secret"  # noqa: S105
    INSECURE_CRYPTO = "insecure_crypto"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"
    BROKEN_AUTH = "broken_auth"


class CodeLanguage(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    JAVA = "java"
    RUST = "rust"
    CSHARP = "csharp"
    RUBY = "ruby"


class CodeLocation(BaseModel):
    """Source code location for a finding."""

    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    column: int = 0
    snippet: str = ""
    function_name: str = ""
    language: CodeLanguage = CodeLanguage.PYTHON


class ScanFinding(BaseModel):
    """A vulnerability finding from SAST scanning."""

    id: str = ""
    rule_id: str = ""
    category: VulnCategory = VulnCategory.SQL_INJECTION
    severity: str = "medium"
    title: str = ""
    description: str = ""
    location: CodeLocation = Field(default_factory=CodeLocation)
    cwe_id: str = ""
    owasp_id: str = ""
    confidence: float = 0.0
    is_false_positive: bool = False
    remediation: str = ""
    dataflow_trace: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SASTScannerState(BaseModel):
    """Full state for the SAST Scanner agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SASTStage = SASTStage.DISCOVER_FILES
    scan_targets: list[str] = Field(default_factory=list)
    discovered_files: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_files: int = 0
    ast_results: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    dataflow_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    prioritized: list[dict[str, Any]] = Field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
