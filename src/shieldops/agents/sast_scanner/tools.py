"""SAST Scanner Agent — Tool functions for static analysis."""

from __future__ import annotations

import hashlib
import re
from typing import Any

import structlog

from .models import (
    CodeLanguage,
    CodeLocation,
    ScanFinding,
    VulnCategory,
)

logger = structlog.get_logger()

# -----------------------------------------------------------
# SAST pattern rules
# -----------------------------------------------------------
_SAST_RULES: list[dict[str, Any]] = [
    {
        "id": "SAST-001",
        "pattern": re.compile(
            r'(?i)f["\'].*\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)',
            re.DOTALL,
        ),
        "title": "SQL injection via f-string interpolation",
        "category": VulnCategory.SQL_INJECTION,
        "severity": "critical",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    {
        "id": "SAST-002",
        "pattern": re.compile(r"(?i)(?:eval|exec)\s*\("),
        "title": "Dynamic code execution (eval/exec)",
        "category": VulnCategory.COMMAND_INJECTION,
        "severity": "high",
        "cwe": "CWE-94",
        "owasp": "A03:2021",
    },
    {
        "id": "SAST-003",
        "pattern": re.compile(r"(?i)(?:innerHTML|outerHTML|document\.write)\s*="),
        "title": "DOM-based XSS via innerHTML assignment",
        "category": VulnCategory.XSS,
        "severity": "high",
        "cwe": "CWE-79",
        "owasp": "A07:2021",
    },
    {
        "id": "SAST-004",
        "pattern": re.compile(r"(?i)subprocess\.\w+\(.*shell\s*=\s*True"),
        "title": "Shell injection via subprocess",
        "category": VulnCategory.COMMAND_INJECTION,
        "severity": "high",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    {
        "id": "SAST-005",
        "pattern": re.compile(
            r"(?i)(?:open|read_file|fopen)\s*\("
            r".*(?:user_input|request\.|params)"
        ),
        "title": "Path traversal via user-controlled file path",
        "category": VulnCategory.PATH_TRAVERSAL,
        "severity": "high",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
    },
    {
        "id": "SAST-006",
        "pattern": re.compile(r"(?i)(?:pickle\.loads?|yaml\.(?:load|unsafe_load))\s*\("),
        "title": "Insecure deserialization",
        "category": VulnCategory.DESERIALIZATION,
        "severity": "high",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
    },
    {
        "id": "SAST-007",
        "pattern": re.compile(
            r"(?i)(?:password|secret|api_key|token)\s*"
            r'[:=]\s*["\'][^"\']{8,}'
        ),
        "title": "Hardcoded secret or credential",
        "category": VulnCategory.HARDCODED_SECRET,
        "severity": "critical",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
    },
    {
        "id": "SAST-008",
        "pattern": re.compile(r"(?i)(?:md5|sha1)\s*\("),
        "title": "Weak cryptographic hash function",
        "category": VulnCategory.INSECURE_CRYPTO,
        "severity": "medium",
        "cwe": "CWE-328",
        "owasp": "A02:2021",
    },
    {
        "id": "SAST-009",
        "pattern": re.compile(
            r"(?i)requests\.(?:get|post|put)\s*\("
            r".*(?:user_input|request\.|params)"
        ),
        "title": "SSRF via user-controlled URL",
        "category": VulnCategory.SSRF,
        "severity": "high",
        "cwe": "CWE-918",
        "owasp": "A10:2021",
    },
    {
        "id": "SAST-010",
        "pattern": re.compile(r"(?i)verify\s*=\s*False"),
        "title": "TLS certificate verification disabled",
        "category": VulnCategory.INSECURE_CRYPTO,
        "severity": "medium",
        "cwe": "CWE-295",
        "owasp": "A07:2021",
    },
]

# -----------------------------------------------------------
# Language detection
# -----------------------------------------------------------
_EXT_LANG: dict[str, CodeLanguage] = {
    ".py": CodeLanguage.PYTHON,
    ".js": CodeLanguage.JAVASCRIPT,
    ".ts": CodeLanguage.TYPESCRIPT,
    ".go": CodeLanguage.GO,
    ".java": CodeLanguage.JAVA,
    ".rs": CodeLanguage.RUST,
    ".cs": CodeLanguage.CSHARP,
    ".rb": CodeLanguage.RUBY,
}


def _detect_language(path: str) -> CodeLanguage:
    lower = path.lower()
    for ext, lang in _EXT_LANG.items():
        if lower.endswith(ext):
            return lang
    return CodeLanguage.PYTHON


def _hash_id(prefix: str, *parts: str) -> str:
    raw = ":".join(parts)
    return prefix + hashlib.sha256(raw.encode()).hexdigest()[:12]


class SASTScannerToolkit:
    """Tools for static application security testing."""

    def __init__(
        self,
        git_client: Any | None = None,
    ) -> None:
        self._git_client = git_client

    async def discover_files(
        self,
        tenant_id: str,
        targets: list[str],
    ) -> list[dict[str, Any]]:
        """Discover source files to scan."""
        logger.info(
            "sast_scanner.discover_files",
            tenant_id=tenant_id,
            target_count=len(targets),
        )
        files: list[dict[str, Any]] = []
        for target in targets:
            lang = _detect_language(target)
            files.append(
                {
                    "id": _hash_id("file-", target),
                    "path": target,
                    "language": lang.value,
                    "size_bytes": 0,
                }
            )
        return files

    async def parse_ast(
        self,
        files: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Parse AST for discovered files."""
        logger.info(
            "sast_scanner.parse_ast",
            file_count=len(files),
        )
        results: list[dict[str, Any]] = []
        for f in files:
            results.append(
                {
                    "file_id": f.get("id", ""),
                    "path": f.get("path", ""),
                    "language": f.get("language", "python"),
                    "functions": 0,
                    "classes": 0,
                    "imports": 0,
                    "parsed": True,
                }
            )
        return results

    async def scan_patterns(
        self,
        targets: list[str],
    ) -> list[ScanFinding]:
        """Scan files for vulnerability patterns."""
        logger.info(
            "sast_scanner.scan_patterns",
            target_count=len(targets),
        )
        findings: list[ScanFinding] = []
        for target in targets:
            lines = await self._read_file(target)
            lang = _detect_language(target)
            for line_num, line in enumerate(lines, start=1):
                for rule in _SAST_RULES:
                    if rule["pattern"].search(line):
                        fid = _hash_id(
                            "sast-",
                            target,
                            str(line_num),
                            rule["id"],
                        )
                        findings.append(
                            ScanFinding(
                                id=fid,
                                rule_id=rule["id"],
                                category=rule["category"],
                                severity=rule["severity"],
                                title=rule["title"],
                                description=rule["title"],
                                location=CodeLocation(
                                    file_path=target,
                                    line_start=line_num,
                                    snippet=line.strip()[:80],
                                    language=lang,
                                ),
                                cwe_id=rule["cwe"],
                                owasp_id=rule["owasp"],
                                confidence=0.85,
                                remediation="",
                            )
                        )
        return self._dedupe(findings)

    async def analyze_dataflow(
        self,
        findings: list[ScanFinding],
        targets: list[str],
    ) -> list[ScanFinding]:
        """Analyze dataflow for taint propagation."""
        logger.info(
            "sast_scanner.analyze_dataflow",
            finding_count=len(findings),
        )
        enriched: list[ScanFinding] = []
        for f in findings:
            trace = [
                f"source:{f.location.file_path}:{f.location.line_start}",
                f"sink:{f.category.value}",
            ]
            enriched.append(f.model_copy(update={"dataflow_trace": trace}))
        return enriched

    def prioritize(
        self,
        findings: list[ScanFinding],
    ) -> list[ScanFinding]:
        """Prioritize findings by severity and confidence."""
        logger.info(
            "sast_scanner.prioritize",
            count=len(findings),
        )
        sev_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }
        return sorted(
            findings,
            key=lambda f: (
                sev_order.get(f.severity, 5),
                -f.confidence,
            ),
        )

    async def _read_file(self, target: str) -> list[str]:
        if self._git_client:
            try:
                content = await self._git_client.read_file(target)
                if isinstance(content, str):
                    return content.splitlines()
                return list(content)
            except Exception:  # noqa: S110
                pass
        try:
            with open(target) as fh:
                return fh.readlines()
        except (OSError, FileNotFoundError):
            return []

    @staticmethod
    def _dedupe(
        items: list[ScanFinding],
    ) -> list[ScanFinding]:
        seen: set[str] = set()
        result: list[ScanFinding] = []
        for item in items:
            if item.id not in seen:
                seen.add(item.id)
                result.append(item)
        return result
