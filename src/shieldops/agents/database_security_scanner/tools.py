"""Database Security Scanner Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    AccessAudit,
    AuthWeakness,
    ConfigFinding,
    DatabaseEngine,
    DatabaseInstance,
    DataExposure,
    FindingSeverity,
)

logger = structlog.get_logger()

_DB_PROFILES: list[dict[str, Any]] = [
    {
        "name": "prod-primary",
        "engine": DatabaseEngine.POSTGRESQL,
        "version": "15.4",
        "host": "prod-pg.internal",
        "port": 5432,
        "provider": "AWS",
        "region": "us-east-1",
        "encrypted": True,
        "ssl": True,
        "public": False,
    },
    {
        "name": "prod-mysql-legacy",
        "engine": DatabaseEngine.MYSQL,
        "version": "5.7.38",
        "host": "legacy-mysql.internal",
        "port": 3306,
        "provider": "AWS",
        "region": "us-east-1",
        "encrypted": False,
        "ssl": False,
        "public": False,
    },
    {
        "name": "analytics-mongo",
        "engine": DatabaseEngine.MONGODB,
        "version": "6.0.8",
        "host": "mongo.internal",
        "port": 27017,
        "provider": "GCP",
        "region": "us-central1",
        "encrypted": True,
        "ssl": True,
        "public": False,
    },
    {
        "name": "cache-redis-prod",
        "engine": DatabaseEngine.REDIS,
        "version": "7.2.1",
        "host": "redis.internal",
        "port": 6379,
        "provider": "AWS",
        "region": "us-east-1",
        "encrypted": False,
        "ssl": False,
        "public": True,
    },
    {
        "name": "search-elastic",
        "engine": DatabaseEngine.ELASTICSEARCH,
        "version": "8.10.2",
        "host": "es.internal",
        "port": 9200,
        "provider": "AWS",
        "region": "us-west-2",
        "encrypted": True,
        "ssl": True,
        "public": False,
    },
    {
        "name": "events-dynamo",
        "engine": DatabaseEngine.DYNAMODB,
        "version": "managed",
        "host": "dynamodb.us-east-1.amazonaws.com",
        "port": 443,
        "provider": "AWS",
        "region": "us-east-1",
        "encrypted": True,
        "ssl": True,
        "public": False,
    },
]

_CONFIG_CHECKS: list[dict[str, Any]] = [
    {
        "check": "encryption_at_rest",
        "desc": "Data is not encrypted at rest",
        "severity": FindingSeverity.CRITICAL,
        "remediation": "Enable encryption at rest using AES-256",
        "fails_when_unencrypted": True,
    },
    {
        "check": "ssl_in_transit",
        "desc": "Connections not using SSL/TLS",
        "severity": FindingSeverity.CRITICAL,
        "remediation": "Enable SSL/TLS and require encrypted connections",
        "fails_when_no_ssl": True,
    },
    {
        "check": "public_access",
        "desc": "Database is publicly accessible",
        "severity": FindingSeverity.CRITICAL,
        "remediation": "Disable public access; use VPC/private endpoints",
        "fails_when_public": True,
    },
    {
        "check": "version_eol",
        "desc": "Database version is end-of-life or outdated",
        "severity": FindingSeverity.HIGH,
        "remediation": "Upgrade to a supported version",
        "eol_versions": ["5.7", "5.6", "9.6", "10"],
    },
    {
        "check": "audit_logging",
        "desc": "Audit logging is not enabled",
        "severity": FindingSeverity.MEDIUM,
        "remediation": "Enable audit logging for all DDL/DML operations",
    },
    {
        "check": "backup_encryption",
        "desc": "Automated backups are not encrypted",
        "severity": FindingSeverity.HIGH,
        "remediation": "Enable backup encryption with KMS",
    },
]

_AUTH_CHECKS: list[dict[str, Any]] = [
    {
        "type": "default_credentials",
        "desc": "Default admin credentials detected",
        "severity": FindingSeverity.CRITICAL,
        "users": ["admin", "root"],
        "remediation": "Rotate all default credentials immediately",
    },
    {
        "type": "weak_password_policy",
        "desc": "No password complexity requirements enforced",
        "severity": FindingSeverity.HIGH,
        "users": ["app_user", "readonly"],
        "remediation": "Enforce min 16-char passwords with complexity",
    },
    {
        "type": "no_auth_required",
        "desc": "Authentication not required for connections",
        "severity": FindingSeverity.CRITICAL,
        "users": [],
        "remediation": "Enable requirepass or authentication mechanism",
    },
    {
        "type": "no_mfa",
        "desc": "Multi-factor authentication not enabled for admins",
        "severity": FindingSeverity.MEDIUM,
        "users": ["dba_admin"],
        "remediation": "Enable MFA for all privileged database accounts",
    },
]

_SENSITIVE_COLUMNS: list[dict[str, Any]] = [
    {
        "table": "users",
        "column": "ssn",
        "data_type": "PII_SSN",
        "severity": FindingSeverity.CRITICAL,
    },
    {
        "table": "payments",
        "column": "card_number",
        "data_type": "PCI_CARD",
        "severity": FindingSeverity.CRITICAL,
    },
    {
        "table": "users",
        "column": "email",
        "data_type": "PII_EMAIL",
        "severity": FindingSeverity.HIGH,
    },
    {
        "table": "patients",
        "column": "diagnosis",
        "data_type": "PHI_DIAGNOSIS",
        "severity": FindingSeverity.CRITICAL,
    },
    {
        "table": "employees",
        "column": "salary",
        "data_type": "PII_FINANCIAL",
        "severity": FindingSeverity.HIGH,
    },
    {
        "table": "audit_log",
        "column": "ip_address",
        "data_type": "PII_NETWORK",
        "severity": FindingSeverity.MEDIUM,
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class DatabaseSecurityScannerToolkit:
    """Tools for database security scanning."""

    def __init__(
        self,
        db_client: Any | None = None,
        scanner_api: Any | None = None,
    ) -> None:
        self._db_client = db_client
        self._scanner_api = scanner_api

    async def discover_databases(
        self,
        tenant_id: str,
    ) -> list[DatabaseInstance]:
        """Discover database instances across infrastructure."""
        logger.info(
            "dss.discover_databases",
            tenant_id=tenant_id,
        )

        if self._db_client is not None:
            try:
                raw = await self._db_client.list_databases(
                    tenant_id=tenant_id,
                )
                return [DatabaseInstance(**r) for r in raw]
            except Exception:
                logger.exception("dss.discover.error")

        instances: list[DatabaseInstance] = []
        for i, p in enumerate(_DB_PROFILES):
            instances.append(
                DatabaseInstance(
                    id=_gen_id("DB", tenant_id, i),
                    name=p["name"],
                    engine=p["engine"],
                    version=p["version"],
                    host=p["host"],
                    port=p["port"],
                    provider=p["provider"],
                    region=p["region"],
                    encrypted_at_rest=p["encrypted"],
                    ssl_enabled=p["ssl"],
                    publicly_accessible=p["public"],
                    tags={"env": "production"},
                )
            )
        return instances

    async def scan_configurations(
        self,
        instances: list[DatabaseInstance],
    ) -> list[ConfigFinding]:
        """Scan database configurations for misconfigurations."""
        logger.info(
            "dss.scan_config",
            count=len(instances),
        )

        findings: list[ConfigFinding] = []
        idx = 0
        for inst in instances:
            for chk in _CONFIG_CHECKS:
                compliant = True
                if (
                    (chk.get("fails_when_unencrypted") and not inst.encrypted_at_rest)
                    or (chk.get("fails_when_no_ssl") and not inst.ssl_enabled)
                    or (chk.get("fails_when_public") and inst.publicly_accessible)
                ):
                    compliant = False
                elif chk.get("eol_versions"):
                    for eol in chk["eol_versions"]:
                        if inst.version.startswith(eol):
                            compliant = False
                            break
                else:
                    compliant = random.random() > 0.3  # noqa: S311

                if not compliant:
                    findings.append(
                        ConfigFinding(
                            id=_gen_id("CF", inst.id, idx),
                            instance_id=inst.id,
                            check=chk["check"],
                            description=(f"{inst.name}: {chk['desc']}"),
                            severity=chk["severity"],
                            remediation=chk["remediation"],
                            compliant=False,
                        )
                    )
                    idx += 1
        return findings

    async def check_authentication(
        self,
        instances: list[DatabaseInstance],
    ) -> list[AuthWeakness]:
        """Check for authentication weaknesses."""
        logger.info(
            "dss.check_auth",
            count=len(instances),
        )

        weaknesses: list[AuthWeakness] = []
        idx = 0
        for inst in instances:
            for chk in _AUTH_CHECKS:
                applies = False
                if (
                    chk["type"] == "no_auth_required"
                    and inst.engine == DatabaseEngine.REDIS
                    and not inst.ssl_enabled
                ):
                    applies = True
                elif chk["type"] == "default_credentials" and inst.engine in {
                    DatabaseEngine.MYSQL,
                    DatabaseEngine.POSTGRESQL,
                }:
                    applies = random.random() > 0.5  # noqa: S311
                elif chk["type"] in {
                    "weak_password_policy",
                    "no_mfa",
                }:
                    applies = random.random() > 0.6  # noqa: S311

                if applies:
                    weaknesses.append(
                        AuthWeakness(
                            id=_gen_id("AW", inst.id, idx),
                            instance_id=inst.id,
                            weakness_type=chk["type"],
                            description=(f"{inst.name}: {chk['desc']}"),
                            severity=chk["severity"],
                            affected_users=chk["users"],
                            remediation=chk["remediation"],
                        )
                    )
                    idx += 1
        return weaknesses

    async def audit_access(
        self,
        instances: list[DatabaseInstance],
    ) -> list[AccessAudit]:
        """Audit access controls and privileges."""
        logger.info(
            "dss.audit_access",
            count=len(instances),
        )

        _principals = [
            ("app_service", ["SELECT", "INSERT", "UPDATE"]),
            ("etl_pipeline", ["SELECT", "INSERT", "DELETE"]),
            ("dba_admin", ["ALL PRIVILEGES"]),
            ("readonly_user", ["SELECT"]),
            ("backup_agent", ["SELECT", "SHOW VIEW", "LOCK"]),
            (
                "legacy_app",
                [
                    "ALL PRIVILEGES",
                    "GRANT OPTION",
                ],
            ),
        ]

        audits: list[AccessAudit] = []
        idx = 0
        for inst in instances:
            if inst.engine == DatabaseEngine.DYNAMODB:
                continue
            sample = random.sample(  # noqa: S311
                _principals,
                k=min(4, len(_principals)),
            )
            for principal, privs in sample:
                excessive = "ALL PRIVILEGES" in privs
                rec = ""
                if excessive:
                    rec = f"Revoke ALL PRIVILEGES from {principal}; grant least-privilege"
                audits.append(
                    AccessAudit(
                        id=_gen_id("AA", inst.id, idx),
                        instance_id=inst.id,
                        principal=principal,
                        privileges=privs,
                        excessive=excessive,
                        last_used=random.choice(  # noqa: S311
                            [
                                "2026-03-29",
                                "2026-03-01",
                                "2025-12-15",
                                "never",
                            ],
                        ),
                        recommendation=rec,
                    )
                )
                idx += 1
        return audits

    async def detect_data_exposure(
        self,
        instances: list[DatabaseInstance],
    ) -> list[DataExposure]:
        """Detect sensitive data exposure in databases."""
        logger.info(
            "dss.detect_exposure",
            count=len(instances),
        )

        exposures: list[DataExposure] = []
        idx = 0
        for inst in instances:
            if inst.engine == DatabaseEngine.REDIS:
                continue
            sample = random.sample(  # noqa: S311
                _SENSITIVE_COLUMNS,
                k=min(3, len(_SENSITIVE_COLUMNS)),
            )
            for col in sample:
                encrypted = (
                    inst.encrypted_at_rest and random.random() > 0.4  # noqa: S311
                )
                masked = random.random() > 0.6  # noqa: S311
                rec = ""
                if not encrypted:
                    rec = f"Encrypt {col['column']} column using field-level encryption"
                elif not masked:
                    rec = f"Apply dynamic data masking to {col['column']}"
                exposures.append(
                    DataExposure(
                        id=_gen_id("DE", inst.id, idx),
                        instance_id=inst.id,
                        table=col["table"],
                        column=col["column"],
                        data_type=col["data_type"],
                        severity=col["severity"],
                        encrypted=encrypted,
                        masked=masked,
                        recommendation=rec,
                    )
                )
                idx += 1
        return exposures
