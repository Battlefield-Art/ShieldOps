"""Data Pipeline Protector Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
import time
from typing import Any

import structlog

from .models import (
    AccessEnforcement,
    DataAnomaly,
    DataPipeline,
    DataSourceType,
    InputScan,
    PipelineRisk,
    SchemaValidation,
)

logger = structlog.get_logger()


# --- Injection patterns ---
_INJECTION_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern": "' OR 1=1",
        "type": "sql_injection",
        "severity": PipelineRisk.CRITICAL,
        "mitre": "T1190",
        "description": ("SQL injection payload in ETL source input"),
    },
    {
        "pattern": "ignore previous instructions",
        "type": "prompt_injection",
        "severity": PipelineRisk.CRITICAL,
        "mitre": "AML.T0051",
        "description": ("Prompt injection in ML training data"),
    },
    {
        "pattern": "__import__(",
        "type": "code_injection",
        "severity": PipelineRisk.CRITICAL,
        "mitre": "T1059",
        "description": ("Python code injection via deserialization"),
    },
    {
        "pattern": "{{",
        "type": "template_injection",
        "severity": PipelineRisk.HIGH,
        "mitre": "T1221",
        "description": ("Server-side template injection in transform"),
    },
    {
        "pattern": "eval(",
        "type": "code_execution",
        "severity": PipelineRisk.CRITICAL,
        "mitre": "T1059.006",
        "description": ("Code execution payload in stream record"),
    },
    {
        "pattern": "DROP TABLE",
        "type": "destructive_sql",
        "severity": PipelineRisk.CRITICAL,
        "mitre": "T1485",
        "description": ("Destructive SQL in batch ingestion input"),
    },
]

# --- Schema drift signatures ---
_SCHEMA_DRIFT_TYPES: list[dict[str, Any]] = [
    {
        "drift": "type_change",
        "description": "Field type changed unexpectedly",
        "breaking": True,
    },
    {
        "drift": "field_removed",
        "description": "Required field removed from schema",
        "breaking": True,
    },
    {
        "drift": "nullable_added",
        "description": "Non-nullable field became nullable",
        "breaking": False,
    },
    {
        "drift": "constraint_relaxed",
        "description": "Validation constraint was weakened",
        "breaking": False,
    },
    {
        "drift": "encoding_changed",
        "description": "Character encoding changed",
        "breaking": True,
    },
]

# --- Mock pipeline inventory ---
_MOCK_PIPELINES: list[dict[str, Any]] = [
    {
        "name": "customer-etl-daily",
        "type": "etl_batch",
        "source_type": "database",
        "source": "postgres://warehouse/customers",
        "dest": "s3://analytics/customers/",
        "owner": "data-eng",
        "schedule": "0 2 * * *",
        "records": 2_500_000,
    },
    {
        "name": "clickstream-ingest",
        "type": "streaming",
        "source_type": "stream",
        "source": "kafka://clicks.events",
        "dest": "elasticsearch://clickstream-idx",
        "owner": "analytics",
        "schedule": "continuous",
        "records": 85_000_000,
    },
    {
        "name": "ml-training-features",
        "type": "ml_training",
        "source_type": "ml_dataset",
        "source": "s3://ml-data/features/",
        "dest": "sagemaker://training-jobs",
        "owner": "ml-platform",
        "schedule": "0 0 * * 0",
        "records": 10_000_000,
    },
    {
        "name": "api-log-collector",
        "type": "log_ingestion",
        "source_type": "api",
        "source": "https://api.internal/logs",
        "dest": "splunk://main-index",
        "owner": "sre",
        "schedule": "*/5 * * * *",
        "records": 50_000_000,
    },
    {
        "name": "vendor-data-sync",
        "type": "replication",
        "source_type": "cloud_storage",
        "source": "gs://vendor-feeds/",
        "dest": "s3://vendor-data/",
        "owner": "integrations",
        "schedule": "0 */6 * * *",
        "records": 500_000,
    },
]

# --- Access control policies ---
_ACCESS_POLICIES: list[dict[str, Any]] = [
    {
        "name": "least_privilege_pipeline",
        "description": ("Pipeline service accounts must use least-privilege permissions"),
    },
    {
        "name": "encrypt_in_transit",
        "description": ("All pipeline data must be encrypted in transit via TLS 1.2+"),
    },
    {
        "name": "no_cross_tenant_access",
        "description": ("Pipelines must not access data across tenant boundaries"),
    },
    {
        "name": "credential_rotation",
        "description": ("Pipeline credentials must be rotated within 90 days"),
    },
]


def _gen_id(prefix: str, content: str) -> str:
    """Generate a deterministic finding ID."""
    raw = f"{prefix}:{content}:{time.time()}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{digest.upper()}"


class DataPipelineProtectorToolkit:
    """Tools for protecting data pipelines."""

    def __init__(
        self,
        pipeline_client: Any | None = None,
        schema_registry: Any | None = None,
        iam_client: Any | None = None,
    ) -> None:
        self._pipeline_client = pipeline_client
        self._schema_registry = schema_registry
        self._iam_client = iam_client

    async def discover_pipelines(
        self,
        environment: str,
        pipeline_ids: list[str] | None = None,
    ) -> list[DataPipeline]:
        """Discover data pipelines in the environment."""
        logger.info(
            "dpp.discover_pipelines",
            environment=environment,
            filter_count=len(pipeline_ids or []),
        )

        if self._pipeline_client is not None:
            try:
                raw = await self._pipeline_client.list_pipelines(
                    environment=environment,
                )
                return [
                    DataPipeline(**p)
                    for p in raw
                    if not pipeline_ids or p.get("id") in pipeline_ids
                ]
            except Exception:
                logger.exception("dpp.discover.client_error")

        # Mock discovery
        pipelines: list[DataPipeline] = []
        for idx, mock in enumerate(_MOCK_PIPELINES):
            pid = f"pipe-{idx:04d}"
            if pipeline_ids and pid not in pipeline_ids:
                continue
            try:
                st = DataSourceType(mock["source_type"])
            except ValueError:
                st = DataSourceType.DATABASE
            risk = PipelineRisk.LOW
            if mock["type"] in ("streaming", "ml_training"):
                risk = PipelineRisk.MEDIUM
            if mock["records"] > 50_000_000:
                risk = PipelineRisk.HIGH
            pipelines.append(
                DataPipeline(
                    id=pid,
                    name=mock["name"],
                    pipeline_type=mock["type"],
                    source_type=st,
                    source_uri=mock["source"],
                    destination_uri=mock["dest"],
                    owner=mock["owner"],
                    schedule=mock["schedule"],
                    last_run=time.time()
                    - random.randint(  # noqa: S311
                        3600,
                        86400,
                    ),
                    record_count=mock["records"],
                    risk=risk,
                ),
            )
        return pipelines

    async def scan_inputs(
        self,
        pipelines: list[DataPipeline],
        records: list[dict[str, Any]] | None = None,
    ) -> list[InputScan]:
        """Scan pipeline input data for injection and poisoning."""
        logger.info(
            "dpp.scan_inputs",
            pipeline_count=len(pipelines),
        )

        findings: list[InputScan] = []

        # Scan provided records against patterns
        for record in records or []:
            text = str(
                record.get("content", record.get("data", "")),
            ).lower()
            rec_pipeline = record.get("pipeline_id", "unknown")
            for pattern in _INJECTION_PATTERNS:
                if pattern["pattern"].lower() in text:
                    findings.append(
                        InputScan(
                            id=_gen_id("INP", pattern["pattern"]),
                            pipeline_id=rec_pipeline,
                            scan_type="pattern_match",
                            threat_category=pattern["type"],
                            description=pattern["description"],
                            severity=pattern["severity"],
                            confidence=0.90,
                            affected_records=record.get(
                                "count",
                                1,
                            ),
                            mitre_technique=pattern["mitre"],
                            sample_payload=text[:120],
                        ),
                    )

        # Mock baseline findings for discovered pipelines
        if not records:
            for pipe in pipelines:
                if pipe.pipeline_type == "ml_training":
                    findings.append(
                        InputScan(
                            id=_gen_id("INP", pipe.id),
                            pipeline_id=pipe.id,
                            scan_type="statistical",
                            threat_category="distribution_shift",
                            description=("Training data distribution shifted from baseline by 12%"),
                            severity=PipelineRisk.MEDIUM,
                            confidence=0.75,
                            affected_records=int(
                                pipe.record_count * 0.03,
                            ),
                            mitre_technique="AML.T0020",
                        ),
                    )
                if pipe.pipeline_type == "streaming":
                    findings.append(
                        InputScan(
                            id=_gen_id("INP", pipe.id),
                            pipeline_id=pipe.id,
                            scan_type="schema_probe",
                            threat_category="malformed_payload",
                            description=(
                                "Malformed JSON payloads detected in stream — possible fuzzing"
                            ),
                            severity=PipelineRisk.HIGH,
                            confidence=0.80,
                            affected_records=random.randint(  # noqa: S311
                                50,
                                500,
                            ),
                            mitre_technique="T1190",
                        ),
                    )
        return findings

    async def detect_anomalies(
        self,
        pipelines: list[DataPipeline],
    ) -> list[DataAnomaly]:
        """Detect anomalies in pipeline data flows."""
        logger.info(
            "dpp.detect_anomalies",
            pipeline_count=len(pipelines),
        )

        anomalies: list[DataAnomaly] = []

        for pipe in pipelines:
            baseline = float(pipe.record_count)
            # Simulate anomaly detection
            deviation = random.uniform(-0.05, 0.35)  # noqa: S311
            observed = baseline * (1.0 + deviation)

            if abs(deviation) > 0.15:
                sev = PipelineRisk.HIGH
                if abs(deviation) > 0.25:
                    sev = PipelineRisk.CRITICAL
                anomalies.append(
                    DataAnomaly(
                        id=_gen_id("ANM", pipe.id),
                        pipeline_id=pipe.id,
                        anomaly_type="volume_deviation",
                        description=(
                            f"Record volume deviated {deviation * 100:.1f}% from baseline"
                        ),
                        severity=sev,
                        baseline_value=baseline,
                        observed_value=observed,
                        deviation_pct=round(
                            deviation * 100,
                            2,
                        ),
                        detected_at=time.time(),
                    ),
                )

            # Latency anomaly for streaming
            if pipe.pipeline_type == "streaming":
                lat_dev = random.uniform(0.0, 0.5)  # noqa: S311
                if lat_dev > 0.2:
                    anomalies.append(
                        DataAnomaly(
                            id=_gen_id("ANM", f"lat-{pipe.id}"),
                            pipeline_id=pipe.id,
                            anomaly_type="latency_spike",
                            description=(
                                f"Processing latency exceeded p99 threshold by {lat_dev * 100:.0f}%"
                            ),
                            severity=PipelineRisk.MEDIUM,
                            baseline_value=50.0,
                            observed_value=50.0 * (1 + lat_dev),
                            deviation_pct=round(
                                lat_dev * 100,
                                2,
                            ),
                            detected_at=time.time(),
                        ),
                    )

        return anomalies

    async def validate_schemas(
        self,
        pipelines: list[DataPipeline],
    ) -> list[SchemaValidation]:
        """Check for schema drift and tampering."""
        logger.info(
            "dpp.validate_schemas",
            pipeline_count=len(pipelines),
        )

        validations: list[SchemaValidation] = []

        if self._schema_registry is not None:
            try:
                for pipe in pipelines:
                    result = await self._schema_registry.compare(
                        pipeline_id=pipe.id,
                    )
                    for diff in result.get("diffs", []):
                        validations.append(
                            SchemaValidation(**diff),
                        )
                return validations
            except Exception:
                logger.exception("dpp.validate.registry_error")

        # Mock schema validation
        mock_fields = [
            ("user_id", "int64", "string"),
            ("timestamp", "datetime", "string"),
            ("amount", "decimal", "float32"),
            ("email", "string", None),
            ("metadata", "json", "bytes"),
        ]

        for pipe in pipelines:
            chosen = random.sample(  # noqa: S311
                mock_fields,
                k=min(
                    random.randint(1, 2),  # noqa: S311
                    len(mock_fields),
                ),
            )
            for field_name, expected, actual in chosen:
                if actual is None:
                    drift = _SCHEMA_DRIFT_TYPES[1]
                    actual_str = "REMOVED"
                else:
                    drift = _SCHEMA_DRIFT_TYPES[0]
                    actual_str = actual

                sev = PipelineRisk.HIGH if drift["breaking"] else PipelineRisk.MEDIUM
                validations.append(
                    SchemaValidation(
                        id=_gen_id("SCH", f"{pipe.id}:{field_name}"),
                        pipeline_id=pipe.id,
                        field_name=field_name,
                        expected_type=expected,
                        actual_type=actual_str,
                        drift_type=drift["drift"],
                        severity=sev,
                        description=drift["description"],
                        is_breaking=drift["breaking"],
                    ),
                )

        return validations

    async def enforce_access(
        self,
        pipelines: list[DataPipeline],
        findings: list[dict[str, Any]],
    ) -> list[AccessEnforcement]:
        """Enforce access controls on pipelines."""
        logger.info(
            "dpp.enforce_access",
            pipeline_count=len(pipelines),
            finding_count=len(findings),
        )

        enforcements: list[AccessEnforcement] = []

        if self._iam_client is not None:
            try:
                for pipe in pipelines:
                    result = await self._iam_client.audit_access(
                        resource=pipe.source_uri,
                    )
                    for violation in result.get("violations", []):
                        enforcements.append(
                            AccessEnforcement(**violation),
                        )
                return enforcements
            except Exception:
                logger.exception("dpp.enforce.iam_error")

        # Mock access enforcement
        mock_principals = [
            ("svc-etl-prod", "read_write", True),
            ("svc-analytics-ro", "read_only", True),
            ("svc-unknown-ext", "read_write", False),
            ("svc-ml-trainer", "read_write", True),
            ("former-employee@co.com", "admin", False),
        ]

        for pipe in pipelines:
            chosen = random.sample(  # noqa: S311
                mock_principals,
                k=min(2, len(mock_principals)),
            )
            for principal, action, authorized in chosen:
                decision = "allow" if authorized else "deny"
                sev = PipelineRisk.INFORMATIONAL if authorized else PipelineRisk.CRITICAL
                policy = "least_privilege_pipeline" if authorized else "no_cross_tenant_access"
                enforcements.append(
                    AccessEnforcement(
                        id=_gen_id("ACL", f"{pipe.id}:{principal}"),
                        pipeline_id=pipe.id,
                        principal=principal,
                        action=action,
                        resource=pipe.source_uri,
                        decision=decision,
                        policy_name=policy,
                        severity=sev,
                        auto_remediated=not authorized,
                    ),
                )

        # Auto-quarantine pipelines with critical findings
        critical = [f for f in findings if f.get("severity") == PipelineRisk.CRITICAL]
        for finding in critical:
            pid = finding.get("pipeline_id", "unknown")
            enforcements.append(
                AccessEnforcement(
                    id=_gen_id("ACL", f"quarantine:{pid}"),
                    pipeline_id=pid,
                    principal="system",
                    action="quarantine",
                    resource=pid,
                    decision="enforce",
                    policy_name="critical_finding_quarantine",
                    severity=PipelineRisk.CRITICAL,
                    auto_remediated=True,
                ),
            )

        return enforcements
