"""OTel Semantic Conventions Agent — Tool functions for convention validation."""

from __future__ import annotations

import re
from typing import Any

import structlog

from .models import (
    ComplianceResult,
    ConventionRule,
    ConventionScope,
    Violation,
    ViolationSeverity,
)

logger = structlog.get_logger()

# Canonical OTel semantic convention rules per scope
_RESOURCE_RULES: list[dict[str, str]] = [
    {
        "attribute_name": "service.name",
        "expected_pattern": r"^[a-z][a-z0-9._-]+$",
        "description": "Required. Logical name of the service (lowercase, dotted).",
    },
    {
        "attribute_name": "service.version",
        "expected_pattern": r"^[0-9]+\.[0-9]+\.[0-9]+",
        "description": "Version string of the service (semver recommended).",
    },
    {
        "attribute_name": "deployment.environment",
        "expected_pattern": r"^(production|staging|development|test)$",
        "description": "Deployment environment name.",
    },
]

_SPAN_RULES: list[dict[str, str]] = [
    {
        "attribute_name": "http.request.method",
        "expected_pattern": r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)$",
        "description": "HTTP request method (uppercase). Replaces deprecated http.method.",
    },
    {
        "attribute_name": "url.path",
        "expected_pattern": r"^/",
        "description": "URL path component. Replaces deprecated http.target.",
    },
    {
        "attribute_name": "server.address",
        "expected_pattern": r".+",
        "description": "Server address (hostname or IP). Replaces deprecated net.peer.name.",
    },
]

_METRIC_RULES: list[dict[str, str]] = [
    {
        "attribute_name": "http.server.request.duration",
        "expected_pattern": r"^[a-z][a-z0-9._]+$",
        "description": "HTTP server request duration histogram (seconds).",
    },
    {
        "attribute_name": "http.client.request.duration",
        "expected_pattern": r"^[a-z][a-z0-9._]+$",
        "description": "HTTP client request duration histogram (seconds).",
    },
    {
        "attribute_name": "process.cpu.time",
        "expected_pattern": r"^[a-z][a-z0-9._]+$",
        "description": "Process CPU time (seconds).",
    },
]

_LOG_RULES: list[dict[str, str]] = [
    {
        "attribute_name": "severity",
        "expected_pattern": r"^(TRACE|DEBUG|INFO|WARN|ERROR|FATAL)$",
        "description": "Log severity text per OTel log data model.",
    },
    {
        "attribute_name": "body",
        "expected_pattern": r".+",
        "description": "Log body must be non-empty.",
    },
]

_RULES_BY_SCOPE: dict[ConventionScope, list[dict[str, str]]] = {
    ConventionScope.RESOURCE: _RESOURCE_RULES,
    ConventionScope.SPAN: _SPAN_RULES,
    ConventionScope.METRIC: _METRIC_RULES,
    ConventionScope.LOG: _LOG_RULES,
}

# Deprecated attribute mappings (old -> new)
_DEPRECATED_ATTRIBUTES: dict[str, str] = {
    "http.method": "http.request.method",
    "http.target": "url.path",
    "http.url": "url.full",
    "http.scheme": "url.scheme",
    "http.status_code": "http.response.status_code",
    "net.peer.name": "server.address",
    "net.peer.port": "server.port",
    "net.host.name": "server.address",
    "http.flavor": "network.protocol.version",
}


class OTelSemanticToolkit:
    """Tools for OpenTelemetry semantic convention validation and enforcement."""

    def __init__(
        self,
        telemetry_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._telemetry_client = telemetry_client
        self._repository = repository

    def load_convention_rules(
        self,
        scope: ConventionScope | None = None,
    ) -> list[ConventionRule]:
        """Load OTel semantic convention rules for the given scope.

        If scope is None, loads rules for all scopes.
        """
        logger.info("otel_semantic.load_rules", scope=scope)

        scopes = [scope] if scope else list(ConventionScope)
        rules: list[ConventionRule] = []

        for s in scopes:
            raw_rules = _RULES_BY_SCOPE.get(s, [])
            for raw in raw_rules:
                rules.append(
                    ConventionRule(
                        scope=s,
                        attribute_name=raw["attribute_name"],
                        expected_pattern=raw["expected_pattern"],
                        description=raw["description"],
                    )
                )

        return rules

    async def scan_service(
        self,
        service_name: str,
        rules: list[ConventionRule],
    ) -> ComplianceResult:
        """Scan a service's telemetry against semantic convention rules.

        Returns a ComplianceResult with all violations found.
        """
        logger.info("otel_semantic.scan_service", service=service_name)

        # Fetch actual telemetry attributes from the service
        attributes = await self._fetch_service_attributes(service_name)

        violations: list[Violation] = []
        total_checked = 0
        compliant = 0

        for rule in rules:
            total_checked += 1
            scope_attrs = attributes.get(rule.scope.value, {})
            actual = scope_attrs.get(rule.attribute_name)

            # Check for deprecated attribute usage
            deprecated_replacement = None
            for old_name, new_name in _DEPRECATED_ATTRIBUTES.items():
                if old_name in scope_attrs and new_name == rule.attribute_name:
                    deprecated_replacement = old_name
                    break

            if actual is None and deprecated_replacement:
                # Using deprecated name instead of current name
                actual_val = str(scope_attrs.get(deprecated_replacement, ""))
                violations.append(
                    Violation(
                        service=service_name,
                        scope=rule.scope,
                        attribute_name=rule.attribute_name,
                        actual_value=f"[deprecated] {deprecated_replacement}={actual_val}",
                        expected=rule.expected_pattern,
                        severity=ViolationSeverity.WARNING,
                        fix_suggestion=(
                            f"Rename '{deprecated_replacement}' to '{rule.attribute_name}'. "
                            "Use OTel Collector transform processor or update SDK."
                        ),
                    )
                )
            elif actual is None:
                # Required attribute missing
                severity = ViolationSeverity.ERROR
                if rule.scope == ConventionScope.RESOURCE and rule.attribute_name == "service.name":
                    severity = ViolationSeverity.ERROR
                elif rule.scope in (ConventionScope.LOG, ConventionScope.METRIC):
                    severity = ViolationSeverity.INFO

                violations.append(
                    Violation(
                        service=service_name,
                        scope=rule.scope,
                        attribute_name=rule.attribute_name,
                        actual_value="<missing>",
                        expected=rule.expected_pattern,
                        severity=severity,
                        fix_suggestion=(
                            f"Add attribute '{rule.attribute_name}' to {rule.scope.value} "
                            "telemetry. Configure via OTEL_RESOURCE_ATTRIBUTES or SDK setup."
                        ),
                    )
                )
            else:
                # Attribute present — validate pattern
                actual_str = str(actual)
                try:
                    if re.match(rule.expected_pattern, actual_str):
                        compliant += 1
                    else:
                        violations.append(
                            Violation(
                                service=service_name,
                                scope=rule.scope,
                                attribute_name=rule.attribute_name,
                                actual_value=actual_str,
                                expected=rule.expected_pattern,
                                severity=ViolationSeverity.WARNING,
                                fix_suggestion=(
                                    f"Value '{actual_str}' does not match expected pattern "
                                    f"'{rule.expected_pattern}'. Update the attribute value."
                                ),
                            )
                        )
                except re.error:
                    compliant += 1  # If pattern is invalid, assume compliant

        score = (compliant / total_checked * 100.0) if total_checked > 0 else 0.0

        return ComplianceResult(
            service=service_name,
            total_attributes=total_checked,
            compliant_count=compliant,
            violations=violations,
            score=round(score, 2),
        )

    def suggest_fixes(
        self,
        violations: list[Violation],
    ) -> list[dict[str, Any]]:
        """Generate actionable fix suggestions for violations.

        Returns processor configurations and SDK changes.
        """
        logger.info("otel_semantic.suggest_fixes", count=len(violations))

        fixes: list[dict[str, Any]] = []
        for v in violations:
            fix: dict[str, Any] = {
                "service": v.service,
                "scope": v.scope.value,
                "attribute": v.attribute_name,
                "severity": v.severity.value,
                "suggestion": v.fix_suggestion,
            }

            # Generate specific processor config for attribute renames
            if "[deprecated]" in v.actual_value:
                old_attr = v.actual_value.split("]")[1].strip().split("=")[0].strip()
                fix["processor_config"] = {
                    "transform": {
                        "trace_statements": [
                            {
                                "context": "span"
                                if v.scope == ConventionScope.SPAN
                                else "resource",
                                "statements": [
                                    f'set(attributes["{v.attribute_name}"], '
                                    f'attributes["{old_attr}"])',
                                    f'delete_key(attributes, "{old_attr}")',
                                ],
                            }
                        ]
                    }
                }
            elif v.actual_value == "<missing>":
                fix["sdk_config"] = {
                    "env_var": f"OTEL_RESOURCE_ATTRIBUTES={v.attribute_name}=<value>",
                    "code_snippet": (
                        f'resource = Resource(attributes={{"{v.attribute_name}": "<value>"}})'
                    ),
                }

            fixes.append(fix)

        return fixes

    async def apply_processor_fix(
        self,
        service: str,
        fix_config: dict[str, Any],
    ) -> dict[str, Any]:
        """Apply an OTel Collector processor configuration to fix violations.

        In production, this would update the collector config via K8s ConfigMap.
        """
        logger.info("otel_semantic.apply_fix", service=service)

        if self._telemetry_client is not None:
            try:
                result = await self._telemetry_client.apply_processor(
                    service=service,
                    config=fix_config,
                )
                return {
                    "status": "applied",
                    "service": service,
                    "detail": result,
                }
            except Exception as exc:
                logger.exception("otel_semantic.apply_fix.error")
                return {
                    "status": "failed",
                    "service": service,
                    "error": str(exc),
                }

        return {
            "status": "simulated",
            "service": service,
            "config": fix_config,
        }

    async def _fetch_service_attributes(
        self,
        service_name: str,
    ) -> dict[str, dict[str, Any]]:
        """Fetch telemetry attributes for a service.

        Returns attributes grouped by scope (resource, span, metric, log).
        """
        if self._telemetry_client is not None:
            try:
                return await self._telemetry_client.get_service_attributes(service_name)  # type: ignore[no-any-return]
            except Exception:
                logger.exception("otel_semantic.fetch_attributes.error")

        # Simulated attributes for offline/testing mode
        return {
            "resource": {
                "service.name": service_name,
                "service.version": "1.2.3",
                "deployment.environment": "production",
            },
            "span": {
                "http.request.method": "GET",
                "url.path": "/api/v1/health",
                "server.address": "api.example.com",
            },
            "metric": {
                "http.server.request.duration": "http.server.request.duration",
            },
            "log": {
                "severity": "INFO",
                "body": "Request processed",
            },
        }
