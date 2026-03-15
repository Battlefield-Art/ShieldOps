"""Python auto-instrumentation manager for ShieldOps.

Inspired by splunk-otel-python. Manages runtime patching of Python
services for automatic trace/metric collection via OTel.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class InstrumentationMode(StrEnum):
    FULL = "full"  # All supported libraries
    SELECTIVE = "selective"  # Only specified libraries
    MINIMAL = "minimal"  # Core only (requests, urllib3)


# Libraries supported for auto-instrumentation (splunk-otel-python compatible)
SUPPORTED_LIBRARIES: dict[str, str] = {
    "requests": "opentelemetry-instrumentation-requests",
    "flask": "opentelemetry-instrumentation-flask",
    "django": "opentelemetry-instrumentation-django",
    "fastapi": "opentelemetry-instrumentation-fastapi",
    "sqlalchemy": "opentelemetry-instrumentation-sqlalchemy",
    "redis": "opentelemetry-instrumentation-redis",
    "celery": "opentelemetry-instrumentation-celery",
    "grpc": "opentelemetry-instrumentation-grpc",
    "httpx": "opentelemetry-instrumentation-httpx",
    "aiohttp": "opentelemetry-instrumentation-aiohttp-client",
    "psycopg2": "opentelemetry-instrumentation-psycopg2",
    "urllib3": "opentelemetry-instrumentation-urllib3",
    "kafka": "opentelemetry-instrumentation-kafka-python",
    "boto3": "opentelemetry-instrumentation-boto3sqs",
}


class InstrumentationConfig(BaseModel):
    """Configuration for Python auto-instrumentation."""

    service_name: str = ""
    service_version: str = ""
    environment: str = "production"
    mode: InstrumentationMode = InstrumentationMode.FULL
    selected_libraries: list[str] = Field(default_factory=list)
    exporter_endpoint: str = "http://localhost:4317"
    exporter_protocol: str = "grpc"  # grpc or http
    trace_sample_rate: float = 1.0  # Full fidelity by default (splunk-otel pattern)
    max_attributes: int = 0  # 0 = unlimited (splunk-otel default)
    max_events: int = 0
    max_links: int = 0
    include_system_metrics: bool = True


class InstrumentedLibrary(BaseModel):
    """Status of an instrumented library."""

    name: str = ""
    package: str = ""
    installed: bool = False
    instrumented: bool = False
    version: str = ""


class PythonInstrumentor:
    """Manages Python auto-instrumentation for services."""

    def __init__(
        self,
        config: InstrumentationConfig | None = None,
    ) -> None:
        self._config = config or InstrumentationConfig()
        self._instrumented: dict[str, InstrumentedLibrary] = {}
        logger.info(
            "python_instrumentor.init",
            service=self._config.service_name,
            mode=self._config.mode.value,
        )

    def detect_libraries(self) -> list[InstrumentedLibrary]:
        """Detect which supported libraries are installed."""
        results: list[InstrumentedLibrary] = []
        for lib_name, package_name in SUPPORTED_LIBRARIES.items():
            installed = self._check_installed(lib_name)
            lib = InstrumentedLibrary(
                name=lib_name,
                package=package_name,
                installed=installed,
            )
            results.append(lib)
            self._instrumented[lib_name] = lib
        return results

    def get_instrumentation_plan(self) -> dict[str, Any]:
        """Generate an instrumentation plan based on detected libraries."""
        if not self._instrumented:
            self.detect_libraries()

        installed = [lib for lib in self._instrumented.values() if lib.installed]
        to_instrument: list[str] = []

        if self._config.mode == InstrumentationMode.FULL:
            to_instrument = [lib.name for lib in installed]
        elif self._config.mode == InstrumentationMode.SELECTIVE:
            to_instrument = [
                lib.name for lib in installed if lib.name in self._config.selected_libraries
            ]
        elif self._config.mode == InstrumentationMode.MINIMAL:
            to_instrument = [lib.name for lib in installed if lib.name in ("requests", "urllib3")]

        packages_needed = [
            SUPPORTED_LIBRARIES[name] for name in to_instrument if name in SUPPORTED_LIBRARIES
        ]

        return {
            "service_name": self._config.service_name,
            "mode": self._config.mode.value,
            "installed_libraries": len(installed),
            "to_instrument": to_instrument,
            "packages_needed": packages_needed,
            "exporter": {
                "endpoint": self._config.exporter_endpoint,
                "protocol": self._config.exporter_protocol,
            },
            "trace_config": {
                "sample_rate": self._config.trace_sample_rate,
                "max_attributes": self._config.max_attributes,
            },
        }

    def generate_k8s_annotation(self) -> dict[str, str]:
        """Generate K8s annotations for OTel operator injection."""
        annotations: dict[str, str] = {
            "instrumentation.opentelemetry.io/inject-python": "true",
        }
        if self._config.service_name:
            annotations["resource.opentelemetry.io/service.name"] = self._config.service_name
        if self._config.environment:
            annotations["resource.opentelemetry.io/deployment.environment"] = (
                self._config.environment
            )
        return annotations

    def generate_env_vars(self) -> dict[str, str]:
        """Generate environment variables for OTel Python SDK."""
        env: dict[str, str] = {
            "OTEL_SERVICE_NAME": self._config.service_name,
            "OTEL_EXPORTER_OTLP_ENDPOINT": self._config.exporter_endpoint,
            "OTEL_EXPORTER_OTLP_PROTOCOL": self._config.exporter_protocol,
            "OTEL_TRACES_SAMPLER": "parentbased_traceidratio",
            "OTEL_TRACES_SAMPLER_ARG": str(self._config.trace_sample_rate),
        }
        if self._config.environment:
            env["OTEL_RESOURCE_ATTRIBUTES"] = f"deployment.environment={self._config.environment}"
        if self._config.max_attributes > 0:
            env["OTEL_ATTRIBUTE_COUNT_LIMIT"] = str(self._config.max_attributes)
        if self._config.include_system_metrics:
            env["OTEL_PYTHON_SYSTEM_METRICS_ENABLED"] = "true"
        return env

    def get_coverage_report(self) -> dict[str, Any]:
        """Report on instrumentation coverage."""
        if not self._instrumented:
            self.detect_libraries()

        total = len(self._instrumented)
        installed = sum(1 for lib in self._instrumented.values() if lib.installed)
        instrumented = sum(1 for lib in self._instrumented.values() if lib.instrumented)

        return {
            "service": self._config.service_name,
            "total_supported": total,
            "installed": installed,
            "instrumented": instrumented,
            "coverage_pct": round(instrumented / max(installed, 1) * 100, 1),
            "uninstrumented": [
                lib.name
                for lib in self._instrumented.values()
                if lib.installed and not lib.instrumented
            ],
        }

    def _check_installed(self, library: str) -> bool:
        """Check if a library is installed in the current environment."""
        try:
            __import__(library)
            return True
        except ImportError:
            return False
