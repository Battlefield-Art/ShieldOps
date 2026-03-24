"""Threat Modeling Agent — Tool functions for STRIDE threat analysis."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    Mitigation,
    ServiceComponent,
    StrideCategory,
    ThreatLikelihood,
    ThreatVector,
)

logger = structlog.get_logger()

# Component discovery profiles per service type
_SERVICE_PROFILES: dict[str, list[dict[str, Any]]] = {
    "web_application": [
        {
            "name": "load_balancer",
            "component_type": "network",
            "trust_boundary": "external",
            "data_flows": ["client_requests", "backend_routing"],
            "technologies": ["nginx", "AWS ALB"],
        },
        {
            "name": "api_gateway",
            "component_type": "api",
            "trust_boundary": "dmz",
            "data_flows": ["auth_tokens", "api_requests", "rate_limiting"],
            "technologies": ["FastAPI", "Kong"],
        },
        {
            "name": "application_server",
            "component_type": "compute",
            "trust_boundary": "internal",
            "data_flows": ["business_logic", "database_queries", "cache_access"],
            "technologies": ["Python", "Docker", "Kubernetes"],
        },
        {
            "name": "database",
            "component_type": "data_store",
            "trust_boundary": "internal",
            "data_flows": ["persistent_storage", "query_results"],
            "technologies": ["PostgreSQL", "Redis"],
        },
        {
            "name": "message_queue",
            "component_type": "messaging",
            "trust_boundary": "internal",
            "data_flows": ["async_events", "task_dispatch"],
            "technologies": ["Kafka", "RabbitMQ"],
        },
    ],
    "microservice": [
        {
            "name": "service_mesh",
            "component_type": "network",
            "trust_boundary": "internal",
            "data_flows": ["service_to_service", "mTLS_traffic"],
            "technologies": ["Istio", "Envoy"],
        },
        {
            "name": "service_instance",
            "component_type": "compute",
            "trust_boundary": "internal",
            "data_flows": ["grpc_calls", "rest_calls"],
            "technologies": ["Go", "Python", "Kubernetes"],
        },
        {
            "name": "config_store",
            "component_type": "data_store",
            "trust_boundary": "internal",
            "data_flows": ["config_reads", "secret_access"],
            "technologies": ["etcd", "Vault"],
        },
    ],
    "default": [
        {
            "name": "frontend",
            "component_type": "ui",
            "trust_boundary": "external",
            "data_flows": ["user_input", "rendered_output"],
            "technologies": ["React", "TypeScript"],
        },
        {
            "name": "backend",
            "component_type": "compute",
            "trust_boundary": "internal",
            "data_flows": ["api_calls", "data_processing"],
            "technologies": ["Python", "FastAPI"],
        },
        {
            "name": "data_store",
            "component_type": "data_store",
            "trust_boundary": "internal",
            "data_flows": ["read_write", "backups"],
            "technologies": ["PostgreSQL"],
        },
    ],
}

# STRIDE threat patterns per component type
_STRIDE_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "network": [
        {
            "stride_category": StrideCategory.SPOOFING,
            "description": "IP spoofing or DNS hijacking to redirect traffic",
            "likelihood": ThreatLikelihood.POSSIBLE,
            "base_impact": 70.0,
            "mitre_technique": "T1557",
        },
        {
            "stride_category": StrideCategory.DENIAL_OF_SERVICE,
            "description": "DDoS attack overwhelming network capacity",
            "likelihood": ThreatLikelihood.LIKELY,
            "base_impact": 80.0,
            "mitre_technique": "T1498",
        },
    ],
    "api": [
        {
            "stride_category": StrideCategory.SPOOFING,
            "description": "Token forgery or session hijacking on API endpoints",
            "likelihood": ThreatLikelihood.LIKELY,
            "base_impact": 85.0,
            "mitre_technique": "T1550",
        },
        {
            "stride_category": StrideCategory.TAMPERING,
            "description": "API parameter manipulation to bypass validation",
            "likelihood": ThreatLikelihood.POSSIBLE,
            "base_impact": 75.0,
            "mitre_technique": "T1565",
        },
        {
            "stride_category": StrideCategory.INFORMATION_DISCLOSURE,
            "description": "Excessive data exposure through API responses",
            "likelihood": ThreatLikelihood.LIKELY,
            "base_impact": 65.0,
            "mitre_technique": "T1530",
        },
    ],
    "compute": [
        {
            "stride_category": StrideCategory.TAMPERING,
            "description": "Code injection or container escape in compute layer",
            "likelihood": ThreatLikelihood.POSSIBLE,
            "base_impact": 90.0,
            "mitre_technique": "T1610",
        },
        {
            "stride_category": StrideCategory.ELEVATION_OF_PRIVILEGE,
            "description": "Privilege escalation through misconfigured RBAC",
            "likelihood": ThreatLikelihood.POSSIBLE,
            "base_impact": 95.0,
            "mitre_technique": "T1078",
        },
        {
            "stride_category": StrideCategory.REPUDIATION,
            "description": "Insufficient logging allows untracked actions",
            "likelihood": ThreatLikelihood.LIKELY,
            "base_impact": 50.0,
            "mitre_technique": "T1070",
        },
    ],
    "data_store": [
        {
            "stride_category": StrideCategory.INFORMATION_DISCLOSURE,
            "description": "Unauthorized data access through SQL injection or misconfigured ACLs",
            "likelihood": ThreatLikelihood.LIKELY,
            "base_impact": 90.0,
            "mitre_technique": "T1213",
        },
        {
            "stride_category": StrideCategory.TAMPERING,
            "description": "Data corruption or unauthorized modification",
            "likelihood": ThreatLikelihood.POSSIBLE,
            "base_impact": 85.0,
            "mitre_technique": "T1565.001",
        },
    ],
    "messaging": [
        {
            "stride_category": StrideCategory.TAMPERING,
            "description": "Message injection or replay attacks on message queue",
            "likelihood": ThreatLikelihood.UNLIKELY,
            "base_impact": 65.0,
            "mitre_technique": "T1557.001",
        },
        {
            "stride_category": StrideCategory.DENIAL_OF_SERVICE,
            "description": "Message queue flooding causing backpressure failures",
            "likelihood": ThreatLikelihood.POSSIBLE,
            "base_impact": 70.0,
            "mitre_technique": "T1499",
        },
    ],
    "ui": [
        {
            "stride_category": StrideCategory.SPOOFING,
            "description": "Phishing or UI redress attacks targeting user credentials",
            "likelihood": ThreatLikelihood.LIKELY,
            "base_impact": 75.0,
            "mitre_technique": "T1566",
        },
        {
            "stride_category": StrideCategory.TAMPERING,
            "description": "Cross-site scripting (XSS) injecting malicious scripts",
            "likelihood": ThreatLikelihood.POSSIBLE,
            "base_impact": 70.0,
            "mitre_technique": "T1059.007",
        },
    ],
}

# Likelihood multipliers for RBA risk scoring
_LIKELIHOOD_WEIGHTS: dict[ThreatLikelihood, float] = {
    ThreatLikelihood.VERY_LIKELY: 1.0,
    ThreatLikelihood.LIKELY: 0.8,
    ThreatLikelihood.POSSIBLE: 0.6,
    ThreatLikelihood.UNLIKELY: 0.3,
    ThreatLikelihood.RARE: 0.1,
}

# Mitigation templates per STRIDE category
_MITIGATION_TEMPLATES: dict[StrideCategory, list[dict[str, str]]] = {
    StrideCategory.SPOOFING: [
        {
            "description": "Implement mutual TLS (mTLS) for service authentication",
            "control_type": "preventive",
            "effort": "medium",
            "effectiveness": "high",
        },
        {
            "description": "Deploy multi-factor authentication for all user access",
            "control_type": "preventive",
            "effort": "low",
            "effectiveness": "high",
        },
    ],
    StrideCategory.TAMPERING: [
        {
            "description": "Enable integrity verification with cryptographic checksums",
            "control_type": "detective",
            "effort": "medium",
            "effectiveness": "high",
        },
        {
            "description": "Implement input validation and parameterized queries",
            "control_type": "preventive",
            "effort": "low",
            "effectiveness": "high",
        },
    ],
    StrideCategory.REPUDIATION: [
        {
            "description": "Deploy immutable audit logging with tamper-proof storage",
            "control_type": "detective",
            "effort": "medium",
            "effectiveness": "high",
        },
        {
            "description": "Implement digital signatures for critical transactions",
            "control_type": "preventive",
            "effort": "high",
            "effectiveness": "high",
        },
    ],
    StrideCategory.INFORMATION_DISCLOSURE: [
        {
            "description": "Encrypt data at rest and in transit using AES-256/TLS 1.3",
            "control_type": "preventive",
            "effort": "medium",
            "effectiveness": "high",
        },
        {
            "description": "Implement field-level access controls and data masking",
            "control_type": "preventive",
            "effort": "medium",
            "effectiveness": "medium",
        },
    ],
    StrideCategory.DENIAL_OF_SERVICE: [
        {
            "description": "Deploy rate limiting and circuit breakers at all entry points",
            "control_type": "preventive",
            "effort": "low",
            "effectiveness": "medium",
        },
        {
            "description": "Implement auto-scaling and DDoS mitigation (WAF/CDN)",
            "control_type": "preventive",
            "effort": "medium",
            "effectiveness": "high",
        },
    ],
    StrideCategory.ELEVATION_OF_PRIVILEGE: [
        {
            "description": "Enforce least-privilege RBAC with regular access reviews",
            "control_type": "preventive",
            "effort": "medium",
            "effectiveness": "high",
        },
        {
            "description": "Implement container security policies and pod security standards",
            "control_type": "preventive",
            "effort": "medium",
            "effectiveness": "high",
        },
    ],
}


def _generate_threat_id(component: str, stride: str, index: int) -> str:
    """Generate a deterministic threat ID."""
    raw = f"{component}:{stride}:{index}"
    return f"THR-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class ThreatModelingToolkit:
    """Tools for STRIDE-based threat modeling and mitigation analysis."""

    def __init__(
        self,
        rba_client: Any | None = None,
        architecture_registry: Any | None = None,
        threat_intel: Any | None = None,
    ) -> None:
        self._rba_client = rba_client
        self._architecture_registry = architecture_registry
        self._threat_intel = threat_intel

    async def discover_components(self, service: str) -> list[ServiceComponent]:
        """Discover architecture components for a target service.

        Uses an architecture registry if available, otherwise returns
        mock components based on service type heuristics.
        """
        logger.info("threat_modeling.discover_components", service=service)

        if self._architecture_registry is not None:
            try:
                raw = await self._architecture_registry.get_components(service=service)
                return [ServiceComponent(**c) for c in raw]
            except Exception:
                logger.exception("threat_modeling.discover_components.error")

        # Determine service profile
        service_lower = service.lower()
        if "web" in service_lower or "app" in service_lower:
            profile_key = "web_application"
        elif "micro" in service_lower or "service" in service_lower:
            profile_key = "microservice"
        else:
            profile_key = "default"

        profile = _SERVICE_PROFILES[profile_key]
        components = [ServiceComponent(**c) for c in profile]
        return components

    async def analyze_threats(self, components: list[ServiceComponent]) -> list[ThreatVector]:
        """Apply STRIDE analysis to discovered components.

        Generates threat vectors for each component based on its type
        and the applicable STRIDE patterns.
        """
        logger.info(
            "threat_modeling.analyze_threats",
            component_count=len(components),
        )

        threats: list[ThreatVector] = []
        threat_index = 0

        for component in components:
            patterns = _STRIDE_PATTERNS.get(
                component.component_type,
                _STRIDE_PATTERNS.get("compute", []),
            )

            for pattern in patterns:
                threat_id = _generate_threat_id(
                    component.name,
                    pattern["stride_category"].value,
                    threat_index,
                )

                # Add some variance to impact
                noise = random.gauss(0, 3.0)
                impact = round(max(0.0, min(100.0, pattern["base_impact"] + noise)), 1)

                threats.append(
                    ThreatVector(
                        id=threat_id,
                        stride_category=pattern["stride_category"],
                        component=component.name,
                        description=pattern["description"],
                        likelihood=pattern["likelihood"],
                        impact_score=impact,
                        risk_score=0.0,  # Calculated in assess_risk
                        mitre_technique=pattern["mitre_technique"],
                    )
                )
                threat_index += 1

        return threats

    async def assess_risk(self, threats: list[ThreatVector]) -> list[ThreatVector]:
        """Score risks using RBA methodology.

        Combines impact score and likelihood to produce a weighted risk score.
        Uses external RBA client if available for enhanced scoring.
        """
        logger.info("threat_modeling.assess_risk", threat_count=len(threats))

        scored: list[ThreatVector] = []

        for threat in threats:
            # Try RBA client for scoring
            if self._rba_client is not None:
                try:
                    rba_result = await self._rba_client.score_threat(
                        threat_id=threat.id,
                        impact=threat.impact_score,
                        likelihood=threat.likelihood.value,
                    )
                    risk_score = float(rba_result.get("risk_score", 0.0))
                    scored.append(threat.model_copy(update={"risk_score": risk_score}))
                    continue
                except Exception:
                    logger.exception("threat_modeling.assess_risk.rba_error")

            # Fallback: calculate risk_score = impact * likelihood_weight
            weight = _LIKELIHOOD_WEIGHTS.get(threat.likelihood, 0.5)
            risk_score = round(threat.impact_score * weight, 1)
            risk_score = min(100.0, max(0.0, risk_score))

            scored.append(threat.model_copy(update={"risk_score": risk_score}))

        # Sort by risk score descending
        scored.sort(key=lambda t: t.risk_score, reverse=True)
        return scored

    async def recommend_mitigations(self, threats: list[ThreatVector]) -> list[Mitigation]:
        """Generate mitigation recommendations for identified threats.

        Selects appropriate mitigations based on STRIDE category and
        threat severity, prioritizing high-risk threats.
        """
        logger.info(
            "threat_modeling.recommend_mitigations",
            threat_count=len(threats),
        )

        mitigations: list[Mitigation] = []
        seen_descriptions: set[str] = set()

        for threat in threats:
            templates = _MITIGATION_TEMPLATES.get(threat.stride_category, [])

            # For high-risk threats, include all templates;
            # for lower risk, include the first one
            selected = templates if threat.risk_score >= 60.0 else templates[:1]

            for tmpl in selected:
                desc = tmpl["description"]
                if desc in seen_descriptions:
                    continue
                seen_descriptions.add(desc)

                mitigations.append(
                    Mitigation(
                        threat_id=threat.id,
                        description=desc,
                        control_type=tmpl["control_type"],
                        effort=tmpl["effort"],
                        effectiveness=tmpl["effectiveness"],
                    )
                )

        return mitigations

    def calculate_residual_risk(
        self,
        threats: list[ThreatVector],
        mitigations: list[Mitigation],
    ) -> float:
        """Calculate residual risk after mitigations are applied.

        Reduces risk scores based on mitigation effectiveness.
        """
        if not threats:
            return 0.0

        # Map threat_ids that have mitigations
        mitigated_ids: set[str] = set()
        effectiveness_map: dict[str, float] = {}
        for m in mitigations:
            mitigated_ids.add(m.threat_id)
            eff = {"high": 0.8, "medium": 0.5, "low": 0.2}.get(m.effectiveness, 0.3)
            # Take best effectiveness per threat
            current = effectiveness_map.get(m.threat_id, 0.0)
            effectiveness_map[m.threat_id] = max(current, eff)

        total_risk = 0.0
        for threat in threats:
            if threat.id in mitigated_ids:
                reduction = effectiveness_map.get(threat.id, 0.5)
                residual = threat.risk_score * (1.0 - reduction)
            else:
                residual = threat.risk_score
            total_risk += residual

        # Average residual risk
        avg_residual = total_risk / len(threats)
        return round(min(100.0, max(0.0, avg_residual)), 1)
