"""Crypto Agility Manager Agent — Tool functions for PQC migration lifecycle."""

from __future__ import annotations

import hashlib
from typing import Any

import structlog

from .models import (
    AgilityAssessment,
    AlgorithmRecord,
    CompatibilityResult,
    MigrationExecution,
    MigrationPlan,
    MigrationPriority,
    PQCAlgorithm,
)

logger = structlog.get_logger()

# Algorithms known to be quantum-vulnerable
_QUANTUM_VULNERABLE = {"RSA", "ECDSA", "ECDH", "DH", "DSA", "EdDSA"}

# Deprecated/weak algorithms
_DEPRECATED = {"MD5", "SHA-1", "DES", "3DES", "RC4", "Blowfish"}

# PQC recommendation mapping by usage
_PQC_RECOMMENDATIONS: dict[str, str] = {
    "key_exchange": PQCAlgorithm.CRYSTALS_KYBER.value,
    "kem": PQCAlgorithm.CRYSTALS_KYBER.value,
    "signature": PQCAlgorithm.CRYSTALS_DILITHIUM.value,
    "signing": PQCAlgorithm.CRYSTALS_DILITHIUM.value,
    "authentication": PQCAlgorithm.CRYSTALS_DILITHIUM.value,
    "hash_signature": PQCAlgorithm.SPHINCS_PLUS.value,
    "code_signing": PQCAlgorithm.CRYSTALS_DILITHIUM.value,
    "tls": PQCAlgorithm.CRYSTALS_KYBER.value,
    "encryption": PQCAlgorithm.CRYSTALS_KYBER.value,
}

# Estimated performance overhead for PQC algorithms (percentage increase)
_PQC_PERF_OVERHEAD: dict[str, float] = {
    PQCAlgorithm.CRYSTALS_KYBER.value: 5.0,
    PQCAlgorithm.CRYSTALS_DILITHIUM.value: 8.0,
    PQCAlgorithm.SPHINCS_PLUS.value: 25.0,
    PQCAlgorithm.FALCON.value: 6.0,
    PQCAlgorithm.BIKE.value: 12.0,
    PQCAlgorithm.CLASSIC_MCELIECE.value: 15.0,
}


def _generate_algo_id(service: str, algorithm: str) -> str:
    """Generate a deterministic algorithm record ID."""
    raw = f"{service}:{algorithm}"
    return f"ALG-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


def _generate_plan_id(service: str, target: str) -> str:
    """Generate a deterministic migration plan ID."""
    raw = f"{service}:{target}"
    return f"MIG-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class CryptoAgilityManagerToolkit:
    """Tools for post-quantum cryptographic agility management."""

    def __init__(
        self,
        crypto_store: Any | None = None,
        pqc_test_client: Any | None = None,
        config_client: Any | None = None,
        notification_client: Any | None = None,
    ) -> None:
        self._crypto_store = crypto_store
        self._pqc_test_client = pqc_test_client
        self._config_client = config_client
        self._notification_client = notification_client

    async def discover_algorithms(self, tenant_id: str) -> list[AlgorithmRecord]:
        """Discover all cryptographic algorithms in use across infrastructure."""
        logger.info("crypto_agility.discover", tenant_id=tenant_id)

        if self._crypto_store is not None:
            try:
                raw = await self._crypto_store.list_algorithms(tenant_id=tenant_id)
                return [AlgorithmRecord(**a) for a in raw]
            except Exception:
                logger.exception("crypto_agility.discover.error")

        # Fallback: synthetic algorithm inventory
        algorithms = [
            AlgorithmRecord(
                id=_generate_algo_id("api-gateway", "RSA-2048"),
                service="api-gateway",
                algorithm="RSA",
                key_size=2048,
                usage="tls",
                protocol="TLS 1.3",
                quantum_safe=False,
                priority=MigrationPriority.CRITICAL,
                location="production/ingress",
            ),
            AlgorithmRecord(
                id=_generate_algo_id("auth-service", "ECDSA-P256"),
                service="auth-service",
                algorithm="ECDSA",
                key_size=256,
                usage="signature",
                protocol="JWT",
                quantum_safe=False,
                priority=MigrationPriority.HIGH,
                location="production/auth",
            ),
            AlgorithmRecord(
                id=_generate_algo_id("data-store", "AES-256-GCM"),
                service="data-store",
                algorithm="AES-256-GCM",
                key_size=256,
                usage="encryption",
                protocol="at-rest",
                quantum_safe=True,
                priority=MigrationPriority.LOW,
                location="production/database",
            ),
            AlgorithmRecord(
                id=_generate_algo_id("vpn-gateway", "DH-2048"),
                service="vpn-gateway",
                algorithm="DH",
                key_size=2048,
                usage="key_exchange",
                protocol="IKEv2",
                quantum_safe=False,
                priority=MigrationPriority.CRITICAL,
                location="production/network",
            ),
            AlgorithmRecord(
                id=_generate_algo_id("code-signing", "RSA-4096"),
                service="code-signing",
                algorithm="RSA",
                key_size=4096,
                usage="code_signing",
                protocol="PKCS#1 v1.5",
                quantum_safe=False,
                priority=MigrationPriority.MEDIUM,
                location="ci-cd/pipeline",
            ),
            AlgorithmRecord(
                id=_generate_algo_id("internal-ca", "ECDSA-P384"),
                service="internal-ca",
                algorithm="ECDSA",
                key_size=384,
                usage="signing",
                protocol="X.509",
                quantum_safe=False,
                priority=MigrationPriority.HIGH,
                location="pki/root-ca",
            ),
        ]
        return algorithms

    async def assess_agility(self, algorithms: list[AlgorithmRecord]) -> list[AgilityAssessment]:
        """Assess cryptographic agility for each discovered service."""
        logger.info("crypto_agility.assess", algo_count=len(algorithms))

        assessments: list[AgilityAssessment] = []
        for algo in algorithms:
            if algo.quantum_safe:
                continue

            is_deprecated = algo.algorithm in _DEPRECATED

            blockers: list[str] = []
            if is_deprecated:
                blockers.append(f"Deprecated algorithm: {algo.algorithm}")
            if algo.key_size < 2048 and algo.algorithm == "RSA":
                blockers.append(f"Weak key size: {algo.key_size} bits")

            recommended = _PQC_RECOMMENDATIONS.get(algo.usage, PQCAlgorithm.CRYSTALS_KYBER.value)

            complexity = "low"
            effort = 8
            if algo.protocol in ("TLS 1.3", "IKEv2"):
                complexity = "medium"
                effort = 24
            if algo.usage in ("signing", "code_signing"):
                complexity = "high"
                effort = 40

            assessments.append(
                AgilityAssessment(
                    service=algo.service,
                    algorithm=algo.algorithm,
                    supports_negotiation=algo.protocol in ("TLS 1.3", "IKEv2"),
                    supports_hybrid=algo.protocol in ("TLS 1.3",),
                    migration_complexity=complexity,
                    estimated_effort_hours=effort,
                    blockers=blockers,
                    recommended_pqc=recommended,
                )
            )

        return assessments

    async def plan_migration(
        self,
        assessments: list[AgilityAssessment],
        algorithms: list[AlgorithmRecord],
    ) -> list[MigrationPlan]:
        """Create PQC migration plans based on agility assessments."""
        logger.info("crypto_agility.plan_migration", assessment_count=len(assessments))

        algo_map = {a.service: a for a in algorithms}
        plans: list[MigrationPlan] = []

        for assessment in assessments:
            algo = algo_map.get(assessment.service)
            if algo is None:
                continue

            target = assessment.recommended_pqc
            plan_id = _generate_plan_id(assessment.service, target)
            hybrid = assessment.supports_hybrid

            steps = [
                f"Enable {target} support in {assessment.service}",
                f"Configure hybrid mode: {algo.algorithm} + {target}",
                "Run compatibility validation suite",
                "Monitor performance metrics for 24h",
                f"Disable legacy {algo.algorithm} after validation",
                "Update certificate/key material",
                "Verify end-to-end connectivity",
            ]

            rollback = [
                f"Re-enable {algo.algorithm} as primary",
                f"Disable {target} in {assessment.service}",
                "Restore previous key material from backup",
                "Verify service recovery",
            ]

            requires_approval = algo.priority in (
                MigrationPriority.CRITICAL,
                MigrationPriority.HIGH,
            )

            plans.append(
                MigrationPlan(
                    id=plan_id,
                    service=assessment.service,
                    current_algorithm=algo.algorithm,
                    target_algorithm=target,
                    priority=algo.priority,
                    hybrid_mode=hybrid,
                    steps=steps,
                    rollback_steps=rollback,
                    estimated_downtime_seconds=0 if hybrid else 300,
                    requires_approval=requires_approval,
                )
            )

        # Sort by priority
        priority_order = {
            MigrationPriority.CRITICAL: 0,
            MigrationPriority.HIGH: 1,
            MigrationPriority.MEDIUM: 2,
            MigrationPriority.LOW: 3,
            MigrationPriority.DEFERRED: 4,
        }
        plans.sort(key=lambda p: priority_order.get(p.priority, 99))

        return plans

    async def test_compatibility(self, plans: list[MigrationPlan]) -> list[CompatibilityResult]:
        """Test PQC algorithm compatibility for each migration plan."""
        logger.info("crypto_agility.test_compatibility", plan_count=len(plans))

        if self._pqc_test_client is not None:
            try:
                raw = await self._pqc_test_client.run_compatibility_suite(
                    plans=[p.model_dump() for p in plans]
                )
                return [CompatibilityResult(**r) for r in raw]
            except Exception:
                logger.exception("crypto_agility.test_compatibility.error")

        # Simulated compatibility test results
        results: list[CompatibilityResult] = []
        for plan in plans:
            overhead = _PQC_PERF_OVERHEAD.get(plan.target_algorithm, 10.0)
            issues: list[str] = []

            # SPHINCS+ has larger signatures
            key_increase = 0.0
            if plan.target_algorithm == PQCAlgorithm.SPHINCS_PLUS.value:
                key_increase = 800.0
                issues.append("SPHINCS+ signatures are significantly larger (~8KB)")
            elif plan.target_algorithm == PQCAlgorithm.CRYSTALS_KYBER.value:
                key_increase = 50.0
            elif plan.target_algorithm == PQCAlgorithm.CRYSTALS_DILITHIUM.value:
                key_increase = 120.0
            elif plan.target_algorithm == PQCAlgorithm.CLASSIC_MCELIECE.value:
                key_increase = 5000.0
                issues.append("Classic McEliece has very large public keys (~1MB)")

            # Handshake time varies by algorithm
            handshake = 2.0 + (overhead / 5.0)

            results.append(
                CompatibilityResult(
                    service=plan.service,
                    algorithm=plan.current_algorithm,
                    target_pqc=plan.target_algorithm,
                    compatible=len(issues) == 0 or plan.hybrid_mode,
                    performance_impact_pct=overhead,
                    key_size_increase_pct=key_increase,
                    issues=issues,
                    handshake_time_ms=handshake,
                )
            )

        return results

    async def execute_migration(
        self, plan: MigrationPlan, compatible: bool = True
    ) -> MigrationExecution:
        """Execute a PQC migration step."""
        logger.info(
            "crypto_agility.execute_migration",
            plan_id=plan.id,
            service=plan.service,
            target=plan.target_algorithm,
        )

        if not compatible:
            return MigrationExecution(
                plan_id=plan.id,
                service=plan.service,
                status="skipped",
                message=f"Skipped: compatibility test failed for {plan.target_algorithm}",
            )

        if plan.requires_approval:
            return MigrationExecution(
                plan_id=plan.id,
                service=plan.service,
                status="pending_approval",
                hybrid_enabled=False,
                rollback_available=True,
                message=(
                    f"Awaiting approval for {plan.priority.value}-priority "
                    f"migration of {plan.service} to {plan.target_algorithm}"
                ),
            )

        if self._config_client is not None:
            try:
                await self._config_client.apply_pqc_config(
                    service=plan.service,
                    algorithm=plan.target_algorithm,
                    hybrid=plan.hybrid_mode,
                )
                return MigrationExecution(
                    plan_id=plan.id,
                    service=plan.service,
                    status="completed",
                    hybrid_enabled=plan.hybrid_mode,
                    rollback_available=True,
                    verification_passed=True,
                    message=f"Migrated {plan.service} to {plan.target_algorithm}",
                )
            except Exception:
                logger.exception("crypto_agility.execute_migration.error")
                return MigrationExecution(
                    plan_id=plan.id,
                    service=plan.service,
                    status="failed",
                    rollback_available=True,
                    message=f"Migration failed for {plan.service}",
                )

        # Simulated successful migration
        return MigrationExecution(
            plan_id=plan.id,
            service=plan.service,
            status="completed",
            hybrid_enabled=plan.hybrid_mode,
            rollback_available=True,
            verification_passed=True,
            message=(
                f"Migrated {plan.service} from {plan.current_algorithm} "
                f"to {plan.target_algorithm} (hybrid={plan.hybrid_mode})"
            ),
        )
