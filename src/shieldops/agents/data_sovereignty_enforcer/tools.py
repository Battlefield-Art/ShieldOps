"""Data Sovereignty Enforcer Agent — Tool functions for sovereignty enforcement."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .models import (
    DataFlow,
    Jurisdiction,
    JurisdictionMapping,
    PolicyEnforcement,
    ResidencyViolation,
    TransferMechanism,
    TransferValidation,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Jurisdiction detection from region strings
# ---------------------------------------------------------------------------

_REGION_JURISDICTION: dict[str, Jurisdiction] = {
    "eu-west-1": Jurisdiction.EU,
    "eu-west-2": Jurisdiction.EU,
    "eu-central-1": Jurisdiction.EU,
    "eu-north-1": Jurisdiction.EU,
    "eu-south-1": Jurisdiction.EU,
    "europe-west1": Jurisdiction.EU,
    "europe-west4": Jurisdiction.EU,
    "westeurope": Jurisdiction.EU,
    "northeurope": Jurisdiction.EU,
    "us-east-1": Jurisdiction.US,
    "us-east-2": Jurisdiction.US,
    "us-west-1": Jurisdiction.US,
    "us-west-2": Jurisdiction.US,
    "us-central1": Jurisdiction.US,
    "eastus": Jurisdiction.US,
    "westus": Jurisdiction.US,
    "eu-west-2-london": Jurisdiction.UK,
    "europe-west2": Jurisdiction.UK,
    "uksouth": Jurisdiction.UK,
    "cn-north-1": Jurisdiction.CHINA,
    "cn-northwest-1": Jurisdiction.CHINA,
    "asia-east1": Jurisdiction.CHINA,
    "chinaeast": Jurisdiction.CHINA,
    "ap-south-1": Jurisdiction.INDIA,
    "asia-south1": Jurisdiction.INDIA,
    "centralindia": Jurisdiction.INDIA,
    "sa-east-1": Jurisdiction.BRAZIL,
    "southamerica-east1": Jurisdiction.BRAZIL,
    "brazilsouth": Jurisdiction.BRAZIL,
    "ap-northeast-1": Jurisdiction.JAPAN,
    "asia-northeast1": Jurisdiction.JAPAN,
    "japaneast": Jurisdiction.JAPAN,
    "ap-southeast-2": Jurisdiction.AUSTRALIA,
    "australia-southeast1": Jurisdiction.AUSTRALIA,
    "australiaeast": Jurisdiction.AUSTRALIA,
    "ca-central-1": Jurisdiction.CANADA,
    "northamerica-northeast1": Jurisdiction.CANADA,
    "canadacentral": Jurisdiction.CANADA,
    "ap-southeast-1": Jurisdiction.SINGAPORE,
    "asia-southeast1": Jurisdiction.SINGAPORE,
    "southeastasia": Jurisdiction.SINGAPORE,
}

# ---------------------------------------------------------------------------
# Regulation applicability per jurisdiction
# ---------------------------------------------------------------------------

_JURISDICTION_REGULATIONS: dict[Jurisdiction, list[str]] = {
    Jurisdiction.EU: ["GDPR", "EU_DGA", "Schrems_II"],
    Jurisdiction.US: ["CCPA", "HIPAA", "SOX", "CLOUD_Act"],
    Jurisdiction.UK: ["UK_GDPR", "DPA_2018"],
    Jurisdiction.CHINA: ["PIPL", "CSL", "DSL"],
    Jurisdiction.INDIA: ["DPDP_Act"],
    Jurisdiction.BRAZIL: ["LGPD"],
    Jurisdiction.JAPAN: ["APPI"],
    Jurisdiction.AUSTRALIA: ["Privacy_Act_1988"],
    Jurisdiction.CANADA: ["PIPEDA"],
    Jurisdiction.SINGAPORE: ["PDPA"],
}

# ---------------------------------------------------------------------------
# Adequacy decisions (EU perspective, post-Schrems II)
# ---------------------------------------------------------------------------

_EU_ADEQUACY_JURISDICTIONS: set[Jurisdiction] = {
    Jurisdiction.UK,
    Jurisdiction.JAPAN,
    Jurisdiction.CANADA,
    Jurisdiction.SINGAPORE,
}

# ---------------------------------------------------------------------------
# Residency requirements per regulation
# ---------------------------------------------------------------------------

_RESIDENCY_REQUIREMENTS: dict[str, dict[str, str]] = {
    "PIPL": {
        "requirement": "Art. 38-43 — personal data of Chinese citizens must be stored in China "
        "unless security assessment passed",
        "required_location": "china",
    },
    "DPDP_Act": {
        "requirement": "Sec. 16 — certain categories of personal data must not be transferred "
        "outside India without govt approval",
        "required_location": "india",
    },
    "CSL": {
        "requirement": "Art. 37 — critical information infrastructure operators must store "
        "personal data within China",
        "required_location": "china",
    },
    "DSL": {
        "requirement": "Art. 31 — important data collected in China must be stored domestically",
        "required_location": "china",
    },
}


def _detect_jurisdiction(region: str) -> Jurisdiction:
    """Detect jurisdiction from a cloud region string."""
    region_lower = region.lower().strip()
    if region_lower in _REGION_JURISDICTION:
        return _REGION_JURISDICTION[region_lower]
    # Fallback heuristics
    if "eu" in region_lower or "europe" in region_lower:
        return Jurisdiction.EU
    if "us" in region_lower or "america" in region_lower:
        return Jurisdiction.US
    if "cn" in region_lower or "china" in region_lower:
        return Jurisdiction.CHINA
    if "india" in region_lower:
        return Jurisdiction.INDIA
    if "brazil" in region_lower or "sa-" in region_lower:
        return Jurisdiction.BRAZIL
    if "japan" in region_lower:
        return Jurisdiction.JAPAN
    if "australia" in region_lower:
        return Jurisdiction.AUSTRALIA
    if "canada" in region_lower:
        return Jurisdiction.CANADA
    if "uk" in region_lower or "london" in region_lower:
        return Jurisdiction.UK
    if "singapore" in region_lower or "southeast" in region_lower:
        return Jurisdiction.SINGAPORE
    return Jurisdiction.US  # default


class DataSovereigntyEnforcerToolkit:
    """Tools for discovering data flows, mapping jurisdictions, and enforcing sovereignty."""

    def __init__(
        self,
        flow_connector: Any | None = None,
        policy_engine: Any | None = None,
        geo_fence_api: Any | None = None,
    ) -> None:
        self._flow_connector = flow_connector
        self._policy_engine = policy_engine
        self._geo_fence_api = geo_fence_api
        self._flow_cache: dict[str, DataFlow] = {}

    async def discover_data_flows(
        self,
        tenant_id: str,
        flow_configs: list[dict[str, Any]] | None = None,
    ) -> list[DataFlow]:
        """Discover data flows across systems and regions.

        In production this queries network flow logs, API gateways, and data
        pipeline metadata. Here we build from *flow_configs* or return defaults.
        """
        logger.info(
            "data_sovereignty.discover_flows",
            tenant_id=tenant_id,
            configs=len(flow_configs or []),
        )
        flows: list[DataFlow] = []
        configs = flow_configs or []

        if not configs:
            configs = [
                {
                    "source_system": "crm-api",
                    "destination_system": "analytics-lake",
                    "source_region": "eu-west-1",
                    "destination_region": "us-east-1",
                    "data_categories": ["pii", "customer_data"],
                    "volume_gb_per_day": 12.5,
                    "encrypted": True,
                    "protocol": "https",
                },
                {
                    "source_system": "payment-service",
                    "destination_system": "fraud-engine",
                    "source_region": "eu-central-1",
                    "destination_region": "eu-west-1",
                    "data_categories": ["pci", "pii"],
                    "volume_gb_per_day": 3.2,
                    "encrypted": True,
                    "protocol": "grpc",
                },
                {
                    "source_system": "hr-portal",
                    "destination_system": "payroll-processor",
                    "source_region": "ap-south-1",
                    "destination_region": "us-west-2",
                    "data_categories": ["pii", "employee_data"],
                    "volume_gb_per_day": 0.8,
                    "encrypted": False,
                    "protocol": "https",
                },
                {
                    "source_system": "health-records-cn",
                    "destination_system": "research-cluster",
                    "source_region": "cn-north-1",
                    "destination_region": "us-east-1",
                    "data_categories": ["phi", "pii"],
                    "volume_gb_per_day": 5.4,
                    "encrypted": True,
                    "protocol": "sftp",
                },
                {
                    "source_system": "customer-db-br",
                    "destination_system": "ml-training",
                    "source_region": "sa-east-1",
                    "destination_region": "us-east-1",
                    "data_categories": ["pii", "behavioral"],
                    "volume_gb_per_day": 18.0,
                    "encrypted": True,
                    "protocol": "kafka",
                },
                {
                    "source_system": "eu-user-service",
                    "destination_system": "backup-store",
                    "source_region": "eu-central-1",
                    "destination_region": "eu-central-1",
                    "data_categories": ["pii"],
                    "volume_gb_per_day": 7.1,
                    "encrypted": True,
                    "protocol": "s3",
                },
            ]

        now = time.time()
        for cfg in configs:
            flow = DataFlow(
                id=str(uuid.uuid4())[:12],
                source_system=cfg.get("source_system", "unknown"),
                destination_system=cfg.get("destination_system", "unknown"),
                source_region=cfg.get("source_region", ""),
                destination_region=cfg.get("destination_region", ""),
                data_categories=cfg.get("data_categories", []),
                volume_gb_per_day=cfg.get("volume_gb_per_day", 0.0),
                encrypted=cfg.get("encrypted", False),
                protocol=cfg.get("protocol", ""),
            )
            flows.append(flow)
            self._flow_cache[flow.id] = flow
            _ = now  # suppress unused warning

        return flows

    async def map_jurisdictions(
        self,
        flows: list[DataFlow],
    ) -> list[JurisdictionMapping]:
        """Map each data flow to source/destination jurisdictions and regulations."""
        logger.info(
            "data_sovereignty.map_jurisdictions",
            flow_count=len(flows),
        )
        mappings: list[JurisdictionMapping] = []

        for flow in flows:
            src_j = _detect_jurisdiction(flow.source_region)
            dst_j = _detect_jurisdiction(flow.destination_region)
            cross_border = src_j != dst_j

            # Combine regulations from both jurisdictions
            regs: list[str] = []
            regs.extend(_JURISDICTION_REGULATIONS.get(src_j, []))
            if cross_border:
                regs.extend(_JURISDICTION_REGULATIONS.get(dst_j, []))
            regs = sorted(set(regs))

            # Determine if transfer is restricted
            restricted = False
            if cross_border:
                # China and India have strict data localization
                if src_j in {Jurisdiction.CHINA, Jurisdiction.INDIA}:
                    restricted = True
                # EU to non-adequate country
                if src_j == Jurisdiction.EU and dst_j not in _EU_ADEQUACY_JURISDICTIONS:
                    restricted = True

            mappings.append(
                JurisdictionMapping(
                    id=str(uuid.uuid4())[:12],
                    flow_id=flow.id,
                    source_jurisdiction=src_j,
                    destination_jurisdiction=dst_j,
                    regulations=regs,
                    cross_border=cross_border,
                    restricted=restricted,
                )
            )

        return mappings

    async def check_residency(
        self,
        flows: list[DataFlow],
        mappings: list[JurisdictionMapping],
    ) -> list[ResidencyViolation]:
        """Check data residency compliance against regulatory requirements."""
        logger.info(
            "data_sovereignty.check_residency",
            flow_count=len(flows),
        )
        violations: list[ResidencyViolation] = []
        {f.id: f for f in flows}
        mapping_map = {m.flow_id: m for m in mappings}

        for flow in flows:
            mapping = mapping_map.get(flow.id)
            if not mapping or not mapping.cross_border:
                continue

            src_j = mapping.source_jurisdiction

            # Check residency requirements for source jurisdiction
            for reg, req_info in _RESIDENCY_REQUIREMENTS.items():
                src_regs = _JURISDICTION_REGULATIONS.get(src_j, [])
                if reg not in src_regs:
                    continue

                required_loc = req_info["required_location"]
                dst_j = mapping.destination_jurisdiction
                if dst_j.value != required_loc:
                    severity = "critical" if "phi" in flow.data_categories else "high"
                    violations.append(
                        ResidencyViolation(
                            id=str(uuid.uuid4())[:12],
                            flow_id=flow.id,
                            regulation=reg,
                            requirement=req_info["requirement"],
                            actual_location=dst_j.value,
                            required_location=required_loc,
                            severity=severity,
                            remediation=(
                                f"Relocate data processing for "
                                f"{flow.source_system}->{flow.destination_system} "
                                f"to {required_loc} or obtain regulatory exemption"
                            ),
                        )
                    )

            # Schrems II: EU data to US without adequate safeguards
            if src_j == Jurisdiction.EU and mapping.destination_jurisdiction == Jurisdiction.US:
                violations.append(
                    ResidencyViolation(
                        id=str(uuid.uuid4())[:12],
                        flow_id=flow.id,
                        regulation="Schrems_II",
                        requirement=(
                            "CJEU C-311/18 — EU-US transfers require supplementary measures "
                            "beyond Privacy Shield (invalidated)"
                        ),
                        actual_location="us",
                        required_location="eu",
                        severity="high",
                        remediation=(
                            "Implement Standard Contractual Clauses (SCCs) with supplementary "
                            "measures (encryption, pseudonymization) or relocate processing to EU"
                        ),
                    )
                )

        return violations

    async def validate_transfers(
        self,
        flows: list[DataFlow],
        mappings: list[JurisdictionMapping],
    ) -> list[TransferValidation]:
        """Validate that cross-border transfers have valid legal mechanisms."""
        logger.info(
            "data_sovereignty.validate_transfers",
            flow_count=len(flows),
        )
        validations: list[TransferValidation] = []
        mapping_map = {m.flow_id: m for m in mappings}

        for flow in flows:
            mapping = mapping_map.get(flow.id)
            if not mapping or not mapping.cross_border:
                continue

            src_j = mapping.source_jurisdiction
            dst_j = mapping.destination_jurisdiction

            # Determine transfer mechanism
            mechanism = TransferMechanism.NONE
            valid = False
            details = ""

            if src_j == Jurisdiction.EU:
                if dst_j in _EU_ADEQUACY_JURISDICTIONS:
                    mechanism = TransferMechanism.ADEQUACY_DECISION
                    valid = True
                    details = f"EU adequacy decision covers transfers to {dst_j.value.upper()}"
                elif flow.encrypted:
                    # SCCs with encryption = conditionally valid
                    mechanism = TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES
                    valid = True
                    details = "SCCs with supplementary encryption measures per Schrems II"
                else:
                    mechanism = TransferMechanism.NONE
                    valid = False
                    details = (
                        f"No valid mechanism for EU->{dst_j.value.upper()} transfer; "
                        "data is unencrypted and no SCCs/BCRs in place"
                    )

            elif src_j == Jurisdiction.CHINA:
                # PIPL requires security assessment for cross-border transfers
                mechanism = TransferMechanism.NONE
                valid = False
                details = (
                    "PIPL Art. 38 requires CAC security assessment for cross-border transfer "
                    "of personal data originating in China"
                )

            elif src_j == Jurisdiction.BRAZIL:
                if dst_j in {Jurisdiction.EU, Jurisdiction.UK, Jurisdiction.CANADA}:
                    mechanism = TransferMechanism.ADEQUACY_DECISION
                    valid = True
                    details = (
                        f"LGPD Art. 33(I) — ANPD recognizes {dst_j.value.upper()} "
                        "as providing adequate protection"
                    )
                else:
                    mechanism = TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES
                    valid = flow.encrypted
                    details = (
                        "LGPD Art. 33(II) — requires contractual clauses with adequate safeguards"
                    )

            elif src_j == Jurisdiction.INDIA:
                mechanism = TransferMechanism.CONSENT
                valid = False
                details = (
                    "DPDP Act Sec. 16 — cross-border transfer requires explicit consent "
                    "and destination must not be on restricted list"
                )

            else:
                # Default: allow encrypted transfers with consent mechanism
                if flow.encrypted:
                    mechanism = TransferMechanism.CONSENT
                    valid = True
                    details = "Encrypted transfer with implied consent mechanism"
                else:
                    mechanism = TransferMechanism.NONE
                    valid = False
                    details = "Unencrypted cross-border transfer without legal mechanism"

            # Determine applicable regulation
            src_regs = _JURISDICTION_REGULATIONS.get(src_j, [])
            regulation = src_regs[0] if src_regs else "unknown"

            validations.append(
                TransferValidation(
                    id=str(uuid.uuid4())[:12],
                    flow_id=flow.id,
                    mechanism=mechanism,
                    valid=valid,
                    regulation=regulation,
                    details=details,
                    expiry_date="",
                )
            )

        return validations

    async def enforce_policies(
        self,
        flows: list[DataFlow],
        violations: list[ResidencyViolation],
        validations: list[TransferValidation],
    ) -> list[PolicyEnforcement]:
        """Enforce sovereignty policies based on violations and transfer validations.

        In production this calls geo-fence APIs, network policy engines, and
        data routing controllers. Here we simulate enforcement actions.
        """
        logger.info(
            "data_sovereignty.enforce_policies",
            flow_count=len(flows),
            violation_count=len(violations),
        )
        enforcements: list[PolicyEnforcement] = []

        violation_flows = {v.flow_id for v in violations}
        invalid_transfers = {v.flow_id for v in validations if not v.valid}

        for flow in flows:
            has_violation = flow.id in violation_flows
            has_invalid_transfer = flow.id in invalid_transfers

            if has_violation and has_invalid_transfer:
                # Critical: block the flow
                action = "block"
                policy_name = "sovereignty_violation_block"
                details = (
                    f"Blocked {flow.source_system}->{flow.destination_system}: "
                    "residency violation + no valid transfer mechanism"
                )
            elif has_violation:
                # Violation but valid transfer mechanism: redirect + alert
                action = "redirect"
                policy_name = "sovereignty_violation_redirect"
                details = (
                    f"Redirecting {flow.source_system}->{flow.destination_system} "
                    "to compliant region; alerting DPO"
                )
            elif has_invalid_transfer:
                # No violation but invalid mechanism: encrypt + alert
                action = "encrypt"
                policy_name = "transfer_mechanism_enforce"
                details = (
                    f"Enforcing encryption on {flow.source_system}->"
                    f"{flow.destination_system}; requesting SCC documentation"
                )
            elif not flow.encrypted:
                # No violations but unencrypted: enforce encryption
                action = "encrypt"
                policy_name = "encryption_enforcement"
                details = (
                    f"Enforcing encryption on {flow.source_system}->"
                    f"{flow.destination_system} as baseline sovereignty control"
                )
            else:
                action = "allow"
                policy_name = "sovereignty_compliant"
                details = (
                    f"Flow {flow.source_system}->{flow.destination_system} "
                    "meets all sovereignty requirements"
                )

            success = True
            if self._geo_fence_api and action in {"block", "redirect"}:
                try:
                    await self._geo_fence_api.enforce(
                        flow_id=flow.id,
                        action=action,
                    )
                except Exception:
                    success = False
                    logger.warning(
                        "data_sovereignty.enforce_failed",
                        flow_id=flow.id,
                        action=action,
                    )

            enforcements.append(
                PolicyEnforcement(
                    id=str(uuid.uuid4())[:12],
                    flow_id=flow.id,
                    action=action,
                    policy_name=policy_name,
                    applied=True,
                    success=success,
                    details=details,
                )
            )

        return enforcements
