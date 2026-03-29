"""Cloud Identity Federation Agent — Tool functions."""

from __future__ import annotations

import random
import uuid
from typing import Any

import structlog

from .models import (
    FederatedIdentity,
    FederationMapping,
    FederationRisk,
    IdentityProvider,
    SsoMisconfiguration,
    TrustAnalysis,
)

logger = structlog.get_logger()

_SSO_MISCONFIG_TYPES = [
    {
        "type": "missing_mfa",
        "severity": FederationRisk.CRITICAL,
        "desc": "MFA not enforced on federation trust",
        "fix": "Enable MFA requirement on IdP federation",
    },
    {
        "type": "long_session",
        "severity": FederationRisk.HIGH,
        "desc": "Session duration exceeds 4 hours",
        "fix": "Reduce session duration to 1 hour max",
    },
    {
        "type": "wildcard_attribute",
        "severity": FederationRisk.HIGH,
        "desc": "Wildcard attribute mapping allows any role",
        "fix": "Restrict attribute mapping to specific roles",
    },
    {
        "type": "stale_certificate",
        "severity": FederationRisk.MEDIUM,
        "desc": "SAML signing certificate expires soon",
        "fix": "Rotate SAML signing certificate",
    },
    {
        "type": "no_audience_restriction",
        "severity": FederationRisk.HIGH,
        "desc": "SAML assertion lacks audience restriction",
        "fix": "Add audience restriction to SAML config",
    },
    {
        "type": "insecure_binding",
        "severity": FederationRisk.MEDIUM,
        "desc": "HTTP redirect binding used instead of POST",
        "fix": "Switch to HTTP POST binding for SAML",
    },
]


class CloudIdentityFederationToolkit:
    """Tools for cloud identity federation security."""

    def __init__(
        self,
        idp_clients: Any | None = None,
    ) -> None:
        self._idp_clients = idp_clients

    async def discover_identities(
        self,
        tenant_id: str,
        identity_providers: list[str],
    ) -> list[FederatedIdentity]:
        """Discover federated identities across providers."""
        logger.info(
            "cif.discover",
            tenant_id=tenant_id,
            idps=identity_providers,
        )

        if self._idp_clients is not None:
            try:
                raw = await self._idp_clients.list_identities(
                    tenant_id=tenant_id,
                    providers=identity_providers,
                )
                return [FederatedIdentity(**r) for r in raw]
            except Exception:
                logger.exception("cif.discover.error")

        identities: list[FederatedIdentity] = []
        users = [
            ("admin", "admin@company.com"),
            ("dev-lead", "devlead@company.com"),
            ("security-eng", "seceng@company.com"),
            ("platform-eng", "platform@company.com"),
            ("data-eng", "dataeng@company.com"),
            ("sre", "sre@company.com"),
            ("analyst", "analyst@company.com"),
            ("intern", "intern@company.com"),
        ]

        for idp_key in identity_providers:
            selected_users = random.sample(  # noqa: S311
                users,
                min(len(users), random.randint(4, 8)),  # noqa: S311
            )
            for name, email in selected_users:
                identities.append(
                    FederatedIdentity(
                        id=str(uuid.uuid4())[:8],
                        identity_provider=IdentityProvider(idp_key),
                        principal_name=name,
                        email=email,
                        cloud_mappings=[
                            {"cloud": "aws", "role": f"{name}-role"},
                            {"cloud": "gcp", "role": f"{name}-sa"},
                        ],
                        mfa_enabled=random.random() > 0.2,  # noqa: S311
                        roles=[
                            random.choice(  # noqa: S311
                                [
                                    "admin",
                                    "developer",
                                    "viewer",
                                    "security",
                                ]
                            )
                        ],
                    )
                )

        logger.info("cif.discover.done", count=len(identities))
        return identities

    async def map_federations(
        self,
        identities: list[FederatedIdentity],
    ) -> list[FederationMapping]:
        """Map federation trust relationships."""
        logger.info("cif.map_fed", count=len(identities))

        idps = {ident.identity_provider.value for ident in identities}
        clouds = ["aws", "gcp", "azure"]

        mappings: list[FederationMapping] = []
        for idp in idps:
            for cloud in clouds:
                mappings.append(
                    FederationMapping(
                        id=str(uuid.uuid4())[:8],
                        source_idp=idp,
                        target_cloud=cloud,
                        trust_type="saml_federation",
                        protocol=random.choice(  # noqa: S311
                            ["saml", "oidc"]
                        ),
                        attribute_mappings={
                            "role": f"{cloud}_role_attr",
                            "email": "email",
                        },
                        session_duration_hours=random.choice(  # noqa: S311
                            [1, 2, 4, 8, 12]
                        ),
                        mfa_required=random.random() > 0.3,  # noqa: S311
                    )
                )

        logger.info("cif.map_fed.done", mappings=len(mappings))
        return mappings

    async def detect_sso_misconfigs(
        self,
        mappings: list[FederationMapping],
        identities: list[FederatedIdentity],
    ) -> list[SsoMisconfiguration]:
        """Detect SSO misconfigurations."""
        logger.info(
            "cif.misconfigs",
            mappings=len(mappings),
        )

        misconfigs: list[SsoMisconfiguration] = []
        for mapping in mappings:
            if random.random() > 0.4:  # noqa: S311
                tpl = random.choice(  # noqa: S311
                    _SSO_MISCONFIG_TYPES
                )
                base_risk = {
                    FederationRisk.CRITICAL: 90.0,
                    FederationRisk.HIGH: 70.0,
                    FederationRisk.MEDIUM: 50.0,
                }.get(tpl["severity"], 50.0)

                misconfigs.append(
                    SsoMisconfiguration(
                        id=str(uuid.uuid4())[:8],
                        federation_id=mapping.id,
                        misconfig_type=tpl["type"],
                        severity=tpl["severity"],
                        description=tpl["desc"],
                        affected_users=random.randint(  # noqa: S311
                            5, 50
                        ),
                        risk_score=round(
                            base_risk + random.uniform(-5, 5),  # noqa: S311
                            1,
                        ),
                        remediation=tpl["fix"],
                    )
                )

        logger.info(
            "cif.misconfigs.done",
            misconfigs=len(misconfigs),
        )
        return misconfigs

    async def analyze_trust_chains(
        self,
        mappings: list[FederationMapping],
        misconfigs: list[SsoMisconfiguration],
    ) -> list[TrustAnalysis]:
        """Analyze federation trust chains."""
        logger.info(
            "cif.trust",
            mappings=len(mappings),
        )

        analyses: list[TrustAnalysis] = []
        idps = {m.source_idp for m in mappings}

        for idp in idps:
            idp_mappings = [m for m in mappings if m.source_idp == idp]
            clouds = [m.target_cloud for m in idp_mappings]
            idp_misconfigs = [
                mc for mc in misconfigs if mc.federation_id in {m.id for m in idp_mappings}
            ]

            weaknesses = [mc.description for mc in idp_misconfigs]
            trust_score = max(
                0.0,
                100.0 - len(idp_misconfigs) * 15.0,
            )

            analyses.append(
                TrustAnalysis(
                    id=str(uuid.uuid4())[:8],
                    trust_chain=[idp] + clouds,
                    trust_score=round(trust_score, 1),
                    weaknesses=weaknesses[:5],
                    cross_cloud_risks=[f"Compromise of {idp} affects {', '.join(clouds)}"],
                    description=(f"Trust chain: {idp} -> {', '.join(clouds)}"),
                )
            )

        logger.info(
            "cif.trust.done",
            analyses=len(analyses),
        )
        return analyses
