"""Tests for shieldops.agents.data_encryption_monitor."""

from __future__ import annotations

import pytest

from shieldops.agents.data_encryption_monitor.models import (
    CertificateHealth,
    CertificateStatus,
    DataEncryptionMonitorState,
    EncryptionAsset,
    EncryptionGap,
    EncryptionStage,
    EncryptionType,
    KeyRotationStatus,
)
from shieldops.agents.data_encryption_monitor.tools import (
    DataEncryptionMonitorToolkit,
)


class TestEnums:
    def test_stage_scan_assets(self):
        assert EncryptionStage.SCAN_ASSETS == "scan_assets"

    def test_stage_assess_encryption(self):
        assert EncryptionStage.ASSESS_ENCRYPTION == "assess_encryption"

    def test_stage_check_key_rotation(self):
        assert EncryptionStage.CHECK_KEY_ROTATION == "check_key_rotation"

    def test_stage_check_certificates(self):
        assert EncryptionStage.CHECK_CERTIFICATES == "check_certificates"

    def test_stage_identify_gaps(self):
        assert EncryptionStage.IDENTIFY_GAPS == "identify_gaps"

    def test_stage_report(self):
        assert EncryptionStage.REPORT == "report"

    def test_type_at_rest(self):
        assert EncryptionType.AT_REST == "at_rest"

    def test_type_in_transit(self):
        assert EncryptionType.IN_TRANSIT == "in_transit"

    def test_type_end_to_end(self):
        assert EncryptionType.END_TO_END == "end_to_end"

    def test_type_field_level(self):
        assert EncryptionType.FIELD_LEVEL == "field_level"

    def test_type_none(self):
        assert EncryptionType.NONE == "none"

    def test_cert_status_valid(self):
        assert CertificateStatus.VALID == "valid"

    def test_cert_status_expiring_soon(self):
        assert CertificateStatus.EXPIRING_SOON == "expiring_soon"

    def test_cert_status_expired(self):
        assert CertificateStatus.EXPIRED == "expired"

    def test_cert_status_revoked(self):
        assert CertificateStatus.REVOKED == "revoked"

    def test_cert_status_self_signed(self):
        assert CertificateStatus.SELF_SIGNED == "self_signed"

    def test_cert_status_unknown(self):
        assert CertificateStatus.UNKNOWN == "unknown"


class TestModels:
    def test_state_defaults(self):
        s = DataEncryptionMonitorState(tenant_id="t-01")
        assert s.error == ""
        assert s.encryption_coverage_pct == 0.0
        assert s.assets_scanned == []
        assert s.key_rotation_statuses == []
        assert s.certificate_health == []
        assert s.encryption_gaps == []

    def test_encryption_asset_defaults(self):
        a = EncryptionAsset()
        assert a.id == ""
        assert a.is_encrypted is False
        assert a.encryption_type == EncryptionType.NONE

    def test_key_rotation_status_defaults(self):
        k = KeyRotationStatus()
        assert k.key_id == ""
        assert k.is_overdue is False
        assert k.auto_rotation_enabled is False

    def test_certificate_health_defaults(self):
        c = CertificateHealth()
        assert c.status == CertificateStatus.UNKNOWN
        assert c.days_until_expiry == 0
        assert c.auto_renew is False

    def test_encryption_gap_defaults(self):
        g = EncryptionGap()
        assert g.severity == "medium"
        assert g.compliance_impact == []


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        return DataEncryptionMonitorToolkit()

    @pytest.mark.asyncio()
    async def test_scan_assets(self, toolkit):
        assets = await toolkit.scan_assets(tenant_id="t-01")
        assert len(assets) > 0
        assert all(isinstance(a, EncryptionAsset) for a in assets)

    @pytest.mark.asyncio()
    async def test_scan_assets_filter_provider(self, toolkit):
        assets = await toolkit.scan_assets(
            tenant_id="t-01",
            cloud_providers=["gcp"],
        )
        assert all(a.cloud_provider == "gcp" for a in assets)

    @pytest.mark.asyncio()
    async def test_check_key_rotation(self, toolkit):
        assets = await toolkit.scan_assets(tenant_id="t-01")
        statuses = await toolkit.check_key_rotation(assets=assets)
        assert len(statuses) > 0
        assert all(isinstance(s, KeyRotationStatus) for s in statuses)

    @pytest.mark.asyncio()
    async def test_check_certificates(self, toolkit):
        assets = await toolkit.scan_assets(tenant_id="t-01")
        certs = await toolkit.check_certificates(assets=assets)
        assert len(certs) > 0
        assert all(isinstance(c, CertificateHealth) for c in certs)

    @pytest.mark.asyncio()
    async def test_identify_gaps(self, toolkit):
        assets = await toolkit.scan_assets(tenant_id="t-01")
        keys = await toolkit.check_key_rotation(assets=assets)
        certs = await toolkit.check_certificates(assets=assets)
        gaps = await toolkit.identify_gaps(
            assets=assets,
            key_statuses=keys,
            certificates=certs,
        )
        assert len(gaps) > 0
        assert all(isinstance(g, EncryptionGap) for g in gaps)
        # Should find unencrypted assets
        unencrypted = [g for g in gaps if g.gap_type == "unencrypted"]
        assert len(unencrypted) > 0


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.data_encryption_monitor.graph import (
            create_data_encryption_monitor_graph,
        )

        sg = create_data_encryption_monitor_graph()
        assert sg.compile() is not None
