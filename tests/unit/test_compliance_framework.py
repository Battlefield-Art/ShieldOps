"""Tests for the compliance framework: PII detection, encryption, retention,
security events, and FedRAMP controls.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from shieldops.compliance.pii_detector import PIICategory, PIIDetector, PIIMatch
from shieldops.compliance.data_encryption import FieldEncryptor
from shieldops.compliance.data_retention import (
    DataRetentionManager,
    RetentionPolicy,
)
from shieldops.compliance.security_events import (
    SecurityEvent,
    SecurityEventLogger,
    SecurityEventType,
)
from shieldops.compliance.fedramp_controls import (
    ControlCheck,
    FedRAMPControlFamily,
    FedRAMPValidator,
)


# =====================================================================
# PII Detection
# =====================================================================


class TestPIIDetectorScan:
    """PIIDetector.scan — find PII without modifying text."""

    def test_detect_ssn(self) -> None:
        detector = PIIDetector()
        matches = detector.scan("SSN is 123-45-6789")
        assert any(m.category == PIICategory.SSN for m in matches)

    def test_detect_credit_card_visa(self) -> None:
        detector = PIIDetector()
        matches = detector.scan("Card: 4111111111111111")
        assert any(m.category == PIICategory.CREDIT_CARD for m in matches)

    def test_detect_credit_card_mastercard(self) -> None:
        detector = PIIDetector()
        matches = detector.scan("Card: 5105105105105100")
        assert any(m.category == PIICategory.CREDIT_CARD for m in matches)

    def test_detect_email(self) -> None:
        detector = PIIDetector()
        matches = detector.scan("Contact alice@example.com for info")
        assert any(m.category == PIICategory.EMAIL for m in matches)

    def test_detect_phone(self) -> None:
        detector = PIIDetector()
        matches = detector.scan("Call 555-123-4567 now")
        assert any(m.category == PIICategory.PHONE for m in matches)

    def test_detect_ip_address(self) -> None:
        detector = PIIDetector()
        matches = detector.scan("Server at 192.168.1.100")
        assert any(m.category == PIICategory.IP_ADDRESS for m in matches)

    def test_detect_aws_key(self) -> None:
        detector = PIIDetector()
        matches = detector.scan("key=AKIAIOSFODNN7EXAMPLE")
        assert any(m.category == PIICategory.AWS_KEY for m in matches)

    def test_detect_api_key_openai(self) -> None:
        detector = PIIDetector()
        matches = detector.scan("sk-abc12345678901234567890")
        assert any(m.category == PIICategory.API_KEY for m in matches)

    def test_detect_password(self) -> None:
        detector = PIIDetector()
        matches = detector.scan("password=SuperSecret123!")
        assert any(m.category == PIICategory.PASSWORD for m in matches)

    def test_detect_phi_mrn(self) -> None:
        detector = PIIDetector()
        matches = detector.scan("Patient MRN: 12345678")
        assert any(m.category == PIICategory.PHI_MRN for m in matches)

    def test_no_false_positive_on_clean_text(self) -> None:
        detector = PIIDetector()
        matches = detector.scan("The quick brown fox jumps over the lazy dog")
        assert len(matches) == 0

    def test_multiple_pii_in_one_string(self) -> None:
        detector = PIIDetector()
        text = "SSN 123-45-6789, email: bob@test.com"
        matches = detector.scan(text)
        categories = {m.category for m in matches}
        assert PIICategory.SSN in categories
        assert PIICategory.EMAIL in categories


# =====================================================================
# PII Redaction
# =====================================================================


class TestPIIDetectorRedact:
    """PIIDetector.redact — replace PII with masks."""

    def test_redact_ssn(self) -> None:
        detector = PIIDetector()
        redacted, matches = detector.redact("SSN is 123-45-6789")
        assert "123-45-6789" not in redacted
        assert "***-**-****" in redacted

    def test_redact_email(self) -> None:
        detector = PIIDetector()
        redacted, _ = detector.redact("Email: user@corp.io")
        assert "user@corp.io" not in redacted
        assert "[EMAIL_REDACTED]" in redacted

    def test_redact_preserves_non_pii_text(self) -> None:
        detector = PIIDetector()
        redacted, _ = detector.redact("Hello world, SSN 123-45-6789 end")
        assert redacted.startswith("Hello world,")
        assert redacted.endswith("end")

    def test_redact_returns_matches(self) -> None:
        detector = PIIDetector()
        _, matches = detector.redact("SSN 123-45-6789")
        assert len(matches) >= 1
        assert matches[0].framework == "soc2"

    def test_redact_dict_flat(self) -> None:
        detector = PIIDetector()
        data = {"name": "Alice", "ssn": "123-45-6789"}
        redacted, matches = detector.redact_dict(data)
        assert "123-45-6789" not in redacted["ssn"]
        assert len(matches) >= 1

    def test_redact_dict_nested(self) -> None:
        detector = PIIDetector()
        data = {"user": {"contact": {"email": "a@b.com"}}}
        redacted, matches = detector.redact_dict(data)
        assert "a@b.com" not in redacted["user"]["contact"]["email"]
        assert any(m.category == PIICategory.EMAIL for m in matches)

    def test_redact_dict_with_list(self) -> None:
        detector = PIIDetector()
        data = {"emails": ["x@y.com", "z@w.com"]}
        redacted, matches = detector.redact_dict(data)
        assert all("[EMAIL_REDACTED]" in v for v in redacted["emails"])

    def test_scan_dict_finds_pii(self) -> None:
        detector = PIIDetector()
        data = {"key": "AKIAIOSFODNN7EXAMPLE"}
        matches = detector.scan_dict(data)
        assert any(m.category == PIICategory.AWS_KEY for m in matches)


# =====================================================================
# Field Encryption
# =====================================================================


class TestFieldEncryptor:
    """FieldEncryptor — encrypt/decrypt individual fields."""

    def test_roundtrip(self) -> None:
        enc = FieldEncryptor()
        ct = enc.encrypt("hello")
        assert enc.decrypt(ct) == "hello"

    def test_ciphertext_differs_from_plaintext(self) -> None:
        enc = FieldEncryptor()
        ct = enc.encrypt("secret")
        assert ct != "secret"

    def test_encrypt_dict(self) -> None:
        enc = FieldEncryptor()
        data = {"ssn": "123-45-6789", "name": "Alice"}
        encrypted = enc.encrypt_dict(data, ["ssn"])
        assert encrypted["ssn"] != "123-45-6789"
        assert encrypted["name"] == "Alice"  # untouched

    def test_decrypt_dict(self) -> None:
        enc = FieldEncryptor()
        data = {"ssn": "123-45-6789", "name": "Alice"}
        encrypted = enc.encrypt_dict(data, ["ssn"])
        decrypted = enc.decrypt_dict(encrypted, ["ssn"])
        assert decrypted["ssn"] == "123-45-6789"

    def test_generate_key_returns_valid_key(self) -> None:
        key = FieldEncryptor.generate_key()
        enc = FieldEncryptor(encryption_key=key)
        ct = enc.encrypt("test")
        assert enc.decrypt(ct) == "test"

    def test_wrong_key_raises(self) -> None:
        enc1 = FieldEncryptor()
        ct = enc1.encrypt("secret")
        enc2 = FieldEncryptor()  # different key
        with pytest.raises(Exception):
            enc2.decrypt(ct)


# =====================================================================
# Data Retention
# =====================================================================


class TestDataRetention:
    """DataRetentionManager — policy lookup and compliance checks."""

    def test_get_all_policies(self) -> None:
        mgr = DataRetentionManager()
        policies = mgr.get_policies()
        assert len(policies) >= 4

    def test_get_policies_by_framework(self) -> None:
        mgr = DataRetentionManager()
        hipaa = mgr.get_policies(framework="hipaa")
        assert all(p.framework == "hipaa" for p in hipaa)
        assert len(hipaa) >= 1

    def test_compliance_check_within_retention(self) -> None:
        mgr = DataRetentionManager()
        result = mgr.check_compliance(record_age_days=100, data_type="audit_log")
        assert result.compliant is True
        assert len(result.violations) == 0

    def test_compliance_check_exceeds_retention(self) -> None:
        mgr = DataRetentionManager()
        result = mgr.check_compliance(record_age_days=400, data_type="audit_log")
        assert result.compliant is False
        assert len(result.violations) >= 1
        assert result.recommended_action == "archive"

    def test_compliance_check_unknown_type(self) -> None:
        mgr = DataRetentionManager()
        result = mgr.check_compliance(record_age_days=9999, data_type="unknown_type")
        assert result.compliant is True

    def test_custom_policy(self) -> None:
        custom = RetentionPolicy(
            framework="internal", data_type="tmp_data", retention_days=30, action="delete"
        )
        mgr = DataRetentionManager(custom_policies=[custom])
        result = mgr.check_compliance(record_age_days=60, data_type="tmp_data")
        assert result.compliant is False
        assert result.recommended_action == "delete"

    @pytest.mark.asyncio
    async def test_purge_expired_dry_run(self) -> None:
        mgr = DataRetentionManager()
        result = await mgr.purge_expired(session_factory=None, dry_run=True)
        assert result["dry_run"] is True
        assert result["policies_evaluated"] >= 4
        assert isinstance(result["details"], list)


# =====================================================================
# Security Events
# =====================================================================


class TestSecurityEvents:
    """SecurityEventLogger — creation, CEF export, and querying."""

    def _make_event(self, **kwargs: object) -> SecurityEvent:
        defaults: dict = {
            "event_type": SecurityEventType.AUTH_SUCCESS,
            "severity": 3,
            "actor": "user@corp.com",
            "target": "/api/v1/agents",
            "action": "login",
            "outcome": "success",
            "source_ip": "10.0.0.1",
            "compliance_frameworks": ["soc2"],
        }
        defaults.update(kwargs)
        return SecurityEvent(**defaults)

    def test_log_and_retrieve(self) -> None:
        slog = SecurityEventLogger()
        evt = self._make_event()
        slog.log_event(evt)
        events = slog.get_events()
        assert len(events) == 1
        assert events[0].actor == "user@corp.com"

    def test_cef_format(self) -> None:
        slog = SecurityEventLogger()
        evt = self._make_event()
        cef = slog.to_cef(evt)
        assert cef.startswith("CEF:0|ShieldOps|")
        assert "auth_success" in cef
        assert "duser=user@corp.com" in cef

    def test_filter_by_event_type(self) -> None:
        slog = SecurityEventLogger()
        slog.log_event(self._make_event(event_type=SecurityEventType.AUTH_SUCCESS))
        slog.log_event(self._make_event(event_type=SecurityEventType.AUTH_FAILURE))
        results = slog.get_events(event_type=SecurityEventType.AUTH_FAILURE)
        assert len(results) == 1
        assert results[0].event_type == SecurityEventType.AUTH_FAILURE

    def test_filter_by_actor(self) -> None:
        slog = SecurityEventLogger()
        slog.log_event(self._make_event(actor="alice"))
        slog.log_event(self._make_event(actor="bob"))
        results = slog.get_events(actor="alice")
        assert all(e.actor == "alice" for e in results)

    def test_filter_by_since(self) -> None:
        slog = SecurityEventLogger()
        old = self._make_event(
            timestamp=datetime.now(timezone.utc) - timedelta(hours=2)
        )
        new = self._make_event()
        slog.log_event(old)
        slog.log_event(new)
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        results = slog.get_events(since=since)
        assert len(results) == 1

    def test_limit(self) -> None:
        slog = SecurityEventLogger()
        for _ in range(10):
            slog.log_event(self._make_event())
        results = slog.get_events(limit=3)
        assert len(results) == 3


# =====================================================================
# FedRAMP Controls
# =====================================================================


class TestFedRAMPValidator:
    """FedRAMPValidator — control checks and SSP evidence."""

    def test_access_controls(self) -> None:
        v = FedRAMPValidator()
        checks = v.validate_access_controls()
        assert len(checks) >= 3
        assert all(c.family == FedRAMPControlFamily.AC for c in checks)

    def test_audit_logging_controls(self) -> None:
        v = FedRAMPValidator()
        checks = v.validate_audit_logging()
        assert len(checks) >= 3
        assert all(c.family == FedRAMPControlFamily.AU for c in checks)

    def test_encryption_controls(self) -> None:
        v = FedRAMPValidator()
        checks = v.validate_encryption()
        assert len(checks) >= 2
        assert all(c.family == FedRAMPControlFamily.SC for c in checks)

    def test_ssp_evidence_structure(self) -> None:
        v = FedRAMPValidator()
        ssp = v.generate_ssp_evidence()
        assert "total_controls" in ssp
        assert "passed" in ssp
        assert "compliance_rate" in ssp
        assert "controls" in ssp
        assert ssp["total_controls"] >= 8

    def test_ssp_compliance_rate(self) -> None:
        v = FedRAMPValidator()
        ssp = v.generate_ssp_evidence()
        # Most controls pass; rate should be > 50%
        assert ssp["compliance_rate"] > 50.0

    def test_control_check_model(self) -> None:
        check = ControlCheck(
            control_id="AC-99",
            family=FedRAMPControlFamily.AC,
            description="Test control",
            status="fail",
            evidence="No evidence",
        )
        assert check.status == "fail"
