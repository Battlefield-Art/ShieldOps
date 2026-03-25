"""Integration tests for vendor security webhook receivers."""
from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from shieldops.api.routes.webhooks_security import (
    NormalizedSecurityEvent,
    _cs_severity_map,
    _defender_severity_map,
    _dedup_cache,
    _is_duplicate,
    _normalize_crowdstrike,
    _normalize_defender,
    _normalize_wiz,
    _verify_signature,
    _wiz_severity_map,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_hmac(payload: bytes, secret: str, algorithm: str = "sha256") -> str:
    hash_func = hashlib.sha256 if algorithm == "sha256" else hashlib.sha1
    return hmac.new(secret.encode("utf-8"), payload, hash_func).hexdigest()


@pytest.fixture(autouse=True)
def _clear_dedup() -> None:
    """Ensure dedup cache is empty before each test."""
    _dedup_cache.clear()


# ── CrowdStrike payloads ─────────────────────────────────────────────────────


def _crowdstrike_detection(
    detection_id: str = "ldt:abc123:456",
    severity: int = 4,
    technique: str = "Process Injection",
    technique_id: str = "T1055",
    hostname: str = "web-prod-01",
    filename: str = "malware.exe",
    username: str = "jdoe",
    cmdline: str = "powershell -enc <base64>",
) -> dict:
    return {
        "event": {
            "DetectId": detection_id,
            "Severity": severity,
            "Technique": technique,
            "TechniqueId": technique_id,
            "Tactic": "Defense Evasion",
            "ComputerName": hostname,
            "FileName": filename,
            "UserName": username,
            "CommandLine": cmdline,
            "DetectName": "ML-based Detection",
            "ProcessStartTime": "2026-03-25T10:30:00Z",
        }
    }


# ── Defender payloads ────────────────────────────────────────────────────────


def _defender_alert(
    alert_id: str = "da636983279369912129_-123456789",
    severity: str = "High",
    category: str = "Malware",
    title: str = "Suspicious PowerShell activity",
    devices: list | None = None,
    evidence: list | None = None,
    mitre: list | None = None,
) -> dict:
    return {
        "alert": {
            "alertId": alert_id,
            "severity": severity,
            "category": category,
            "title": title,
            "description": "PowerShell executed encoded command on endpoint",
            "devices": devices
            or [
                {"deviceDnsName": "desktop-corp-42", "deviceId": "d-001"},
                {"deviceDnsName": "laptop-eng-17", "deviceId": "d-002"},
            ],
            "evidence": evidence
            or [
                {"entityType": "file", "fileName": "payload.ps1"},
                {"entityType": "ip", "ipAddress": "10.0.0.55"},
                {"entityType": "domain", "domainName": "evil.example.com"},
            ],
            "mitreTechniques": mitre or ["T1059.001", "T1027"],
        }
    }


# ── Wiz payloads ─────────────────────────────────────────────────────────────


def _wiz_issue(
    issue_id: str = "wiz-issue-abc-123",
    severity: str = "HIGH",
    rule_name: str = "S3 Bucket Publicly Accessible",
    resource_name: str = "prod-data-bucket",
    resource_type: str = "aws_s3_bucket",
    cloud_account: str = "prod-aws-account",
    sub_categories: list | None = None,
) -> dict:
    return {
        "issue": {
            "id": issue_id,
            "severity": severity,
            "status": "OPEN",
            "sourceRule": {"name": rule_name, "id": "rule-001"},
            "resource": {
                "name": resource_name,
                "type": resource_type,
                "nativeType": resource_type,
                "cloudAccount": {"name": cloud_account, "id": "acct-001"},
            },
            "securitySubCategories": sub_categories or [],
            "createdAt": "2026-03-25T08:00:00Z",
        }
    }


# ══════════════════════════════════════════════════════════════════════════════
# TestCrowdStrikeWebhook
# ══════════════════════════════════════════════════════════════════════════════


class TestCrowdStrikeWebhook:
    """Tests for CrowdStrike detection event normalization."""

    def test_normalize_crowdstrike_detection(self) -> None:
        payload = _crowdstrike_detection()
        event = _normalize_crowdstrike(payload)

        assert isinstance(event, NormalizedSecurityEvent)
        assert event.event_id == "ldt:abc123:456"
        assert event.vendor == "crowdstrike"
        assert event.event_type == "detection"
        assert event.severity == "high"  # severity 4 -> high
        assert "Process Injection" in event.title
        # Entities extracted
        host_entities = [e for e in event.entities if e["type"] == "host"]
        assert any(e["value"] == "web-prod-01" for e in host_entities)
        file_entities = [e for e in event.entities if e["type"] == "file"]
        assert any(e["value"] == "malware.exe" for e in file_entities)
        user_entities = [e for e in event.entities if e["type"] == "user"]
        assert any(e["value"] == "jdoe" for e in user_entities)
        # MITRE techniques present
        assert "Process Injection" in event.mitre_techniques
        assert "T1055" in event.mitre_techniques
        # Raw data preserved
        assert event.raw_data == payload

    def test_crowdstrike_severity_mapping(self) -> None:
        for sev_num, expected in _cs_severity_map.items():
            payload = _crowdstrike_detection(severity=int(sev_num))
            event = _normalize_crowdstrike(payload)
            assert event.severity == expected, (
                f"Severity {sev_num} should map to '{expected}', got '{event.severity}'"
            )

    def test_crowdstrike_deduplication(self) -> None:
        event_id = "ldt:dedup-test:001"
        assert _is_duplicate(event_id) is False, "First occurrence should not be a duplicate"
        assert _is_duplicate(event_id) is True, "Second occurrence should be a duplicate"

    def test_crowdstrike_missing_fields(self) -> None:
        # Minimal payload — only the wrapper key, no inner fields
        payload = {"event": {}}
        event = _normalize_crowdstrike(payload)

        assert isinstance(event, NormalizedSecurityEvent)
        assert event.vendor == "crowdstrike"
        assert event.event_type == "detection"
        # Should still get a default severity
        assert event.severity == "medium"  # severity "3" default
        # Should not crash with empty entities / mitre
        assert isinstance(event.entities, list)
        assert isinstance(event.mitre_techniques, list)

    def test_crowdstrike_signature_verification(self) -> None:
        secret = "cs-webhook-secret-2026"
        payload = json.dumps(_crowdstrike_detection()).encode("utf-8")
        valid_sig = _make_hmac(payload, secret)

        assert _verify_signature(payload, valid_sig, secret) is True
        assert _verify_signature(payload, "sha256=" + valid_sig, secret) is True
        assert _verify_signature(payload, "invalid-signature", secret) is False
        assert _verify_signature(payload, "", secret) is False
        # No secret configured -> always passes
        assert _verify_signature(payload, "", "") is True


# ══════════════════════════════════════════════════════════════════════════════
# TestDefenderWebhook
# ══════════════════════════════════════════════════════════════════════════════


class TestDefenderWebhook:
    """Tests for Microsoft Defender alert normalization."""

    def test_normalize_defender_alert(self) -> None:
        payload = _defender_alert()
        event = _normalize_defender(payload)

        assert isinstance(event, NormalizedSecurityEvent)
        assert event.event_id == "da636983279369912129_-123456789"
        assert event.vendor == "defender"
        assert event.event_type == "Malware"
        assert event.severity == "high"
        assert event.title == "Suspicious PowerShell activity"
        assert "T1059.001" in event.mitre_techniques
        assert "T1027" in event.mitre_techniques
        assert event.raw_data == payload

    def test_defender_severity_mapping(self) -> None:
        for raw_sev, expected in _defender_severity_map.items():
            # Defender sends mixed case; the normalizer lowercases
            payload = _defender_alert(severity=raw_sev.capitalize())
            event = _normalize_defender(payload)
            assert event.severity == expected, (
                f"Severity '{raw_sev}' should map to '{expected}', got '{event.severity}'"
            )

    def test_defender_deduplication(self) -> None:
        alert_id = "da-dedup-001"
        assert _is_duplicate(alert_id) is False
        assert _is_duplicate(alert_id) is True

    def test_defender_missing_fields(self) -> None:
        payload = {"alert": {}}
        event = _normalize_defender(payload)

        assert isinstance(event, NormalizedSecurityEvent)
        assert event.vendor == "defender"
        assert event.title == "Defender Alert"
        assert isinstance(event.entities, list)
        assert isinstance(event.mitre_techniques, list)

    def test_defender_entities_extraction(self) -> None:
        payload = _defender_alert(
            devices=[
                {"deviceDnsName": "server-db-01", "deviceId": "d-100"},
                {"deviceDnsName": "server-app-02", "deviceId": "d-101"},
            ],
            evidence=[
                {"entityType": "user", "fileName": "admin_tool.exe"},
                {"entityType": "ip", "ipAddress": "192.168.1.100"},
            ],
        )
        event = _normalize_defender(payload)

        host_entities = [e for e in event.entities if e["type"] == "host"]
        assert len(host_entities) == 2
        hostnames = {e["value"] for e in host_entities}
        assert "server-db-01" in hostnames
        assert "server-app-02" in hostnames

        # Evidence entities
        non_host = [e for e in event.entities if e["type"] != "host"]
        assert len(non_host) == 2
        values = {e["value"] for e in non_host}
        assert "admin_tool.exe" in values
        assert "192.168.1.100" in values


# ══════════════════════════════════════════════════════════════════════════════
# TestWizWebhook
# ══════════════════════════════════════════════════════════════════════════════


class TestWizWebhook:
    """Tests for Wiz issue notification normalization."""

    def test_normalize_wiz_issue(self) -> None:
        payload = _wiz_issue()
        event = _normalize_wiz(payload)

        assert isinstance(event, NormalizedSecurityEvent)
        assert event.event_id == "wiz-issue-abc-123"
        assert event.vendor == "wiz"
        assert event.event_type == "issue.open"
        assert event.severity == "high"
        assert "S3 Bucket Publicly Accessible" in event.title
        assert event.raw_data == payload

    def test_wiz_severity_mapping(self) -> None:
        for raw_sev, expected in _wiz_severity_map.items():
            payload = _wiz_issue(severity=raw_sev)
            event = _normalize_wiz(payload)
            assert event.severity == expected, (
                f"Severity '{raw_sev}' should map to '{expected}', got '{event.severity}'"
            )

    def test_wiz_deduplication(self) -> None:
        issue_id = "wiz-dedup-001"
        assert _is_duplicate(issue_id) is False
        assert _is_duplicate(issue_id) is True

    def test_wiz_cloud_resource_extraction(self) -> None:
        payload = _wiz_issue(
            resource_name="rds-prod-db",
            resource_type="aws_rds_instance",
            cloud_account="production-aws",
        )
        event = _normalize_wiz(payload)

        resource_entities = [
            e for e in event.entities if e["type"] in ("aws_rds_instance", "cloud_resource")
        ]
        assert len(resource_entities) >= 1
        assert any(e["value"] == "rds-prod-db" for e in resource_entities)

        acct_entities = [e for e in event.entities if e["type"] == "cloud_account"]
        assert len(acct_entities) == 1
        assert acct_entities[0]["value"] == "production-aws"

    def test_wiz_missing_fields(self) -> None:
        payload = {"issue": {}}
        event = _normalize_wiz(payload)

        assert isinstance(event, NormalizedSecurityEvent)
        assert event.vendor == "wiz"
        assert event.severity == "medium"  # default from MEDIUM
        assert isinstance(event.entities, list)
        assert isinstance(event.mitre_techniques, list)
        # Should not crash
        assert "Wiz Issue" in event.title
