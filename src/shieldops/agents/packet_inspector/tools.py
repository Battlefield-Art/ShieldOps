"""Packet Inspector Agent — Tool functions for deep packet inspection."""

from __future__ import annotations

import hashlib
import math
import re
import time
import uuid
from collections import Counter
from typing import Any

import structlog

from .models import (
    PacketCapture,
    PayloadAnalysis,
    PayloadRisk,
    ThreatDetection,
    TLSCertCheck,
    TLSStatus,
)

logger = structlog.get_logger()

# Suspicious payload patterns
SUSPICIOUS_PATTERNS: dict[str, str] = {
    r"(?i)(select|union|insert|drop|delete)\s.*(from|into|table)": "sql_injection",
    r"(?i)(cmd\.exe|/bin/sh|/bin/bash|powershell)": "shell_command",
    r"(?i)(eval\(|exec\(|system\()": "code_execution",
    r"(?i)(<script|javascript:|onerror=|onload=)": "xss_payload",
    r"(?i)(\.\.\/|\.\.\\|%2e%2e)": "path_traversal",
    r"(?i)(password|passwd|credential|secret)=": "credential_leak",
    r"(?i)(base64_decode|frombase64|atob\()": "encoded_payload",
    r"(?i)(wget |curl |nc -e|ncat )": "remote_download",
}

# Known C2 port patterns
C2_PORTS: set[int] = {
    4444,
    5555,
    8443,
    8080,
    1337,
    31337,
    6667,
    6697,
    9001,
    9030,
    9050,
    9051,
    53,
    443,
    80,
}

# Weak TLS cipher suites
WEAK_CIPHERS: set[str] = {
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_DES_CBC_SHA",
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_RSA_WITH_NULL_MD5",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
}

# Deprecated TLS versions
DEPRECATED_TLS: set[str] = {"SSLv3", "TLSv1.0", "TLSv1.1"}

# Known malware JA3 fingerprints (simplified)
KNOWN_MALWARE_JA3: set[str] = {
    "51c64c77e60f3980eea90869b68c58a8",
    "e7d705a3286e19ea42f587b344ee6865",
    "6734f37431670b3ab4292b8f60f29984",
    "3b5074b1b5d032e5620f69f9f700ff0e",
    "72a589da586844d7f0818ce684948eea",
}

# MITRE ATT&CK technique mapping for network threats
MITRE_NETWORK_MAP: dict[str, list[str]] = {
    "c2_beacon": ["T1071", "T1071.001"],
    "dns_tunnel": ["T1071.004", "T1048.003"],
    "data_exfil": ["T1048", "T1048.002"],
    "lateral_movement": ["T1021", "T1021.002"],
    "exploitation": ["T1190", "T1203"],
    "credential_theft": ["T1557", "T1040"],
    "protocol_abuse": ["T1572", "T1090"],
    "encrypted_channel": ["T1573", "T1573.002"],
}

# IP and domain extraction patterns
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def _compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of byte data."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _compute_ja3(
    tls_version: str,
    cipher_suite: str,
) -> str:
    """Compute a simplified JA3 fingerprint."""
    raw = f"{tls_version},{cipher_suite}"
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()


class PacketInspectorToolkit:
    """Tools for deep packet inspection and analysis."""

    def __init__(
        self,
        pcap_client: Any | None = None,
        tls_client: Any | None = None,
        threat_feed_client: Any | None = None,
    ) -> None:
        self._pcap = pcap_client
        self._tls = tls_client
        self._threat_feed = threat_feed_client
        self._inspection_cache: dict[str, dict[str, Any]] = {}

    async def capture_packets(
        self,
        tenant_id: str,
        packets: list[dict[str, Any]],
    ) -> list[PacketCapture]:
        """Ingest and register packets for inspection."""
        logger.info(
            "packet_inspector.capture_packets",
            tenant_id=tenant_id,
            packet_count=len(packets),
        )
        results: list[PacketCapture] = []

        for pkt_data in packets:
            pkt_id = str(uuid.uuid4())[:12]
            raw = pkt_data.get("raw_hex", "")
            raw_bytes = bytes.fromhex(raw) if raw else b""

            capture = PacketCapture(
                id=pkt_id,
                src_ip=pkt_data.get(
                    "src_ip",
                    "0.0.0.0",  # noqa: S104  # nosec B104
                ),
                dst_ip=pkt_data.get(
                    "dst_ip",
                    "0.0.0.0",  # noqa: S104  # nosec B104
                ),
                src_port=pkt_data.get("src_port", 0),
                dst_port=pkt_data.get("dst_port", 0),
                protocol=pkt_data.get("protocol", "TCP"),
                payload_size_bytes=len(raw_bytes),
                timestamp=pkt_data.get("timestamp", time.time()),
                direction=pkt_data.get("direction", "inbound"),
                interface=pkt_data.get("interface", "eth0"),
                flags=pkt_data.get("flags", []),
                raw_hex=raw,
            )
            results.append(capture)
            self._inspection_cache[pkt_id] = {
                "raw": raw_bytes,
                "capture": capture.model_dump(),
            }

        return results

    async def analyze_payloads(
        self,
        packets: list[PacketCapture],
    ) -> list[PayloadAnalysis]:
        """Analyze packet payloads for threats."""
        logger.info(
            "packet_inspector.analyze_payloads",
            packet_count=len(packets),
        )
        results: list[PayloadAnalysis] = []

        for pkt in packets:
            cached = self._inspection_cache.get(pkt.id, {})
            raw = cached.get("raw", b"")

            # Compute payload entropy
            entropy = _compute_entropy(raw)

            # Decode protocol
            protocol = self._decode_protocol(pkt.protocol, pkt.dst_port, raw)

            # Extract printable strings
            strings = self._extract_strings(raw)

            # Match suspicious patterns
            all_text = " ".join(strings)
            suspicious: list[str] = []
            signatures: list[str] = []
            for pattern, name in SUSPICIOUS_PATTERNS.items():
                if re.search(pattern, all_text):
                    suspicious.append(name)
                    signatures.append(f"sig:{name}")

            # Content type detection
            content_type = self._detect_content_type(raw)

            # Encryption detection
            is_encrypted = entropy > 7.2 or pkt.dst_port == 443

            # Risk scoring
            risk, risk_score = self._score_payload_risk(entropy, suspicious, pkt, is_encrypted)

            analysis = PayloadAnalysis(
                packet_id=pkt.id,
                protocol_decoded=protocol,
                content_type=content_type,
                payload_entropy=entropy,
                is_encrypted=is_encrypted,
                suspicious_patterns=suspicious[:20],
                extracted_strings=strings[:30],
                matched_signatures=signatures[:20],
                risk=risk,
                risk_score=risk_score,
                llm_reasoning="",
            )
            results.append(analysis)

            if pkt.id in self._inspection_cache:
                self._inspection_cache[pkt.id]["payload"] = analysis.model_dump()

        return results

    async def validate_tls(
        self,
        packets: list[PacketCapture],
    ) -> list[TLSCertCheck]:
        """Validate TLS certificates and cipher suites."""
        logger.info(
            "packet_inspector.validate_tls",
            packet_count=len(packets),
        )
        results: list[TLSCertCheck] = []

        for pkt in packets:
            if pkt.dst_port not in (443, 8443, 993, 995, 465):
                continue

            cached = self._inspection_cache.get(pkt.id, {})
            raw = cached.get("raw", b"")

            # Extract TLS metadata (simulated)
            tls_meta = self._extract_tls_metadata(pkt, raw)

            # Compute JA3
            ja3 = _compute_ja3(
                tls_meta["tls_version"],
                tls_meta["cipher_suite"],
            )

            # Determine TLS status
            status = self._evaluate_tls_status(tls_meta)

            check = TLSCertCheck(
                packet_id=pkt.id,
                server_name=tls_meta.get("server_name", pkt.dst_ip),
                issuer=tls_meta.get("issuer", ""),
                subject=tls_meta.get("subject", ""),
                not_before=tls_meta.get("not_before", ""),
                not_after=tls_meta.get("not_after", ""),
                serial_number=tls_meta.get("serial_number", ""),
                cipher_suite=tls_meta["cipher_suite"],
                tls_version=tls_meta["tls_version"],
                status=status,
                chain_valid=tls_meta.get("chain_valid", True),
                pinning_match=tls_meta.get("pinning_match", True),
                ja3_fingerprint=ja3,
                ja3s_fingerprint=tls_meta.get("ja3s", ""),
            )
            results.append(check)

            if pkt.id in self._inspection_cache:
                self._inspection_cache[pkt.id]["tls"] = check.model_dump()

        return results

    async def detect_threats(
        self,
        packets: list[PacketCapture],
        analyses: list[PayloadAnalysis],
        tls_checks: list[TLSCertCheck],
    ) -> list[ThreatDetection]:
        """Detect threats from combined analysis."""
        logger.info(
            "packet_inspector.detect_threats",
            packet_count=len(packets),
        )
        analysis_map = {a.packet_id: a for a in analyses}
        tls_map = {t.packet_id: t for t in tls_checks}
        results: list[ThreatDetection] = []

        for pkt in packets:
            analysis = analysis_map.get(pkt.id)
            tls = tls_map.get(pkt.id)

            threats = self._rule_based_detect(pkt, analysis, tls)
            results.extend(threats)

        return results

    # ----------------------------------------------------------
    # Private helpers
    # ----------------------------------------------------------

    @staticmethod
    def _extract_strings(content: bytes, min_len: int = 4) -> list[str]:
        """Extract printable ASCII strings."""
        if not content:
            return []
        pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
        return [m.decode("ascii", errors="ignore") for m in pattern.findall(content)]

    @staticmethod
    def _decode_protocol(
        protocol: str,
        dst_port: int,
        raw: bytes,
    ) -> str:
        """Decode application-layer protocol."""
        if raw[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD"):
            return "HTTP"
        if raw[:3] == b"TLS" or dst_port == 443:
            return "TLS"
        if dst_port == 53:
            return "DNS"
        if dst_port == 22:
            return "SSH"
        if dst_port in (25, 465, 587):
            return "SMTP"
        if dst_port in (143, 993):
            return "IMAP"
        if dst_port in (110, 995):
            return "POP3"
        if dst_port == 3306:
            return "MySQL"
        if dst_port == 5432:
            return "PostgreSQL"
        if dst_port == 6379:
            return "Redis"
        return protocol.upper()

    @staticmethod
    def _detect_content_type(raw: bytes) -> str:
        """Detect content type from magic bytes."""
        if not raw:
            return "empty"
        if raw[:2] == b"PK":
            return "application/zip"
        if raw[:4] == b"\x89PNG":
            return "image/png"
        if raw[:3] == b"GIF":
            return "image/gif"
        if raw[:2] == b"\xff\xd8":
            return "image/jpeg"
        if raw[:5] == b"%PDF-":
            return "application/pdf"
        if raw[:2] == b"MZ":
            return "application/x-executable"
        if raw[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD"):
            return "text/http"
        try:
            raw[:64].decode("utf-8")
            return "text/plain"
        except UnicodeDecodeError:
            return "application/octet-stream"

    @staticmethod
    def _score_payload_risk(
        entropy: float,
        suspicious: list[str],
        pkt: PacketCapture,
        is_encrypted: bool,
    ) -> tuple[PayloadRisk, float]:
        """Score payload risk based on indicators."""
        score = 0.0

        # Entropy-based scoring
        if entropy > 7.5:
            score += 0.2
        elif entropy > 7.0:
            score += 0.1

        # Suspicious pattern hits
        score += min(len(suspicious) * 0.15, 0.4)

        # Known C2 ports
        if pkt.dst_port in C2_PORTS:
            score += 0.1

        # Large payload on unusual port
        if pkt.payload_size_bytes > 10000 and pkt.dst_port > 1024:
            score += 0.1

        # Encrypted to non-standard port
        if is_encrypted and pkt.dst_port not in (443, 8443):
            score += 0.15

        score = min(score, 1.0)

        if score >= 0.8:
            risk = PayloadRisk.CRITICAL
        elif score >= 0.6:
            risk = PayloadRisk.HIGH
        elif score >= 0.4:
            risk = PayloadRisk.MEDIUM
        elif score >= 0.2:
            risk = PayloadRisk.LOW
        else:
            risk = PayloadRisk.BENIGN

        return risk, round(score, 4)

    @staticmethod
    def _extract_tls_metadata(
        pkt: PacketCapture,
        raw: bytes,
    ) -> dict[str, Any]:
        """Extract TLS metadata (simulated)."""
        cipher = "TLS_AES_256_GCM_SHA384"
        version = "TLSv1.3"

        # Check for weak patterns in raw data
        if raw and len(raw) > 5:
            if raw[0:1] == b"\x16" and raw[1:3] == b"\x03\x01":
                version = "TLSv1.0"
                cipher = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
            elif raw[1:3] == b"\x03\x02":
                version = "TLSv1.1"
            elif raw[1:3] == b"\x03\x03":
                version = "TLSv1.2"

        return {
            "server_name": pkt.dst_ip,
            "issuer": "CN=Let's Encrypt Authority X3",
            "subject": f"CN={pkt.dst_ip}",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2026-06-01T00:00:00Z",
            "serial_number": hashlib.sha1(pkt.dst_ip.encode(), usedforsecurity=False).hexdigest()[
                :20
            ],
            "cipher_suite": cipher,
            "tls_version": version,
            "chain_valid": version not in DEPRECATED_TLS,
            "pinning_match": True,
            "ja3s": "",
        }

    @staticmethod
    def _evaluate_tls_status(
        meta: dict[str, Any],
    ) -> TLSStatus:
        """Evaluate TLS status from metadata."""
        cipher = meta.get("cipher_suite", "")
        version = meta.get("tls_version", "")

        if cipher in WEAK_CIPHERS:
            return TLSStatus.WEAK_CIPHER
        if version in DEPRECATED_TLS:
            return TLSStatus.WEAK_CIPHER
        if not meta.get("chain_valid", True):
            return TLSStatus.SELF_SIGNED

        return TLSStatus.VALID

    @staticmethod
    def _rule_based_detect(
        pkt: PacketCapture,
        analysis: PayloadAnalysis | None,
        tls: TLSCertCheck | None,
    ) -> list[ThreatDetection]:
        """Rule-based threat detection as LLM fallback."""
        threats: list[ThreatDetection] = []

        if analysis:
            # Suspicious payload patterns
            for pattern in analysis.suspicious_patterns:
                severity = PayloadRisk.HIGH
                technique = ""
                if pattern in ("sql_injection", "xss_payload"):
                    technique = "T1190"
                    severity = PayloadRisk.CRITICAL
                elif pattern in (
                    "shell_command",
                    "code_execution",
                ):
                    technique = "T1059"
                    severity = PayloadRisk.CRITICAL
                elif pattern == "credential_leak":
                    technique = "T1040"
                    severity = PayloadRisk.HIGH
                elif pattern in (
                    "remote_download",
                    "encoded_payload",
                ):
                    technique = "T1071"
                    severity = PayloadRisk.HIGH
                elif pattern == "path_traversal":
                    technique = "T1083"
                    severity = PayloadRisk.MEDIUM

                threats.append(
                    ThreatDetection(
                        packet_id=pkt.id,
                        threat_type=pattern,
                        description=(
                            f"Detected {pattern} in payload"
                            f" from {pkt.src_ip}:{pkt.src_port}"
                            f" to {pkt.dst_ip}:{pkt.dst_port}"
                        ),
                        severity=severity,
                        mitre_technique=technique,
                        confidence=0.75,
                        recommended_action=(f"Block traffic from {pkt.src_ip}"),
                    )
                )

            # High entropy encrypted traffic to C2 ports
            if analysis.is_encrypted and pkt.dst_port in C2_PORTS and pkt.dst_port != 443:
                threats.append(
                    ThreatDetection(
                        packet_id=pkt.id,
                        threat_type="encrypted_c2",
                        description=(f"Encrypted traffic to known C2 port {pkt.dst_port}"),
                        severity=PayloadRisk.HIGH,
                        mitre_technique="T1573",
                        confidence=0.65,
                        recommended_action=("Inspect with TLS interception"),
                    )
                )

        if tls:
            # Weak TLS
            if tls.status == TLSStatus.WEAK_CIPHER:
                threats.append(
                    ThreatDetection(
                        packet_id=pkt.id,
                        threat_type="weak_tls",
                        description=(f"Weak cipher {tls.cipher_suite} on {tls.server_name}"),
                        severity=PayloadRisk.MEDIUM,
                        mitre_technique="T1557",
                        confidence=0.9,
                        recommended_action=("Upgrade to TLS 1.3"),
                    )
                )

            # Known malware JA3
            if tls.ja3_fingerprint in KNOWN_MALWARE_JA3:
                threats.append(
                    ThreatDetection(
                        packet_id=pkt.id,
                        threat_type="malware_ja3",
                        description=(f"JA3 {tls.ja3_fingerprint} matches known malware"),
                        severity=PayloadRisk.CRITICAL,
                        mitre_technique="T1071",
                        confidence=0.85,
                        recommended_action=(f"Block {pkt.src_ip} immediately"),
                    )
                )

        return threats
