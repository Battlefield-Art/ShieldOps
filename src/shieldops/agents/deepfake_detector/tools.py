"""Deepfake Detector Agent — Tool functions for synthetic media forensics."""

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
    ArtifactAnalysis,
    AuthenticityClassification,
    AuthenticityVerdict,
    EvidencePackage,
    MediaSubmission,
    MediaType,
    ProvenanceRecord,
)

logger = structlog.get_logger()

# Known GAN generator fingerprints (spectral signatures)
GAN_FINGERPRINTS: dict[str, list[str]] = {
    "stylegan2": [
        "checkerboard_fft",
        "periodic_spectral_peak",
        "fixed_noise_pattern",
        "adaptive_instance_norm_artifact",
    ],
    "stylegan3": [
        "alias_free_artifact",
        "rotation_equivariance_trace",
        "fourier_feature_residual",
    ],
    "progan": [
        "progressive_resolution_seam",
        "upsampling_artifact",
        "minibatch_stddev_trace",
    ],
    "deepfacelab": [
        "face_boundary_blend",
        "color_transfer_artifact",
        "mask_edge_artifact",
        "temporal_flicker",
    ],
    "faceswap": [
        "encoder_decoder_seam",
        "skin_tone_mismatch",
        "eye_gaze_inconsistency",
    ],
}

# Diffusion model artifact signatures
DIFFUSION_ARTIFACTS: dict[str, list[str]] = {
    "stable_diffusion": [
        "vae_decoder_blur",
        "high_freq_loss",
        "text_encoder_artifact",
        "latent_grid_pattern",
    ],
    "dall_e": [
        "clip_guided_artifact",
        "discrete_vae_block",
        "token_boundary_seam",
    ],
    "midjourney": [
        "upscale_artifact",
        "style_transfer_residual",
        "composition_blend_edge",
    ],
    "imagen": [
        "cascaded_diffusion_seam",
        "super_resolution_artifact",
    ],
}

# Audio deepfake indicators
AUDIO_DEEPFAKE_INDICATORS: list[str] = [
    "vocoder_buzz",
    "unnatural_formant_transition",
    "prosody_monotone",
    "breathing_absence",
    "spectral_gap",
    "phase_discontinuity",
    "mel_spectrogram_artifact",
    "waveform_clipping",
    "silence_pattern_anomaly",
    "pitch_contour_break",
]

# Text generation indicators
TEXT_GENERATION_INDICATORS: list[str] = [
    "low_perplexity_uniformity",
    "repetition_pattern",
    "token_probability_spike",
    "watermark_pattern_detected",
    "burstiness_anomaly",
    "vocabulary_distribution_skew",
    "sentence_length_uniformity",
    "semantic_coherence_break",
]

# C2PA (Coalition for Content Provenance and Authenticity) action types
C2PA_ACTIONS: list[str] = [
    "c2pa.created",
    "c2pa.edited",
    "c2pa.cropped",
    "c2pa.resized",
    "c2pa.filtered",
    "c2pa.published",
    "c2pa.transcoded",
    "c2pa.color_adjusted",
    "c2pa.placed",
    "c2pa.drawing",
]

# Known AI generation tool EXIF signatures
AI_TOOL_EXIF_SIGNATURES: dict[str, str] = {
    "DALL-E": "dall_e",
    "Midjourney": "midjourney",
    "Stable Diffusion": "stable_diffusion",
    "Adobe Firefly": "adobe_firefly",
    "Imagen": "imagen",
    "StabilityAI": "stability_ai",
    "ElevenLabs": "elevenlabs",
    "Synthesia": "synthesia",
    "HeyGen": "heygen",
    "Runway": "runway",
    "Pika": "pika",
    "Sora": "sora",
    "Kling": "kling",
}

# MIME type to media type mapping
MIME_TO_MEDIA: dict[str, MediaType] = {
    "image/jpeg": MediaType.IMAGE,
    "image/png": MediaType.IMAGE,
    "image/webp": MediaType.IMAGE,
    "image/tiff": MediaType.IMAGE,
    "image/bmp": MediaType.IMAGE,
    "audio/wav": MediaType.AUDIO,
    "audio/mp3": MediaType.AUDIO,
    "audio/mpeg": MediaType.AUDIO,
    "audio/ogg": MediaType.AUDIO,
    "audio/flac": MediaType.AUDIO,
    "video/mp4": MediaType.VIDEO,
    "video/webm": MediaType.VIDEO,
    "video/avi": MediaType.VIDEO,
    "video/quicktime": MediaType.VIDEO,
    "text/plain": MediaType.TEXT,
    "text/html": MediaType.TEXT,
    "application/pdf": MediaType.DOCUMENT,
}

# Frequency domain anomaly thresholds
FREQUENCY_THRESHOLDS: dict[str, float] = {
    "fft_peak_ratio": 3.5,
    "spectral_flatness_min": 0.2,
    "checkerboard_energy_max": 0.15,
    "high_freq_energy_ratio": 0.4,
}


def _compute_byte_entropy(data: bytes) -> float:
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


def _simulate_fft_score(data: bytes) -> float:
    """Simulate FFT-based artifact detection score (0-1)."""
    if not data:
        return 0.0
    # Entropy-based proxy: very uniform entropy suggests synthetic
    entropy = _compute_byte_entropy(data)
    if 6.5 < entropy < 7.2:
        return round(0.3 + (entropy - 6.5) * 0.5, 4)
    if entropy >= 7.2:
        return round(min(0.8 + (entropy - 7.2) * 0.5, 1.0), 4)
    return round(max(entropy / 10.0, 0.05), 4)


class DeepfakeDetectorToolkit:
    """Tools for deepfake detection and synthetic media forensics."""

    def __init__(
        self,
        c2pa_client: Any | None = None,
        forensics_client: Any | None = None,
        model_detector_client: Any | None = None,
    ) -> None:
        self._c2pa = c2pa_client
        self._forensics = forensics_client
        self._model_detector = model_detector_client
        self._analysis_cache: dict[str, dict[str, Any]] = {}

    async def ingest_media(
        self,
        tenant_id: str,
        submissions: list[dict[str, Any]],
    ) -> list[MediaSubmission]:
        """Ingest and register media submissions for analysis."""
        logger.info(
            "deepfake_detector.ingest_media",
            tenant_id=tenant_id,
            submission_count=len(submissions),
        )
        results: list[MediaSubmission] = []

        for item in submissions:
            media_id = f"dfd-{uuid.uuid4().hex[:10]}"
            content = item.get("content", b"")
            if isinstance(content, str):
                content = content.encode()

            sha256 = hashlib.sha256(content).hexdigest()
            mime_type = item.get("mime_type", "application/octet-stream")
            media_type = MIME_TO_MEDIA.get(
                mime_type,
                MediaType(item.get("media_type", "image")),
            )

            submission = MediaSubmission(
                id=media_id,
                file_name=item.get("file_name", "unknown"),
                file_size_bytes=len(content),
                media_type=media_type,
                mime_type=mime_type,
                sha256=sha256,
                submitted_by=item.get("submitted_by", tenant_id),
                submitted_at=time.time(),
                source_url=item.get("source_url", ""),
                metadata=item.get("metadata", {}),
            )
            results.append(submission)

            self._analysis_cache[media_id] = {
                "content": content,
                "submission": submission.model_dump(),
            }

        return results

    async def analyze_artifacts(
        self,
        submissions: list[MediaSubmission],
    ) -> list[ArtifactAnalysis]:
        """Run forensic artifact analysis on each media item."""
        logger.info(
            "deepfake_detector.analyze_artifacts",
            count=len(submissions),
        )
        results: list[ArtifactAnalysis] = []

        for sub in submissions:
            cached = self._analysis_cache.get(sub.id, {})
            content = cached.get("content", b"")

            compression = self._detect_compression_anomalies(content, sub.media_type)
            frequency = self._detect_frequency_anomalies(content, sub.media_type)
            noise = self._detect_noise_inconsistencies(content, sub.media_type)
            lighting = self._detect_lighting_inconsistencies(content, sub.media_type)
            temporal = self._detect_temporal_anomalies(content, sub.media_type)
            spectral = self._detect_spectral_anomalies(content, sub.media_type)
            gan_fps = self._detect_gan_fingerprints(content, sub.media_type)
            diffusion = self._detect_diffusion_artifacts(content, sub.media_type)
            face_score = self._compute_facial_landmarks_score(content, sub.media_type)
            lip_score = self._compute_lip_sync_score(content, sub.media_type)

            # External forensics engine if available
            if self._forensics:
                try:
                    ext_result = await self._forensics.analyze(
                        content,
                        sub.media_type.value,
                    )
                    gan_fps.extend(ext_result.get("gan_fingerprints", []))
                    diffusion.extend(ext_result.get("diffusion_artifacts", []))
                except Exception:
                    logger.debug("deepfake_detector.forensics_fallback")

            # Compute aggregate artifact score
            total_indicators = (
                len(compression)
                + len(frequency)
                + len(noise)
                + len(lighting)
                + len(temporal)
                + len(spectral)
                + len(gan_fps)
                + len(diffusion)
            )
            fft_score = _simulate_fft_score(content)
            artifact_score = min(
                (total_indicators * 0.08) + fft_score * 0.3,
                1.0,
            )

            analysis = ArtifactAnalysis(
                media_id=sub.id,
                media_type=sub.media_type,
                compression_anomalies=compression[:10],
                frequency_anomalies=frequency[:10],
                noise_inconsistencies=noise[:10],
                lighting_inconsistencies=lighting[:10],
                temporal_anomalies=temporal[:10],
                spectral_anomalies=spectral[:10],
                gan_fingerprints=gan_fps[:10],
                diffusion_artifacts=diffusion[:10],
                facial_landmarks_score=face_score,
                lip_sync_score=lip_score,
                artifact_score=round(artifact_score, 4),
            )
            results.append(analysis)

            if sub.id in self._analysis_cache:
                self._analysis_cache[sub.id]["artifacts"] = analysis.model_dump()

        return results

    async def check_provenance(
        self,
        submissions: list[MediaSubmission],
    ) -> list[ProvenanceRecord]:
        """Verify C2PA provenance and EXIF metadata for each media item."""
        logger.info(
            "deepfake_detector.check_provenance",
            count=len(submissions),
        )
        results: list[ProvenanceRecord] = []

        for sub in submissions:
            cached = self._analysis_cache.get(sub.id, {})
            content = cached.get("content", b"")

            has_c2pa, c2pa_data = self._check_c2pa_manifest(content)
            exif_intact, exif_sigs = self._check_exif(content)
            tool = self._identify_creation_tool(content, exif_sigs)
            history = self._extract_modification_history(content)
            anchors = self._check_blockchain_anchors(content)

            # External C2PA client if available
            if self._c2pa:
                try:
                    ext = await self._c2pa.verify(content)
                    has_c2pa = ext.get("has_manifest", has_c2pa)
                    c2pa_data.update(ext.get("manifest", {}))
                except Exception:
                    logger.debug("deepfake_detector.c2pa_fallback")

            # Provenance score: higher = more trustworthy provenance
            prov_score = 0.0
            if has_c2pa and c2pa_data.get("valid_signature", False):
                prov_score += 0.5
            if exif_intact:
                prov_score += 0.2
            if tool and tool not in AI_TOOL_EXIF_SIGNATURES:
                prov_score += 0.15
            if anchors:
                prov_score += 0.15
            # Penalize if AI tool detected in EXIF
            if tool and any(sig.lower() in tool.lower() for sig in AI_TOOL_EXIF_SIGNATURES):
                prov_score = max(prov_score - 0.3, 0.0)

            record = ProvenanceRecord(
                media_id=sub.id,
                has_c2pa_manifest=has_c2pa,
                c2pa_issuer=c2pa_data.get("issuer", ""),
                c2pa_claim_generator=c2pa_data.get("claim_generator", ""),
                c2pa_actions=c2pa_data.get("actions", []),
                c2pa_valid_signature=c2pa_data.get("valid_signature", False),
                exif_intact=exif_intact,
                exif_tool_signatures=exif_sigs[:10],
                creation_tool=tool,
                modification_history=history[:10],
                blockchain_anchors=anchors[:5],
                provenance_score=round(prov_score, 4),
            )
            results.append(record)

            if sub.id in self._analysis_cache:
                self._analysis_cache[sub.id]["provenance"] = record.model_dump()

        return results

    async def classify_authenticity(
        self,
        submissions: list[MediaSubmission],
        artifacts: list[ArtifactAnalysis],
        provenance: list[ProvenanceRecord],
    ) -> list[AuthenticityClassification]:
        """Classify media authenticity using combined artifact + provenance signals."""
        logger.info(
            "deepfake_detector.classify_authenticity",
            count=len(submissions),
        )
        artifact_map = {a.media_id: a for a in artifacts}
        prov_map = {p.media_id: p for p in provenance}
        results: list[AuthenticityClassification] = []

        for sub in submissions:
            art = artifact_map.get(sub.id)
            prov = prov_map.get(sub.id)

            verdict, confidence, combined = self._rule_based_classify(art, prov)
            manip_techniques = self._identify_manipulation_techniques(art)
            gen_model = self._guess_generation_model(art)
            risk = self._compute_risk_score(verdict, confidence, art)

            classification = AuthenticityClassification(
                media_id=sub.id,
                verdict=verdict,
                confidence_score=round(confidence, 4),
                artifact_score=round(art.artifact_score if art else 0.0, 4),
                provenance_score=round(prov.provenance_score if prov else 0.0, 4),
                combined_score=round(combined, 4),
                generation_model_guess=gen_model,
                manipulation_techniques=manip_techniques[:10],
                risk_score=round(risk, 1),
                llm_reasoning="",
            )
            results.append(classification)

        return results

    async def generate_evidence(
        self,
        submissions: list[MediaSubmission],
        classifications: list[AuthenticityClassification],
        artifacts: list[ArtifactAnalysis],
    ) -> list[EvidencePackage]:
        """Generate forensic evidence packages for flagged media."""
        logger.info(
            "deepfake_detector.generate_evidence",
            count=len(submissions),
        )
        class_map = {c.media_id: c for c in classifications}
        art_map = {a.media_id: a for a in artifacts}
        results: list[EvidencePackage] = []

        for sub in submissions:
            cls = class_map.get(sub.id)
            art = art_map.get(sub.id)
            if not cls:
                continue

            indicators: list[str] = []
            if art:
                indicators.extend([f"gan:{fp}" for fp in art.gan_fingerprints[:3]])
                indicators.extend([f"diffusion:{da}" for da in art.diffusion_artifacts[:3]])
                indicators.extend([f"compression:{ca}" for ca in art.compression_anomalies[:2]])
                indicators.extend([f"frequency:{fa}" for fa in art.frequency_anomalies[:2]])

            if cls.manipulation_techniques:
                indicators.extend([f"technique:{t}" for t in cls.manipulation_techniques[:3]])

            forensic_hashes = [
                f"sha256:{sub.sha256}",
                f"evidence_id:{uuid.uuid4().hex[:12]}",
            ]

            chain_of_custody = [
                f"submitted_by:{sub.submitted_by}",
                f"submitted_at:{sub.submitted_at}",
                f"analyzed_at:{time.time():.0f}",
                f"verdict:{cls.verdict.value}",
                f"confidence:{cls.confidence_score:.2f}",
            ]

            evidence = EvidencePackage(
                media_id=sub.id,
                evidence_id=f"ev-{uuid.uuid4().hex[:10]}",
                summary=(
                    f"{sub.file_name}: {cls.verdict.value} (confidence={cls.confidence_score:.1%})"
                ),
                key_indicators=indicators[:15],
                forensic_hashes=forensic_hashes,
                chain_of_custody=chain_of_custody,
                exportable=True,
            )
            results.append(evidence)

        return results

    # ----------------------------------------------------------
    # Private helpers — Artifact detection
    # ----------------------------------------------------------

    @staticmethod
    def _detect_compression_anomalies(
        content: bytes,
        media_type: MediaType,
    ) -> list[str]:
        """Detect compression-level anomalies."""
        anomalies: list[str] = []
        if not content:
            return anomalies
        if media_type in (MediaType.IMAGE, MediaType.VIDEO):
            # JPEG double-compression detection proxy
            jpeg_markers = content.count(b"\xff\xd8")
            if jpeg_markers > 1:
                anomalies.append("double_jpeg_compression")
            # Quantization table anomaly proxy
            if content.count(b"\xff\xdb") > 2:
                anomalies.append("multiple_quantization_tables")
            entropy = _compute_byte_entropy(content)
            if 7.0 < entropy < 7.5:
                anomalies.append("suspicious_entropy_range")
        return anomalies

    @staticmethod
    def _detect_frequency_anomalies(
        content: bytes,
        media_type: MediaType,
    ) -> list[str]:
        """Detect frequency-domain anomalies (FFT-based proxy)."""
        anomalies: list[str] = []
        if not content:
            return anomalies
        if media_type in (MediaType.IMAGE, MediaType.VIDEO):
            fft_score = _simulate_fft_score(content)
            if fft_score > FREQUENCY_THRESHOLDS["checkerboard_energy_max"]:
                anomalies.append("checkerboard_pattern_detected")
            if fft_score > FREQUENCY_THRESHOLDS["high_freq_energy_ratio"]:
                anomalies.append("high_frequency_energy_anomaly")
            # Periodic peak detection proxy
            block_size = max(len(content) // 16, 1)
            block_entropies = []
            for i in range(0, min(len(content), block_size * 16), block_size):
                block_entropies.append(_compute_byte_entropy(content[i : i + block_size]))
            if block_entropies:
                mean_e = sum(block_entropies) / len(block_entropies)
                variance = sum((e - mean_e) ** 2 for e in block_entropies) / len(block_entropies)
                if variance < 0.01 and mean_e > 6.0:
                    anomalies.append("uniform_block_entropy_synthetic")
        return anomalies

    @staticmethod
    def _detect_noise_inconsistencies(
        content: bytes,
        media_type: MediaType,
    ) -> list[str]:
        """Detect noise-level inconsistencies across regions."""
        anomalies: list[str] = []
        if not content or media_type not in (MediaType.IMAGE, MediaType.VIDEO):
            return anomalies
        # Quadrant noise analysis proxy
        quarter = max(len(content) // 4, 1)
        entropies = [
            _compute_byte_entropy(content[i * quarter : (i + 1) * quarter]) for i in range(4)
        ]
        if entropies:
            spread = max(entropies) - min(entropies)
            if spread > 1.0:
                anomalies.append("regional_noise_inconsistency")
            if spread < 0.05 and all(e > 7.0 for e in entropies):
                anomalies.append("unnaturally_uniform_noise")
        return anomalies

    @staticmethod
    def _detect_lighting_inconsistencies(
        content: bytes,
        media_type: MediaType,
    ) -> list[str]:
        """Detect lighting/shadow inconsistencies."""
        anomalies: list[str] = []
        if not content or media_type not in (MediaType.IMAGE, MediaType.VIDEO):
            return anomalies
        # Simplified luminance gradient proxy
        if len(content) > 100:
            low_bytes = sum(1 for b in content[: len(content) // 2] if b < 64)
            high_bytes = sum(1 for b in content[len(content) // 2 :] if b < 64)
            total = max(len(content) // 2, 1)
            ratio = abs(low_bytes - high_bytes) / total
            if ratio > 0.3:
                anomalies.append("luminance_gradient_discontinuity")
        return anomalies

    @staticmethod
    def _detect_temporal_anomalies(
        content: bytes,
        media_type: MediaType,
    ) -> list[str]:
        """Detect temporal anomalies in video/audio."""
        anomalies: list[str] = []
        if media_type == MediaType.VIDEO:
            if content:
                # Frame boundary proxy
                frame_markers = content.count(b"\x00\x00\x01")
                if frame_markers > 0 and frame_markers < 5:
                    anomalies.append("low_frame_count_suspicious")
                anomalies.append("temporal_coherence_check_required")
        elif media_type == MediaType.AUDIO and content:
            anomalies.append("audio_temporal_analysis_required")
        return anomalies

    @staticmethod
    def _detect_spectral_anomalies(
        content: bytes,
        media_type: MediaType,
    ) -> list[str]:
        """Detect spectral anomalies in audio content."""
        anomalies: list[str] = []
        if media_type != MediaType.AUDIO or not content:
            return anomalies
        entropy = _compute_byte_entropy(content)
        if entropy > 7.5:
            anomalies.append("high_spectral_entropy")
        # Check for vocoder artifacts (repeating patterns)
        chunk = min(len(content), 4096)
        if content[:chunk] == content[chunk : chunk * 2]:
            anomalies.append("repeating_spectral_block")
        return anomalies

    def _detect_gan_fingerprints(
        self,
        content: bytes,
        media_type: MediaType,
    ) -> list[str]:
        """Detect GAN generator fingerprints."""
        fingerprints: list[str] = []
        if not content or media_type not in (MediaType.IMAGE, MediaType.VIDEO):
            return fingerprints

        # Model detector client if available
        if self._model_detector:
            try:
                result = self._model_detector.detect_gan(content)
                return result.get("fingerprints", [])
            except Exception:
                logger.debug("deepfake_detector.model_detector_fallback")

        # Heuristic: entropy + structure based proxy
        entropy = _compute_byte_entropy(content)
        fft_score = _simulate_fft_score(content)

        if fft_score > 0.5:
            fingerprints.append("checkerboard_fft")
        if entropy > 7.0 and fft_score > 0.3:
            fingerprints.append("periodic_spectral_peak")
        if 6.8 < entropy < 7.3:
            fingerprints.append("fixed_noise_pattern")

        return fingerprints

    def _detect_diffusion_artifacts(
        self,
        content: bytes,
        media_type: MediaType,
    ) -> list[str]:
        """Detect diffusion model artifacts."""
        artifacts: list[str] = []
        if not content or media_type not in (MediaType.IMAGE, MediaType.VIDEO):
            return artifacts

        # Model detector client if available
        if self._model_detector:
            try:
                result = self._model_detector.detect_diffusion(content)
                return result.get("artifacts", [])
            except Exception:
                logger.debug("deepfake_detector.model_detector_fallback")

        entropy = _compute_byte_entropy(content)
        if entropy > 7.2:
            artifacts.append("high_freq_loss")
        if len(content) > 1024:
            # Check for latent grid pattern proxy
            block = 64
            blocks = [
                content[i : i + block] for i in range(0, min(len(content), block * 16), block)
            ]
            if len(blocks) > 4:
                similarities = sum(1 for i in range(len(blocks) - 1) if blocks[i] == blocks[i + 1])
                if similarities > len(blocks) // 4:
                    artifacts.append("latent_grid_pattern")

        return artifacts

    @staticmethod
    def _compute_facial_landmarks_score(
        content: bytes,
        media_type: MediaType,
    ) -> float:
        """Compute facial landmark consistency score (0=synthetic, 1=authentic)."""
        if media_type not in (MediaType.IMAGE, MediaType.VIDEO) or not content:
            return 0.5
        # Proxy: higher entropy in face region suggests manipulation
        face_region = content[: len(content) // 3]
        entropy = _compute_byte_entropy(face_region)
        return round(max(1.0 - (entropy / 8.0), 0.0), 4)

    @staticmethod
    def _compute_lip_sync_score(
        content: bytes,
        media_type: MediaType,
    ) -> float:
        """Compute lip-sync consistency score for video (0=mismatch, 1=matched)."""
        if media_type != MediaType.VIDEO or not content:
            return 0.5
        # Proxy score based on content characteristics
        entropy = _compute_byte_entropy(content)
        return round(max(1.0 - (entropy / 9.0), 0.1), 4)

    # ----------------------------------------------------------
    # Private helpers — Provenance
    # ----------------------------------------------------------

    @staticmethod
    def _check_c2pa_manifest(
        content: bytes,
    ) -> tuple[bool, dict[str, Any]]:
        """Check for C2PA content credentials manifest."""
        if not content:
            return False, {}
        # C2PA manifests use JUMBF (ISO 19566-5) boxes
        # Magic bytes: "jumb" in JPEG/PNG
        has_jumbf = b"jumb" in content or b"c2pa" in content
        if has_jumbf:
            return True, {
                "issuer": "detected_issuer",
                "claim_generator": "detected_generator",
                "actions": ["c2pa.created"],
                "valid_signature": True,
            }
        return False, {}

    @staticmethod
    def _check_exif(
        content: bytes,
    ) -> tuple[bool, list[str]]:
        """Check EXIF metadata integrity."""
        if not content:
            return False, []
        signatures: list[str] = []
        # Check for EXIF header (JPEG)
        has_exif = b"Exif" in content[:1024]
        # Check for known tool signatures
        content_str = content[:4096].decode("ascii", errors="ignore")
        for tool_name in AI_TOOL_EXIF_SIGNATURES:
            if tool_name.lower() in content_str.lower():
                signatures.append(tool_name)
        return has_exif, signatures

    @staticmethod
    def _identify_creation_tool(
        content: bytes,
        exif_sigs: list[str],
    ) -> str:
        """Identify the creation tool from metadata."""
        if exif_sigs:
            return exif_sigs[0]
        if not content:
            return ""
        # Check for software tag in content
        content_str = content[:4096].decode("ascii", errors="ignore")
        software_match = re.search(
            r"(?:Software|Creator|Producer)[:\s]+([^\x00\n]{3,40})",
            content_str,
        )
        if software_match:
            return software_match.group(1).strip()
        return ""

    @staticmethod
    def _extract_modification_history(
        content: bytes,
    ) -> list[str]:
        """Extract modification history from metadata."""
        history: list[str] = []
        if not content:
            return history
        content_str = content[:8192].decode("ascii", errors="ignore")
        # XMP history extraction proxy
        if "xmp" in content_str.lower() or "photoshop" in content_str.lower():
            history.append("xmp_metadata_present")
        if "save" in content_str.lower():
            history.append("multiple_save_operations")
        return history

    @staticmethod
    def _check_blockchain_anchors(
        content: bytes,
    ) -> list[str]:
        """Check for blockchain-based provenance anchors."""
        # In production, this would query blockchain registries
        return []

    # ----------------------------------------------------------
    # Private helpers — Classification
    # ----------------------------------------------------------

    def _rule_based_classify(
        self,
        artifact: ArtifactAnalysis | None,
        provenance: ProvenanceRecord | None,
    ) -> tuple[AuthenticityVerdict, float, float]:
        """Rule-based authenticity classification."""
        art_score = artifact.artifact_score if artifact else 0.0
        prov_score = provenance.provenance_score if provenance else 0.0

        # Combined score: artifact score pushes toward synthetic,
        # provenance pushes toward authentic
        combined = art_score * 0.7 - prov_score * 0.3 + 0.3

        # Boost for GAN/diffusion detections
        if artifact:
            if artifact.gan_fingerprints:
                combined += 0.15
            if artifact.diffusion_artifacts:
                combined += 0.15
            if artifact.facial_landmarks_score < 0.3:
                combined += 0.1
            if artifact.lip_sync_score < 0.3:
                combined += 0.05

        # Reduce for strong provenance
        if provenance:
            if provenance.has_c2pa_manifest and provenance.c2pa_valid_signature:
                combined -= 0.3
            if provenance.exif_intact and not any(
                sig in AI_TOOL_EXIF_SIGNATURES for sig in provenance.exif_tool_signatures
            ):
                combined -= 0.1

        combined = max(min(combined, 1.0), 0.0)

        # Map combined score to verdict
        if combined >= 0.8:
            verdict = AuthenticityVerdict.SYNTHETIC
            confidence = min(0.7 + combined * 0.3, 0.99)
        elif combined >= 0.6:
            verdict = AuthenticityVerdict.LIKELY_SYNTHETIC
            confidence = 0.6 + (combined - 0.6) * 0.5
        elif combined >= 0.4:
            verdict = AuthenticityVerdict.UNCERTAIN
            confidence = 0.4 + abs(combined - 0.5) * 0.4
        elif combined >= 0.2:
            verdict = AuthenticityVerdict.LIKELY_AUTHENTIC
            confidence = 0.6 + (0.4 - combined) * 0.5
        else:
            verdict = AuthenticityVerdict.AUTHENTIC
            confidence = min(0.7 + (0.2 - combined) * 1.5, 0.99)

        return verdict, round(confidence, 4), round(combined, 4)

    @staticmethod
    def _identify_manipulation_techniques(
        artifact: ArtifactAnalysis | None,
    ) -> list[str]:
        """Identify specific manipulation techniques from artifacts."""
        techniques: list[str] = []
        if not artifact:
            return techniques
        if artifact.gan_fingerprints:
            techniques.append("gan_generation")
            # Identify specific GAN
            for gen, fps in GAN_FINGERPRINTS.items():
                if any(fp in artifact.gan_fingerprints for fp in fps):
                    techniques.append(f"gan:{gen}")
                    break
        if artifact.diffusion_artifacts:
            techniques.append("diffusion_generation")
            for gen, arts in DIFFUSION_ARTIFACTS.items():
                if any(a in artifact.diffusion_artifacts for a in arts):
                    techniques.append(f"diffusion:{gen}")
                    break
        if artifact.noise_inconsistencies:
            techniques.append("region_splicing")
        if artifact.lighting_inconsistencies:
            techniques.append("composite_manipulation")
        if artifact.temporal_anomalies:
            techniques.append("temporal_manipulation")
        if artifact.spectral_anomalies:
            techniques.append("audio_synthesis")
        return techniques

    @staticmethod
    def _guess_generation_model(
        artifact: ArtifactAnalysis | None,
    ) -> str:
        """Guess the generation model from artifact signatures."""
        if not artifact:
            return ""
        for gen, fps in GAN_FINGERPRINTS.items():
            if any(fp in artifact.gan_fingerprints for fp in fps):
                return gen
        for gen, arts in DIFFUSION_ARTIFACTS.items():
            if any(a in artifact.diffusion_artifacts for a in arts):
                return gen
        if artifact.spectral_anomalies:
            return "audio_vocoder"
        return ""

    @staticmethod
    def _compute_risk_score(
        verdict: AuthenticityVerdict,
        confidence: float,
        artifact: ArtifactAnalysis | None,
    ) -> float:
        """Compute a 0-100 risk score."""
        base_scores = {
            AuthenticityVerdict.SYNTHETIC: 90,
            AuthenticityVerdict.LIKELY_SYNTHETIC: 70,
            AuthenticityVerdict.UNCERTAIN: 45,
            AuthenticityVerdict.LIKELY_AUTHENTIC: 20,
            AuthenticityVerdict.AUTHENTIC: 5,
        }
        base = base_scores.get(verdict, 45)
        if artifact:
            if artifact.gan_fingerprints:
                base = min(base + 5, 100)
            if artifact.diffusion_artifacts:
                base = min(base + 5, 100)
        return round(base * max(confidence, 0.5), 1)
