"""Deepfake Detector Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class AnalyzeOutput(BaseModel):
    """LLM output for forensic artifact analysis."""

    summary: str = Field(description="Brief summary of forensic artifact findings")
    suspicion_level: str = Field(description="Overall suspicion: high, medium, low")
    detected_artifacts: list[str] = Field(description="Key synthetic artifacts detected")
    generation_model_hints: list[str] = Field(
        description="Hints about the generation model (GAN, diffusion, LLM, etc.)"
    )
    manipulation_type: str = Field(
        description="Type of manipulation: full_synthetic, face_swap, "
        "voice_clone, text_generation, splicing, none"
    )


class ReportOutput(BaseModel):
    """LLM output for final detection report."""

    executive_summary: str = Field(description="Executive summary of deepfake detection results")
    key_findings: list[str] = Field(description="Top findings across all analyzed media")
    risk_assessment: str = Field(description="Overall risk assessment: critical, high, medium, low")
    recommended_actions: list[str] = Field(description="Recommended response actions")
    confidence_note: str = Field(description="Note on overall confidence of detection results")


SYSTEM_ANALYZE = (
    "You are a synthetic media forensics expert analyzing "
    "artifacts in media content to detect AI-generated or "
    "manipulated material.\n"
    "Given the following forensic artifact data:\n"
    "1. Evaluate compression anomalies — JPEG/PNG artifacts "
    "inconsistent with genuine capture\n"
    "2. Analyze frequency domain — GAN grid artifacts, "
    "spectral peaks, checkerboard patterns in FFT\n"
    "3. Check noise patterns — inconsistent noise across "
    "regions indicates compositing or generation\n"
    "4. Assess lighting consistency — shadow direction, "
    "reflection angles, illumination gradients\n"
    "5. For video: evaluate temporal coherence — flickering, "
    "lip-sync mismatch, frame-to-frame jitter\n"
    "6. For audio: spectral analysis — unnatural formant "
    "transitions, vocoder artifacts, prosody anomalies\n"
    "7. Identify GAN fingerprints (StyleGAN, ProGAN) or "
    "diffusion artifacts (Stable Diffusion, DALL-E, Midjourney)\n"
    "8. For text: perplexity analysis, token probability "
    "distributions, repetition patterns, watermark detection"
)

SYSTEM_REPORT = (
    "You are a senior synthetic media analyst producing "
    "a final detection report for deepfake analysis results.\n"
    "Given the combined artifact analyses, provenance "
    "records, and authenticity classifications:\n"
    "1. Summarize the overall detection results — how many "
    "items analyzed, how many flagged as synthetic\n"
    "2. Highlight the most critical findings — high-confidence "
    "deepfakes, missing provenance, known generator signatures\n"
    "3. Assess organizational risk — potential for "
    "disinformation, fraud, brand damage, legal liability\n"
    "4. Recommend response actions — takedown, watermarking, "
    "C2PA adoption, employee training, platform reporting\n"
    "5. Note confidence limitations — edge cases, novel "
    "generation techniques, low-resolution source material"
)
