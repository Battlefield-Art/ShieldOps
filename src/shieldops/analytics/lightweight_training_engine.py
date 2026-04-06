"""Lightweight Training Engine Resource-efficient model training with LoRA, QLoRA, and distill..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

LightweightTrainingEngine = engine(
    "LightweightTrainingEngine",
    description="Resource-efficient model training management with budget tracking and effic...",
    enums={
        "training_mode": EnumDef(
            "TrainingMode",
            {
                "FULL": "full",
                "LORA": "lora",
                "QLORA": "qlora",
                "DISTILLATION": "distillation",
            },
        ),
        "constraint": EnumDef(
            "ResourceConstraint",
            {
                "MEMORY": "memory",
                "COMPUTE": "compute",
                "TIME": "time",
                "COST": "cost",
            },
        ),
        "phase": EnumDef(
            "TrainingPhase",
            {
                "WARMUP": "warmup",
                "TRAINING": "training",
                "COOLDOWN": "cooldown",
                "EVALUATION": "evaluation",
            },
        ),
    },
    record_fields=[
        FieldDef("loss_value", float, 0.0),
        FieldDef("resource_usage_pct", float, 0.0),
        FieldDef("epoch", int, 0),
    ],
    key_field="job_name",
)

# Backward-compatible re-exports
TrainingMode = LightweightTrainingEngine.TrainingMode
ResourceConstraint = LightweightTrainingEngine.ResourceConstraint
TrainingPhase = LightweightTrainingEngine.TrainingPhase
TrainingRecord = LightweightTrainingEngine.Record
TrainingAnalysis = LightweightTrainingEngine.Analysis
TrainingReport = LightweightTrainingEngine.Report
