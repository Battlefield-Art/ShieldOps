"""Incident Prediction Model — predicts future incidents from signals and patterns."""

from __future__ import annotations

from shieldops.agents.incident_prediction_model.graph import (
    create_incident_prediction_model_graph,
)

__all__ = ["create_incident_prediction_model_graph"]
