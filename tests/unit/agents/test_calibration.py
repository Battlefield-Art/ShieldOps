"""Tests for shieldops.agents.calibration — utility module."""

from __future__ import annotations


def test_calibration_imports():
    from shieldops.agents.calibration import calibrator, tracker

    assert calibrator is not None
    assert tracker is not None
