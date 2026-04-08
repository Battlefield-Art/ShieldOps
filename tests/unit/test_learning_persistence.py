"""Tests for learning cycle persistence — DB model, repository, and runner integration."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from shieldops.agents.learning.models import (
    LearningState,
    LearningStep,
    PatternInsight,
    PlaybookUpdate,
    ThresholdAdjustment,
)
from shieldops.agents.learning.runner import LearningRunner
from shieldops.db.models import LearningCycleRecord

# ── Helpers ───────────────────────────────────────────────────


def _make_learning_state(
    learning_id: str = "learn-test001",
    learning_type: str = "full",
    current_step: str = "complete",
    **overrides,
) -> LearningState:
    """Build a realistic LearningState for tests."""
    defaults = dict(
        learning_id=learning_id,
        learning_type=learning_type,
        target_period="30d",
        current_step=current_step,
        total_incidents_analyzed=12,
        recurring_pattern_count=2,
        improvement_score=78.5,
        automation_accuracy=85.0,
        learning_duration_ms=4500,
        pattern_insights=[
            PatternInsight(
                pattern_id="p1",
                alert_type="high_cpu",
                description="Recurring CPU spikes",
                frequency=5,
                common_root_cause="memory leak",
                common_resolution="restart_pod",
                confidence=0.9,
            ),
        ],
        playbook_updates=[
            PlaybookUpdate(
                playbook_id="pb1",
                alert_type="high_cpu",
                update_type="modify_step",
                title="Improve CPU playbook",
                steps=["Drain node", "Restart pod"],
            ),
        ],
        threshold_adjustments=[
            ThresholdAdjustment(
                adjustment_id="adj1",
                metric_name="cpu_usage_percent",
                current_threshold=80.0,
                recommended_threshold=88.0,
                direction="increase",
                reason="Too many false positives",
            ),
        ],
        reasoning_chain=[
            LearningStep(
                step_number=1,
                action="gather_outcomes",
                input_summary="period=30d",
                output_summary="12 incidents loaded",
                duration_ms=500,
            ),
        ],
        error=None,
        learning_start=datetime.now(UTC),
    )
    defaults.update(overrides)
    return LearningState(**defaults)


# ===========================================================================
# LearningCycleRecord Model Tests
# ===========================================================================


class TestLearningCycleRecord:
    """Tests for the SQLAlchemy ORM model."""

    def test_create_record_with_all_fields(self):
        record = LearningCycleRecord(
            id="learn-abc123",
            learning_type="full",
            target_period="30d",
            status="complete",
            total_incidents_analyzed=10,
            recurring_pattern_count=2,
            improvement_score=75.0,
            automation_accuracy=90.0,
            pattern_insights=[{"pattern_id": "p1", "alert_type": "high_cpu"}],
            playbook_updates=[{"playbook_id": "pb1"}],
            threshold_adjustments=[{"adjustment_id": "adj1"}],
            reasoning_chain=[{"step_number": 1, "action": "gather"}],
            error=None,
            duration_ms=3000,
        )
        assert record.id == "learn-abc123"
        assert record.learning_type == "full"
        assert record.status == "complete"
        assert record.total_incidents_analyzed == 10
        assert record.improvement_score == 75.0
        assert record.automation_accuracy == 90.0
        assert len(record.pattern_insights) == 1
        assert len(record.playbook_updates) == 1
        assert len(record.threshold_adjustments) == 1
        assert len(record.reasoning_chain) == 1
        assert record.error is None
        assert record.duration_ms == 3000

    def test_default_values(self):
        """Column defaults apply at DB flush time; verify they exist on the schema."""
        record = LearningCycleRecord(
            id="learn-defaults",
            learning_type="pattern_only",
        )
        # Nullable field has no value before flush
        assert record.error is None

        # Verify column-level defaults are declared in the mapping.
        # These apply at INSERT time, not on Python construction.
        table = LearningCycleRecord.__table__
        assert table.c.target_period.default.arg == "30d"
        assert table.c.status.default.arg == "init"
        assert table.c.total_incidents_analyzed.default.arg == 0
        assert table.c.recurring_pattern_count.default.arg == 0
        assert table.c.improvement_score.default.arg == 0.0
        assert table.c.automation_accuracy.default.arg == 0.0
        assert table.c.duration_ms.default.arg == 0

    def test_json_fields_accept_complex_data(self):
        insights = [
            {
                "pattern_id": "p1",
                "alert_type": "high_cpu",
                "description": "Recurring spikes",
                "frequency": 5,
                "environments": ["production", "staging"],
            },
            {
                "pattern_id": "p2",
                "alert_type": "oom_kill",
                "description": "Memory pressure",
                "frequency": 3,
            },
        ]
        record = LearningCycleRecord(
            id="learn-json",
            learning_type="full",
            pattern_insights=insights,
        )
        assert len(record.pattern_insights) == 2
        assert record.pattern_insights[0]["environments"] == [
            "production",
            "staging",
        ]

    def test_error_field_stores_text(self):
        record = LearningCycleRecord(
            id="learn-err",
            learning_type="full",
            error="LLM timeout after 30s",
        )
        assert record.error == "LLM timeout after 30s"

    def test_tablename(self):
        assert LearningCycleRecord.__tablename__ == "learning_cycles"


# ===========================================================================
# NOTE: TestRepositorySaveLearningCycle + TestRepositoryQueryLearningCycles
# were deleted in RFC #245 PR-3 (#272) alongside the god Repository class.
# Equivalent coverage will be rebuilt on fetch.* helpers in PR-4 (#273).
# The runner-level persistence tests below remain — they mock the
# repository via AsyncMock and exercise LearningRunner behavior directly,
# which is still the contract worth protecting.
# ===========================================================================


# ===========================================================================
# LearningRunner Persistence Tests
# ===========================================================================


class TestLearningRunnerPersistence:
    """Tests for runner calling save_learning_cycle after learn()."""

    @pytest.mark.asyncio
    async def test_learn_calls_save_on_success(self):
        mock_repo = AsyncMock()
        mock_repo.save_learning_cycle = AsyncMock(return_value="learn-persisted")

        runner = LearningRunner(repository=mock_repo)

        completed_state = LearningState(
            learning_id="learn-xyz",
            learning_type="full",
            current_step="complete",
            total_incidents_analyzed=10,
            learning_start=datetime.now(UTC),
        )

        with patch.object(runner, "_app") as mock_app:
            mock_app.ainvoke = AsyncMock(return_value=completed_state.model_dump())
            result = await runner.learn()

        assert result.current_step == "complete"
        mock_repo.save_learning_cycle.assert_awaited_once()

        # Verify the state passed to save_learning_cycle is a LearningState
        saved_state = mock_repo.save_learning_cycle.call_args[0][0]
        assert isinstance(saved_state, LearningState)
        assert saved_state.total_incidents_analyzed == 10

    @pytest.mark.asyncio
    async def test_learn_stores_repository_reference(self):
        mock_repo = AsyncMock()
        runner = LearningRunner(repository=mock_repo)
        assert runner._repository is mock_repo

    @pytest.mark.asyncio
    async def test_learn_still_returns_state_on_persist_success(self):
        mock_repo = AsyncMock()
        mock_repo.save_learning_cycle = AsyncMock(return_value="id")

        runner = LearningRunner(repository=mock_repo)

        with patch.object(runner, "_app") as mock_app:
            mock_app.ainvoke = AsyncMock(
                return_value=LearningState(
                    learning_id="learn-ret",
                    current_step="complete",
                    learning_start=datetime.now(UTC),
                    improvement_score=80.0,
                ).model_dump()
            )
            result = await runner.learn()

        assert result.improvement_score == 80.0
        assert len(runner.list_cycles()) == 1


# ===========================================================================
# LearningRunner Persistence Failure Tests
# ===========================================================================


class TestLearningRunnerPersistenceFailure:
    """Tests that persistence failures do not crash the runner."""

    @pytest.mark.asyncio
    async def test_persist_failure_does_not_crash_learn(self):
        mock_repo = AsyncMock()
        mock_repo.save_learning_cycle = AsyncMock(side_effect=RuntimeError("DB connection lost"))

        runner = LearningRunner(repository=mock_repo)

        with patch.object(runner, "_app") as mock_app:
            mock_app.ainvoke = AsyncMock(
                return_value=LearningState(
                    learning_id="learn-fail",
                    current_step="complete",
                    learning_start=datetime.now(UTC),
                ).model_dump()
            )
            result = await runner.learn()

        # Runner should still return the state successfully
        assert result.current_step == "complete"
        assert len(runner.list_cycles()) == 1

    @pytest.mark.asyncio
    async def test_persist_failure_logs_warning(self):
        mock_repo = AsyncMock()
        mock_repo.save_learning_cycle = AsyncMock(side_effect=ConnectionError("connection refused"))

        runner = LearningRunner(repository=mock_repo)

        with (
            patch.object(runner, "_app") as mock_app,
            patch("shieldops.agents.learning.runner.logger") as mock_logger,
        ):
            mock_app.ainvoke = AsyncMock(
                return_value=LearningState(
                    learning_id="learn-warn",
                    current_step="complete",
                    learning_start=datetime.now(UTC),
                ).model_dump()
            )
            await runner.learn()

        # Should have logged a warning about persistence failure
        mock_logger.warning.assert_called()
        call_kwargs = mock_logger.warning.call_args
        assert "learning_cycle_persist_failed" in str(call_kwargs)

    @pytest.mark.asyncio
    async def test_graph_error_does_not_attempt_persist(self):
        """When the graph itself fails, we should not try to persist."""
        mock_repo = AsyncMock()
        mock_repo.save_learning_cycle = AsyncMock()

        runner = LearningRunner(repository=mock_repo)

        with patch.object(runner, "_app") as mock_app:
            mock_app.ainvoke = AsyncMock(side_effect=RuntimeError("graph exploded"))
            result = await runner.learn()

        assert result.current_step == "failed"
        # save_learning_cycle should NOT be called on graph failure
        mock_repo.save_learning_cycle.assert_not_awaited()


# ===========================================================================
# LearningRunner No Repository Tests (backward compatibility)
# ===========================================================================


class TestLearningRunnerNoRepository:
    """Tests that the runner works fine without a repository (backward compat)."""

    def test_init_without_repository(self):
        runner = LearningRunner()
        assert runner._repository is None

    @pytest.mark.asyncio
    async def test_learn_without_repository_skips_persist(self):
        runner = LearningRunner()  # No repository

        with patch.object(runner, "_app") as mock_app:
            mock_app.ainvoke = AsyncMock(
                return_value=LearningState(
                    learning_id="learn-norepo",
                    current_step="complete",
                    learning_start=datetime.now(UTC),
                ).model_dump()
            )
            result = await runner.learn()

        # Should complete successfully without any DB calls
        assert result.current_step == "complete"
        assert len(runner.list_cycles()) == 1

    @pytest.mark.asyncio
    async def test_learn_error_without_repository(self):
        runner = LearningRunner()

        with patch.object(runner, "_app") as mock_app:
            mock_app.ainvoke = AsyncMock(side_effect=RuntimeError("graph error"))
            result = await runner.learn()

        assert result.current_step == "failed"
        assert result.error == "graph error"
        assert len(runner.list_cycles()) == 1

    def test_explicit_none_repository(self):
        runner = LearningRunner(repository=None)
        assert runner._repository is None
