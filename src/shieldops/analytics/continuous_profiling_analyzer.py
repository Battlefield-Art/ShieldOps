"""Continuous Profiling Analyzer — continuous profiling analysis for CPU, memory, and I/O."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ContinuousProfilingAnalyzer = engine(
    "ContinuousProfilingAnalyzer",
    description="Continuous Profiling Analyzer — continuous profiling analysis for CPU, memo...",
    enums={
        "profile_type": EnumDef(
            "ProfileType",
            {
                "CPU": "cpu",
                "MEMORY": "memory",
                "IO": "io",
                "LOCK_CONTENTION": "lock_contention",
                "ALLOCATION": "allocation",
            },
        ),
        "profile_source": EnumDef(
            "ProfileSource",
            {
                "PYROSCOPE": "pyroscope",
                "PPROF": "pprof",
                "ASYNC_PROFILER": "async_profiler",
                "PERF": "perf",
                "CUSTOM": "custom",
            },
        ),
        "profile_severity": EnumDef(
            "ProfileSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFO": "info",
            },
        ),
    },
)

# Backward-compatible re-exports
ProfileType = ContinuousProfilingAnalyzer.ProfileType
ProfileSource = ContinuousProfilingAnalyzer.ProfileSource
ProfileSeverity = ContinuousProfilingAnalyzer.ProfileSeverity
ProfileRecord = ContinuousProfilingAnalyzer.Record
ProfileAnalysis = ContinuousProfilingAnalyzer.Analysis
ContinuousProfilingReport = ContinuousProfilingAnalyzer.Report
