"""Engine factory -- generates engine classes from declarative specs.

Replaces 592 copy-paste engine files with a single ``engine()`` call that
returns a fully-formed class with enums, Pydantic models, ring-buffer
storage, domain analytics, and report generation.
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

# Modules that use ``record_item`` instead of ``add_record``
_RECORD_ITEM_MODULES = frozenset({"changes", "operations", "topology"})


@dataclass(frozen=True)
class EnumDef:
    """Definition for a StrEnum class."""

    name: str
    values: dict[str, str]


@dataclass(frozen=True)
class FieldDef:
    """Definition for a Pydantic model field."""

    name: str
    type: type = str
    default: Any = ""


def _snake(name: str) -> str:
    """Convert CamelCase to snake_case."""
    out: list[str] = []
    for i, ch in enumerate(name):
        if ch.isupper() and i > 0:
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


def _make_enum(edef: EnumDef) -> type[StrEnum]:
    """Create a StrEnum from an EnumDef."""
    return StrEnum(edef.name, {k: v for k, v in edef.values.items()})  # type: ignore[misc,return-value]


def _make_model(
    class_name: str,
    *,
    extra_fields: list[FieldDef] | None = None,
    enum_fields: dict[str, type[StrEnum]] | None = None,
    score_field: str = "score",
    key_field: str = "name",
) -> type[BaseModel]:
    """Dynamically create a Pydantic BaseModel subclass."""
    namespace: dict[str, Any] = {
        "__annotations__": {},
    }

    # id + created_at are always present
    namespace["__annotations__"]["id"] = str
    namespace["id"] = Field(default_factory=lambda: str(uuid.uuid4()))

    # key_field
    namespace["__annotations__"][key_field] = str
    namespace[key_field] = ""

    # enum fields (with their first member as default)
    for fname, ecls in (enum_fields or {}).items():
        namespace["__annotations__"][fname] = ecls
        members = list(ecls)
        namespace[fname] = members[0] if members else None

    # extra fields
    for fdef in extra_fields or []:
        namespace["__annotations__"][fdef.name] = fdef.type
        namespace[fdef.name] = fdef.default

    # score_field
    namespace["__annotations__"][score_field] = float
    namespace[score_field] = 0.0

    # service + team
    namespace["__annotations__"]["service"] = str
    namespace["service"] = ""
    namespace["__annotations__"]["team"] = str
    namespace["team"] = ""

    # created_at last
    namespace["__annotations__"]["created_at"] = float
    namespace["created_at"] = Field(default_factory=time.time)

    return type(class_name, (BaseModel,), namespace)


def _make_analysis_model(
    class_name: str,
    *,
    key_field: str = "name",
    first_enum_field: str | None = None,
    first_enum_cls: type[StrEnum] | None = None,
    extra_fields: list[FieldDef] | None = None,
) -> type[BaseModel]:
    namespace: dict[str, Any] = {"__annotations__": {}}

    namespace["__annotations__"]["id"] = str
    namespace["id"] = Field(default_factory=lambda: str(uuid.uuid4()))

    namespace["__annotations__"][key_field] = str
    namespace[key_field] = ""

    if first_enum_field and first_enum_cls:
        namespace["__annotations__"][first_enum_field] = first_enum_cls
        members = list(first_enum_cls)
        namespace[first_enum_field] = members[0] if members else None

    namespace["__annotations__"]["analysis_score"] = float
    namespace["analysis_score"] = 0.0

    namespace["__annotations__"]["threshold"] = float
    namespace["threshold"] = 0.0

    namespace["__annotations__"]["breached"] = bool
    namespace["breached"] = False

    namespace["__annotations__"]["description"] = str
    namespace["description"] = ""

    for fdef in extra_fields or []:
        namespace["__annotations__"][fdef.name] = fdef.type
        namespace[fdef.name] = fdef.default

    namespace["__annotations__"]["created_at"] = float
    namespace["created_at"] = Field(default_factory=time.time)

    return type(class_name, (BaseModel,), namespace)


def _make_report_model(
    class_name: str,
    *,
    score_field: str = "score",
    enum_fields: dict[str, type[StrEnum]] | None = None,
    extra_fields: list[FieldDef] | None = None,
) -> type[BaseModel]:
    namespace: dict[str, Any] = {"__annotations__": {}}

    namespace["__annotations__"]["id"] = str
    namespace["id"] = Field(default_factory=lambda: str(uuid.uuid4()))

    namespace["__annotations__"]["total_records"] = int
    namespace["total_records"] = 0

    namespace["__annotations__"]["total_analyses"] = int
    namespace["total_analyses"] = 0

    namespace["__annotations__"]["gap_count"] = int
    namespace["gap_count"] = 0

    avg_field = f"avg_{score_field}"
    namespace["__annotations__"][avg_field] = float
    namespace[avg_field] = 0.0

    for fname in enum_fields or {}:
        by_name = f"by_{fname}"
        namespace["__annotations__"][by_name] = dict[str, int]
        namespace[by_name] = Field(default_factory=dict)

    for fdef in extra_fields or []:
        namespace["__annotations__"][fdef.name] = fdef.type
        if isinstance(fdef.default, (dict, list)):
            namespace[fdef.name] = Field(default_factory=type(fdef.default))
        else:
            namespace[fdef.name] = fdef.default

    namespace["__annotations__"]["top_gaps"] = list[str]
    namespace["top_gaps"] = Field(default_factory=list)

    namespace["__annotations__"]["recommendations"] = list[str]
    namespace["recommendations"] = Field(default_factory=list)

    namespace["__annotations__"]["generated_at"] = float
    namespace["generated_at"] = Field(default_factory=time.time)

    namespace["__annotations__"]["created_at"] = float
    namespace["created_at"] = Field(default_factory=time.time)

    return type(class_name, (BaseModel,), namespace)


def engine(
    name: str,
    *,
    module: str = "",
    description: str = "",
    enums: dict[str, EnumDef] | None = None,
    record_fields: list[FieldDef] | None = None,
    analysis_fields: list[FieldDef] | None = None,
    report_extra_fields: list[FieldDef] | None = None,
    max_records: int = 200_000,
    threshold: float = 50.0,
    score_field: str = "score",
    key_field: str = "name",
    group_field: str = "service",
) -> type:
    """Generate a fully-formed engine class from a declarative spec.

    Parameters
    ----------
    name:
        Class name for the generated engine (e.g. ``"BehavioralRiskAggregator"``).
    module:
        Package the engine belongs to (e.g. ``"analytics"``).  Determines
        whether the public ingest method is ``add_record`` or ``record_item``.
    description:
        Docstring for the generated class.
    enums:
        Mapping of *field name* to :class:`EnumDef`.  Each entry produces a
        ``StrEnum`` class and a corresponding field on the Record model.
    record_fields:
        Extra fields beyond the standard set (id, key, enums, score, service,
        team, created_at) to add to the Record model.
    analysis_fields:
        Extra fields on the Analysis model.
    report_extra_fields:
        Extra fields on the Report model.
    max_records:
        Ring-buffer capacity (default 200 000).
    threshold:
        Default gap/breach threshold.
    score_field:
        Name of the primary numeric score field on the Record model
        (e.g. ``"aggregated_score"``, ``"trust_score"``).
    key_field:
        Name of the primary key field on the Record model
        (e.g. ``"entity_name"``, ``"trust_id"``).
    group_field:
        Field used to group records in :meth:`rank_by_score` (default
        ``"service"``).

    Returns
    -------
    type
        A new engine class with all standard methods.
    """
    log_prefix = _snake(name)
    use_record_item = module in _RECORD_ITEM_MODULES

    # --- build enum classes ---
    enum_classes: dict[str, type[StrEnum]] = {}
    for field_name, edef in (enums or {}).items():
        enum_classes[field_name] = _make_enum(edef)

    first_enum_field: str | None = None
    first_enum_cls: type[StrEnum] | None = None
    if enum_classes:
        first_enum_field = next(iter(enum_classes))
        first_enum_cls = enum_classes[first_enum_field]

    # --- build models ---
    record_model = _make_model(
        f"{name}Record",
        extra_fields=record_fields,
        enum_fields=enum_classes,
        score_field=score_field,
        key_field=key_field,
    )

    analysis_model = _make_analysis_model(
        f"{name}Analysis",
        key_field=key_field,
        first_enum_field=first_enum_field,
        first_enum_cls=first_enum_cls,
        extra_fields=analysis_fields,
    )

    report_model = _make_report_model(
        f"{name}Report",
        score_field=score_field,
        enum_fields=enum_classes,
        extra_fields=report_extra_fields,
    )

    # --- capture in closure ---
    _score = score_field
    _key = key_field
    _group = group_field
    _thresh = threshold
    _max = max_records
    _enums = enum_classes
    _first_ef = first_enum_field
    _record_cls = record_model
    _analysis_cls = analysis_model
    _report_cls = report_model

    class _Engine:
        __doc__ = description or f"{name} engine."

        # Expose models and enums as class attributes
        Record = _record_cls
        Analysis = _analysis_cls
        Report = _report_cls

        def __init__(
            self,
            max_records: int = _max,
            threshold: float = _thresh,
        ) -> None:
            self._max_records = max_records
            self._threshold = threshold
            self._records: deque[Any] = deque(maxlen=max_records)
            self._analyses: deque[Any] = deque(maxlen=max_records)
            self._logger = structlog.get_logger()
            self._logger.info(
                f"{log_prefix}.initialized",
                max_records=max_records,
                threshold=threshold,
            )

        # -- ingest ---------------------------------------------------------

        def _ingest(self, **kwargs: Any) -> Any:
            record = _record_cls(**kwargs)
            self._records.append(record)
            log_kw: dict[str, Any] = {"record_id": getattr(record, "id", "")}
            log_kw[_key] = getattr(record, _key, "")
            if _first_ef:
                val = getattr(record, _first_ef, None)
                log_kw[_first_ef] = (
                    val.value if val is not None and hasattr(val, "value") else str(val or "")
                )
            self._logger.info(f"{log_prefix}.recorded", **log_kw)
            return record

        # -- get / list -----------------------------------------------------

        def get_record(self, record_id: str) -> Any | None:
            for r in self._records:
                if r.id == record_id:
                    return r
            return None

        def list_records(self, limit: int = 50, **filters: Any) -> list[Any]:
            results = list(self._records)
            for fname, fval in filters.items():
                if fval is not None:
                    results = [r for r in results if getattr(r, fname, None) == fval]
            return results[-limit:]

        # -- analysis -------------------------------------------------------

        def add_analysis(self, **kwargs: Any) -> Any:
            analysis = _analysis_cls(**kwargs)
            self._analyses.append(analysis)
            log_kw: dict[str, Any] = {_key: getattr(analysis, _key, "")}
            log_kw["analysis_score"] = getattr(analysis, "analysis_score", 0.0)
            self._logger.info(f"{log_prefix}.analysis_added", **log_kw)
            return analysis

        def process(self, key: str) -> Any:
            """Alias: look up a record by key_field and create an analysis."""
            matched = [r for r in self._records if getattr(r, _key, None) == key]
            if matched:
                rec = matched[-1]
                score_val = getattr(rec, _score, 0.0)
                kw: dict[str, Any] = {
                    _key: key,
                    "analysis_score": score_val,
                    "threshold": self._threshold,
                    "breached": score_val < self._threshold,
                    "description": f"Processed {key}",
                }
                if _first_ef:
                    kw[_first_ef] = getattr(rec, _first_ef)
                return self.add_analysis(**kw)
            kw = {
                _key: key,
                "analysis_score": 0.0,
                "threshold": self._threshold,
                "breached": True,
                "description": f"No records found for {key}",
            }
            return self.add_analysis(**kw)

        # -- domain operations ----------------------------------------------

        def analyze_distribution(self) -> dict[str, Any]:
            """Group by first enum field; return count and avg score."""
            if not _first_ef:
                return {}
            group_data: dict[str, list[float]] = {}
            for r in self._records:
                val = getattr(r, _first_ef)
                k = val.value if hasattr(val, "value") else str(val)
                group_data.setdefault(k, []).append(getattr(r, _score, 0.0))
            result: dict[str, Any] = {}
            avg_key = f"avg_{_score}"
            for gk, scores in group_data.items():
                result[gk] = {
                    "count": len(scores),
                    avg_key: round(sum(scores) / len(scores), 2),
                }
            return result

        def identify_gaps(self) -> list[dict[str, Any]]:
            """Return records where score < threshold, sorted ascending."""
            results: list[dict[str, Any]] = []
            for r in self._records:
                sc = getattr(r, _score, 0.0)
                if sc < self._threshold:
                    entry: dict[str, Any] = {
                        "record_id": r.id,
                        _key: getattr(r, _key, ""),
                        _score: sc,
                        "service": getattr(r, "service", ""),
                        "team": getattr(r, "team", ""),
                    }
                    if _first_ef:
                        val = getattr(r, _first_ef)
                        entry[_first_ef] = val.value if hasattr(val, "value") else str(val)
                    results.append(entry)
            return sorted(results, key=lambda x: x[_score])

        def rank_by_score(self) -> list[dict[str, Any]]:
            """Group by group_field, avg score, sort ascending."""
            svc_scores: dict[str, list[float]] = {}
            for r in self._records:
                gval = getattr(r, _group, "")
                svc_scores.setdefault(gval, []).append(getattr(r, _score, 0.0))
            avg_key = f"avg_{_score}"
            results: list[dict[str, Any]] = []
            for svc, scores in svc_scores.items():
                results.append(
                    {
                        _group: svc,
                        avg_key: round(sum(scores) / len(scores), 2),
                    }
                )
            results.sort(key=lambda x: x[avg_key])
            return results

        def detect_trends(self) -> dict[str, Any]:
            """Split-half comparison on analysis_score; delta threshold 5.0."""
            if len(self._analyses) < 2:
                return {"trend": "insufficient_data", "delta": 0.0}
            vals = [a.analysis_score for a in self._analyses]
            mid = len(vals) // 2
            first_half = vals[:mid]
            second_half = vals[mid:]
            avg_first = sum(first_half) / len(first_half)
            avg_second = sum(second_half) / len(second_half)
            delta = round(avg_second - avg_first, 2)
            if abs(delta) < 5.0:
                trend = "stable"
            elif delta > 0:
                trend = "improving"
            else:
                trend = "degrading"
            return {
                "trend": trend,
                "delta": delta,
                "avg_first_half": round(avg_first, 2),
                "avg_second_half": round(avg_second, 2),
            }

        # -- report / stats -------------------------------------------------

        def generate_report(self) -> Any:
            # per-enum distribution
            by_enum: dict[str, dict[str, int]] = {}
            for fname in _enums:
                by_enum[fname] = {}
            for r in self._records:
                for fname in _enums:
                    val = getattr(r, fname)
                    k = val.value if hasattr(val, "value") else str(val)
                    by_enum[fname][k] = by_enum[fname].get(k, 0) + 1

            scores = [getattr(r, _score, 0.0) for r in self._records]
            avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
            gap_count = sum(1 for s in scores if s < self._threshold)

            gap_list = self.identify_gaps()
            top_gaps = [g[_key] for g in gap_list[:5]]

            recs: list[str] = []
            if self._records and gap_count > 0:
                recs.append(f"{gap_count} record(s) below threshold ({self._threshold})")
            if self._records and avg_score < self._threshold:
                recs.append(f"Avg {_score} {avg_score} below threshold ({self._threshold})")
            if not recs:
                recs.append(f"{name} posture is healthy")

            report_kw: dict[str, Any] = {
                "total_records": len(self._records),
                "total_analyses": len(self._analyses),
                "gap_count": gap_count,
                f"avg_{_score}": avg_score,
                "top_gaps": top_gaps,
                "recommendations": recs,
            }
            for fname, dist in by_enum.items():
                report_kw[f"by_{fname}"] = dist

            return _report_cls(**report_kw)

        def get_stats(self) -> dict[str, Any]:
            first_dist: dict[str, int] = {}
            if _first_ef:
                for r in self._records:
                    val = getattr(r, _first_ef)
                    k = val.value if hasattr(val, "value") else str(val)
                    first_dist[k] = first_dist.get(k, 0) + 1
            stats: dict[str, Any] = {
                "total_records": len(self._records),
                "total_analyses": len(self._analyses),
                "threshold": self._threshold,
            }
            if _first_ef:
                stats[f"{_first_ef}_distribution"] = first_dist
            stats["unique_teams"] = len({getattr(r, "team", "") for r in self._records})
            stats["unique_services"] = len({getattr(r, "service", "") for r in self._records})
            return stats

        def clear_data(self) -> dict[str, str]:
            self._records.clear()
            self._analyses.clear()
            self._logger.info(f"{log_prefix}.cleared")
            return {"status": "cleared"}

    # --- attach public ingest method ---
    if use_record_item:
        _Engine.record_item = _Engine._ingest  # type: ignore[attr-defined]
    else:
        _Engine.add_record = _Engine._ingest  # type: ignore[attr-defined]

    # --- attach enum classes as attributes ---
    for _fname, ecls in _enums.items():
        setattr(_Engine, ecls.__name__, ecls)

    # --- rename class ---
    _Engine.__name__ = name
    _Engine.__qualname__ = name

    return _Engine
