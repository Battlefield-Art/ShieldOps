"""Bulk upload endpoints — CSV / JSON historical data ingestion.

Accepts CSV or JSON files (multipart/form-data), auto-detects the format, maps
each row/record to a raw event, and routes it through the ingestion pipeline
(OCSF normalize + DuckDB store). Large files (>10MB) are processed in the
background via FastAPI ``BackgroundTasks`` and the caller receives a ``job_id``
for status polling.

Endpoints
---------
* ``POST /api/v1/ingest/upload``             — accept file, return job_id.
* ``GET  /api/v1/ingest/upload/{job_id}``    — poll job status.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import time
from typing import Any
from uuid import uuid4

import structlog
from fastapi import (
    APIRouter,
    BackgroundTasks,
    File,
    Form,
    HTTPException,
    UploadFile,
)
from pydantic import BaseModel, Field

from shieldops.ingestion.pipeline import process_batch

logger = structlog.get_logger()

router = APIRouter(prefix="/ingest/upload", tags=["Bulk Upload"])

# 10 MB threshold — above this we defer to a BackgroundTask.
_BACKGROUND_THRESHOLD_BYTES = 10 * 1024 * 1024

# Job state enum values (kept as plain strings to keep response bodies small).
JOB_STATUS_QUEUED = "queued"
JOB_STATUS_PROCESSING = "processing"
JOB_STATUS_COMPLETE = "complete"
JOB_STATUS_FAILED = "failed"


# ---------------------------------------------------------------------------
# In-memory job registry (sufficient for a single-process dev deployment;
# production swaps this for Redis — see GH issue #204).
# ---------------------------------------------------------------------------


class UploadJob(BaseModel):
    """Tracked state for a bulk upload job."""

    job_id: str
    org_id: str
    source_provider: str
    filename: str
    file_format: str  # "csv" | "json"
    file_size: int = 0
    status: str = JOB_STATUS_QUEUED
    accepted: int = 0
    rejected: int = 0
    errors: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    error: str = ""


_jobs: dict[str, UploadJob] = {}


def _get_job(job_id: str) -> UploadJob | None:
    return _jobs.get(job_id)


def _save_job(job: UploadJob) -> None:
    job.updated_at = time.time()
    _jobs[job.job_id] = job


def _reset_jobs() -> None:
    """Test-only helper — clear the in-memory job registry."""
    _jobs.clear()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class UploadAcceptedResponse(BaseModel):
    """Immediate response after accepting a bulk upload request."""

    job_id: str
    status: str
    file_format: str
    file_size: int
    background: bool = False


class UploadJobStatusResponse(BaseModel):
    """Job status response for polling."""

    job_id: str
    status: str
    file_format: str
    filename: str
    file_size: int
    accepted: int
    rejected: int
    errors: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    source_provider: str
    org_id: str
    created_at: float
    updated_at: float
    error: str = ""


# ---------------------------------------------------------------------------
# Format detection + parsers
# ---------------------------------------------------------------------------


def _detect_format(filename: str, content_type: str | None, body: bytes) -> str:
    """Auto-detect CSV vs JSON from filename, content-type, or body sniffing."""
    name = (filename or "").lower()
    ctype = (content_type or "").lower()

    if name.endswith(".csv") or "csv" in ctype:
        return "csv"
    if name.endswith(".json") or name.endswith(".ndjson") or "json" in ctype:
        return "json"

    # Sniff body: JSON starts with '{' or '['
    stripped = body.lstrip()
    if stripped[:1] in (b"{", b"["):
        return "json"
    return "csv"


def _parse_csv(body: bytes) -> list[dict[str, Any]]:
    """Parse a CSV body into a list of row dicts."""
    text = body.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    rows: list[dict[str, Any]] = []
    for row in reader:
        # csv.DictReader produces dict[str, str | None]; normalize Nones.
        rows.append({k: (v if v is not None else "") for k, v in row.items()})
    return rows


def _parse_json(body: bytes) -> list[dict[str, Any]]:
    """Parse a JSON body into a list of record dicts.

    Accepts:
        - a top-level list of objects
        - a single object
        - NDJSON (newline-delimited JSON objects)
        - an object with a top-level ``records``/``events`` list.
    """
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return []

    # Try regular JSON first.
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # NDJSON fallback
        rows: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON line: {exc}") from exc
            if isinstance(obj, dict):
                rows.append(obj)
        return rows

    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for key in ("records", "events", "data"):
            if key in data and isinstance(data[key], list):
                return [r for r in data[key] if isinstance(r, dict)]
        return [data]
    return []


# ---------------------------------------------------------------------------
# Processing (shared by sync + background paths)
# ---------------------------------------------------------------------------


async def _run_job(job_id: str, body: bytes, file_format: str) -> None:
    """Parse + ingest a job's payload and update job state."""
    job = _get_job(job_id)
    if job is None:
        logger.warning("bulk_upload.job_missing", job_id=job_id)
        return

    job.status = JOB_STATUS_PROCESSING
    _save_job(job)

    try:
        if file_format == "csv":
            records = _parse_csv(body)
        else:
            records = _parse_json(body)
    except Exception as exc:
        job.status = JOB_STATUS_FAILED
        job.error = f"parse_error: {exc}"
        _save_job(job)
        logger.warning("bulk_upload.parse_failed", job_id=job_id, error=str(exc))
        return

    if not records:
        job.status = JOB_STATUS_COMPLETE
        _save_job(job)
        return

    try:
        result = await process_batch(records, job.source_provider, job.org_id)
    except Exception as exc:
        job.status = JOB_STATUS_FAILED
        job.error = f"pipeline_error: {exc}"
        _save_job(job)
        logger.exception("bulk_upload.pipeline_failed", job_id=job_id)
        return

    job.accepted = result.accepted
    job.rejected = result.rejected
    job.errors = list(result.errors)
    job.event_ids = list(result.event_ids)
    job.status = JOB_STATUS_COMPLETE
    _save_job(job)

    logger.info(
        "bulk_upload.job_complete",
        job_id=job_id,
        accepted=result.accepted,
        rejected=result.rejected,
        org_id=job.org_id,
        source_provider=job.source_provider,
    )


def _run_job_sync_wrapper(job_id: str, body: bytes, file_format: str) -> None:
    """Background-task entrypoint: run the async job on a fresh event loop."""
    try:
        asyncio.run(_run_job(job_id, body, file_format))
    except RuntimeError:
        # An event loop may already exist in some test contexts; fall back to
        # scheduling on the running loop.
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_run_job(job_id, body, file_format))
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", status_code=202, response_model=UploadAcceptedResponse)
async def upload_bulk_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="CSV or JSON file"),
    source_provider: str = Form(default="bulk_upload"),
    org_id: str = Form(default="default"),
) -> UploadAcceptedResponse:
    """Accept a CSV/JSON bulk upload and schedule it for ingestion.

    Small files (<=10MB) are processed inline; large files are deferred to a
    FastAPI background task and the caller polls ``GET /ingest/upload/{job_id}``.
    """
    body = await file.read()
    if not body:
        raise HTTPException(status_code=400, detail="Empty file payload")

    file_format = _detect_format(file.filename or "", file.content_type, body)
    job_id = str(uuid4())

    job = UploadJob(
        job_id=job_id,
        org_id=org_id,
        source_provider=source_provider,
        filename=file.filename or "",
        file_format=file_format,
        file_size=len(body),
        status=JOB_STATUS_QUEUED,
    )
    _save_job(job)

    background = len(body) > _BACKGROUND_THRESHOLD_BYTES
    if background:
        background_tasks.add_task(_run_job_sync_wrapper, job_id, body, file_format)
    else:
        await _run_job(job_id, body, file_format)

    logger.info(
        "bulk_upload.accepted",
        job_id=job_id,
        filename=job.filename,
        file_format=file_format,
        file_size=len(body),
        background=background,
        org_id=org_id,
    )

    return UploadAcceptedResponse(
        job_id=job_id,
        status=job.status,
        file_format=file_format,
        file_size=len(body),
        background=background,
    )


@router.get("/{job_id}", response_model=UploadJobStatusResponse)
async def get_upload_status(job_id: str) -> UploadJobStatusResponse:
    """Return the current status of a bulk upload job."""
    job = _get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"job_id not found: {job_id}")

    return UploadJobStatusResponse(
        job_id=job.job_id,
        status=job.status,
        file_format=job.file_format,
        filename=job.filename,
        file_size=job.file_size,
        accepted=job.accepted,
        rejected=job.rejected,
        errors=job.errors,
        event_ids=job.event_ids,
        source_provider=job.source_provider,
        org_id=job.org_id,
        created_at=job.created_at,
        updated_at=job.updated_at,
        error=job.error,
    )
