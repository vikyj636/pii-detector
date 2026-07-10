"""FastAPI app: POST /detect and GET /health.

Privacy invariant: request text and detected entity values are NEVER logged.
Log lines carry metadata only (request id, method, path, status, latency,
per-type entity counts). Keep it that way — logging raw PII to CloudWatch
defeats the purpose of this service.

This service detects PII spans; it does not tokenize, reconstruct, or persist
anything. Tokenization/reconstruction belongs to the calling workflow.
"""
from __future__ import annotations

import hmac
import logging
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from starlette.concurrency import run_in_threadpool

from .config import (
    REGEX_LABELS,
    Settings,
    configure_logging,
    get_threshold,
    load_denylist,
    resolve_thresholds,
)
from .detectors import ner_detector
from .detectors.regex_detector import RegexDetector
from .schemas import DetectRequest, DetectResponse, Entity

logger = logging.getLogger("pii_detector.api")

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings.from_env()
    configure_logging(settings.log_level)

    # Match torch's thread pool to the vCPUs Fargate actually allocates instead
    # of letting torch detect the host's core count from inside the container.
    try:
        import torch

        torch.set_num_threads(int(os.environ.get("NUM_THREADS", "1")))
    except ImportError:
        logger.warning("torch not installed; skipping thread pinning (expected under test)")

    app.state.settings = settings
    app.state.ready = threading.Event()
    app.state.model_load_error = None
    app.state.regex_detector = RegexDetector(settings.secret_patterns_path, settings.phone_regions)
    app.state.denylist = load_denylist(settings.denylist_path)
    started_at = time.monotonic()

    def _load_model() -> None:
        try:
            ner_detector.load_singleton(settings)
        except Exception:
            app.state.model_load_error = ner_detector.get_load_error() or "model load failed"
            logger.exception("NER model failed to load")
            return
        app.state.ready.set()
        logger.info(
            "NER model ready",
            extra={"meta": {"load_seconds": round(time.monotonic() - started_at, 1)}},
        )

    # Load in a background thread so /health can answer 503 (instead of refusing
    # connections) while the model warms up.
    threading.Thread(target=_load_model, name="model-loader", daemon=True).start()
    yield


app = FastAPI(
    title="pii-detector",
    version="0.1.0",
    description="Stateless PII span detection (regex + GLiNER2). Detection only — no tokenization, no persistence.",
    lifespan=lifespan,
)


async def require_api_key(request: Request, provided: str | None = Depends(_api_key_header)) -> None:
    expected: str = request.app.state.settings.api_key
    if not provided or not hmac.compare_digest(provided.encode(), expected.encode()):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


@app.middleware("http")
async def request_metadata(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    request.state.request_id = request_id
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    if request.url.path != "/health" or response.status_code != 200:
        logger.info(
            "request",
            extra={
                "meta": {
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                }
            },
        )
    return response


@app.get("/health")
async def health(request: Request):
    state = request.app.state
    if state.ready.is_set():
        return {"status": "ok", "model_loaded": True}
    if state.model_load_error:
        content = {"status": "error", "model_loaded": False, "error": state.model_load_error}
    else:
        content = {"status": "loading", "model_loaded": False}
    return JSONResponse(status_code=503, content=content)


@app.post(
    "/detect",
    response_model=DetectResponse,
    response_model_exclude_none=True,
    dependencies=[Depends(require_api_key)],
)
async def detect(request: Request, body: DetectRequest) -> DetectResponse:
    state = request.app.state
    settings: Settings = state.settings

    if not state.ready.is_set():
        detail = (
            "Model failed to load; check /health"
            if state.model_load_error
            else "Model is still loading; retry shortly"
        )
        raise HTTPException(status_code=503, detail=detail, headers={"Retry-After": "5"})
    if len(body.text) > settings.max_text_length:
        raise HTTPException(
            status_code=413,
            detail=f"text exceeds MAX_TEXT_LENGTH ({settings.max_text_length} characters)",
        )

    labels = body.labels or settings.default_labels
    requested = set(labels)
    thresholds = resolve_thresholds(body.thresholds)

    regex_labels = requested & REGEX_LABELS
    ner_labels = sorted(requested - REGEX_LABELS)

    entities: list[Entity] = []
    if regex_labels:
        entities.extend(state.regex_detector.detect(body.text, regex_labels))
    if ner_labels:
        detector = ner_detector.get_detector()
        if detector is None:  # defensive: ready flag implies loaded
            raise HTTPException(status_code=503, detail="Model unavailable")
        entities.extend(
            await run_in_threadpool(detector.detect, body.text, ner_labels, thresholds)
        )

    entities = [e for e in entities if e.confidence >= get_threshold(e.type, thresholds)]
    denylist: frozenset[str] = state.denylist
    entities = [e for e in entities if e.text.strip().lower() not in denylist]

    deduped: dict[tuple[int, int, str], Entity] = {}
    for entity in entities:
        key = (entity.start, entity.end, entity.type)
        current = deduped.get(key)
        if current is None or entity.confidence > current.confidence:
            deduped[key] = entity
    ordered = sorted(deduped.values(), key=lambda e: (e.start, e.end, e.type))

    counts: dict[str, int] = {}
    for entity in ordered:
        counts[entity.type] = counts.get(entity.type, 0) + 1
    logger.info(
        "detect",
        extra={
            "meta": {
                "request_id": getattr(request.state, "request_id", None),
                "text_chars": len(body.text),
                "entity_counts": counts,
            }
        },
    )
    return DetectResponse(entities=ordered, correlation_id=body.correlation_id)


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    # Strip 'input'/'ctx' so request content is never echoed into logs; the
    # sanitized field list is safe to log, the response goes back to the caller.
    errors = [
        {"loc": list(e.get("loc", ())), "msg": e.get("msg"), "type": e.get("type")}
        for e in exc.errors()
    ]
    logger.info(
        "validation error",
        extra={
            "meta": {
                "request_id": getattr(request.state, "request_id", None),
                "fields": [".".join(str(part) for part in e["loc"]) for e in errors],
            }
        },
    )
    return JSONResponse(status_code=422, content={"detail": errors})


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    logger.error(
        "unhandled error",
        exc_info=exc,
        extra={"meta": {"request_id": getattr(request.state, "request_id", None)}},
    )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
