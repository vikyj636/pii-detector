"""GLiNER2 wrapper: singleton load, chunking, output normalization, thresholds.

The gliner2 package is imported lazily inside _load_model() so the test suite
(which mocks the model) never needs torch/gliner2 installed.

The adapter tolerates the output-shape drift seen across gliner/gliner2
releases; see normalize_ner_output() for the shapes handled.
"""
from __future__ import annotations

import logging
import os
import threading

from ..config import Settings, get_threshold
from ..schemas import Entity

logger = logging.getLogger("pii_detector.ner")

_TEXT_KEYS = ("text", "span", "entity", "value")
_SCORE_KEYS = ("score", "confidence", "prob", "probability")
_LABEL_KEYS = ("label", "type", "entity_type")


def chunk_text(text: str, window: int, overlap: int) -> list[tuple[int, str]]:
    """Split text into overlapping windows, preferring whitespace boundaries.

    Returns (offset, chunk) pairs where offset is the chunk's start in the
    original text. Keeps long inputs inside the model's effective context and
    the overlap prevents entities from being lost at window edges.
    """
    if window <= 0 or len(text) <= window:
        return [(0, text)]
    overlap = max(0, min(overlap, window // 2))
    chunks: list[tuple[int, str]] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + window)
        if end < len(text):
            cut = max(text.rfind(" ", start + window // 2, end), text.rfind("\n", start + window // 2, end))
            if cut > start:
                end = cut
        chunks.append((start, text[start:end]))
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


def _find_occurrences(haystack: str, needle: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    if not needle:
        return spans
    idx = haystack.find(needle)
    while idx != -1:
        spans.append((idx, idx + len(needle)))
        idx = haystack.find(needle, idx + len(needle))
    return spans


def _first(item: dict, keys: tuple[str, ...]):
    for key in keys:
        if key in item and item[key] is not None:
            return item[key]
    return None


def normalize_ner_output(
    raw, chunk: str, requested_labels: set[str]
) -> list[tuple[str, str, int, int, float | None]]:
    """Flatten model output into (text, label, start, end, score|None) tuples.

    Shapes handled:
      * [{"text": ..., "label": ..., "start": ..., "end": ..., "score": ...}, ...]
      * {"entities": {label: [item, ...]}} where item is a string or a dict
      * {label: [item, ...]}
    Offsets are relative to `chunk`; items without offsets are located with
    str.find (every occurrence).
    """
    results: list[tuple[str, str, int, int, float | None]] = []
    if raw is None:
        return results

    def handle_item(label, item) -> None:
        label = str(label).strip().lower()
        if isinstance(item, str):
            if label not in requested_labels:
                return
            for start, end in _find_occurrences(chunk, item):
                results.append((chunk[start:end], label, start, end, None))
            return
        if not isinstance(item, dict):
            return
        item_label = _first(item, _LABEL_KEYS)
        if item_label:
            label = str(item_label).strip().lower()
        if label not in requested_labels:
            return
        raw_score = _first(item, _SCORE_KEYS)
        score = float(raw_score) if raw_score is not None else None
        start, end = item.get("start"), item.get("end")
        entity_text = _first(item, _TEXT_KEYS)
        if isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(chunk):
            results.append((chunk[start:end], label, start, end, score))
        elif isinstance(entity_text, str) and entity_text:
            for s, e in _find_occurrences(chunk, entity_text):
                results.append((chunk[s:e], label, s, e, score))

    if isinstance(raw, dict):
        inner = raw.get("entities") if isinstance(raw.get("entities"), dict) else raw
        for label, items in inner.items():
            if isinstance(items, (list, tuple)):
                for item in items:
                    handle_item(label, item)
            else:
                handle_item(label, items)
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                handle_item(item.get("label", ""), item)
    else:
        logger.warning("unrecognized NER output type %s; ignoring", type(raw).__name__)
    return results


class NERDetector:
    """Thin adapter around a GLiNER2 model instance.

    One instance is created at process startup (see load_singleton) and shared
    across requests. Inference is serialized with a lock: the underlying model
    is not guaranteed thread-safe and Fargate tasks are small, so concurrent
    inference would only thrash the torch thread pool.
    """

    def __init__(self, model, window_chars: int = 1_500, overlap_chars: int = 200):
        self._model = model
        self._lock = threading.Lock()
        self._window_chars = window_chars
        self._overlap_chars = overlap_chars

    @staticmethod
    def _load_model(settings: Settings):
        from gliner2 import GLiNER2  # deferred: heavy import, mocked in tests

        source = settings.model_path if os.path.isdir(settings.model_path) else settings.model_name
        logger.info("loading GLiNER2 model from %s", source)
        return GLiNER2.from_pretrained(source)

    @classmethod
    def load(cls, settings: Settings) -> "NERDetector":
        model = cls._load_model(settings)
        return cls(model, settings.ner_window_chars, settings.ner_overlap_chars)

    def _extract(self, chunk: str, labels: list[str], min_threshold: float):
        """Call the model, tolerating signature drift across gliner2 releases."""
        last_error: TypeError | None = None
        with self._lock:
            for kwargs in (
                {"threshold": min_threshold, "include_confidence": True},
                {"threshold": min_threshold},
                {},
            ):
                try:
                    return self._model.extract_entities(chunk, labels, **kwargs)
                except TypeError as exc:
                    last_error = exc
        raise RuntimeError("model.extract_entities rejected all known call signatures") from last_error

    def detect(self, text: str, labels: list[str], thresholds: dict[str, float]) -> list[Entity]:
        if not text or not labels:
            return []
        requested = {label.lower() for label in labels}
        min_threshold = min(get_threshold(label, thresholds) for label in requested)
        best: dict[tuple[int, int, str], Entity] = {}
        for offset, chunk in chunk_text(text, self._window_chars, self._overlap_chars):
            raw = self._extract(chunk, list(labels), min_threshold)
            for entity_text, label, start, end, score in normalize_ner_output(raw, chunk, requested):
                if score is None:
                    # Model version without per-entity scores: its own filtering at
                    # min_threshold is the only gate, so report that lower bound.
                    confidence = min_threshold
                else:
                    confidence = score
                    if confidence < get_threshold(label, thresholds):
                        continue
                key = (offset + start, offset + end, label)
                entity = Entity(
                    text=entity_text,
                    type=label,
                    start=offset + start,
                    end=offset + end,
                    confidence=round(confidence, 4),
                    source="ner",
                )
                current = best.get(key)
                if current is None or entity.confidence > current.confidence:
                    best[key] = entity
        return list(best.values())


_singleton_lock = threading.Lock()
_detector: NERDetector | None = None
_load_error: str | None = None


def load_singleton(settings: Settings) -> NERDetector:
    """Load the model once per process (module-level singleton)."""
    global _detector, _load_error
    with _singleton_lock:
        if _detector is None:
            try:
                _detector = NERDetector.load(settings)
                _load_error = None
            except Exception as exc:
                _load_error = f"{type(exc).__name__}: {exc}"
                raise
    return _detector


def get_detector() -> NERDetector | None:
    return _detector


def get_load_error() -> str | None:
    return _load_error


def reset_singleton() -> None:
    """Test helper; never called in production."""
    global _detector, _load_error
    with _singleton_lock:
        _detector = None
        _load_error = None
