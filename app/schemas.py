"""Pydantic request/response models for the detection API."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DetectRequest(BaseModel):
    """Body of POST /detect."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(description="Free text to scan for PII.")
    labels: list[str] | None = Field(
        default=None,
        description="Entity types to detect. Defaults to DEFAULT_LABELS from app/config.py.",
    )
    thresholds: dict[str, float] | None = Field(
        default=None,
        description='Per-label confidence threshold overrides, e.g. {"person": 0.7}.',
    )

    @field_validator("labels")
    @classmethod
    def _normalize_labels(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        labels = [label.strip().lower() for label in value if label and label.strip()]
        if not labels:
            raise ValueError("labels must contain at least one non-empty label when provided")
        return labels

    @field_validator("thresholds")
    @classmethod
    def _validate_thresholds(cls, value: dict[str, float] | None) -> dict[str, float] | None:
        if value is None:
            return None
        normalized: dict[str, float] = {}
        for label, threshold in value.items():
            if not 0.0 <= threshold <= 1.0:
                raise ValueError("thresholds values must be between 0 and 1")
            normalized[label.strip().lower()] = float(threshold)
        return normalized


class Entity(BaseModel):
    """One detected PII span. start/end are character offsets into the request text."""

    text: str
    type: str
    start: int
    end: int
    confidence: float
    source: Literal["ner", "regex"]


class DetectResponse(BaseModel):
    entities: list[Entity]
