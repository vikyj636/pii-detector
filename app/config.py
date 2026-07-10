"""Central configuration: default labels, per-label thresholds, env parsing.

NOTE: the sibling directory app/config/ holds *data files only* (denylist.yaml,
secret_patterns.yaml). It must never contain __init__.py or any .py file, or it
would shadow this module on import.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

APP_DIR = Path(__file__).resolve().parent
CONFIG_DIR = APP_DIR / "config"

if (CONFIG_DIR / "__init__.py").exists():  # pragma: no cover
    raise RuntimeError("app/config/ must not contain __init__.py (it would shadow app/config.py)")

DEFAULT_MODEL_NAME = "fastino/gliner2-privacy-filter-PII-multi"

# Labels handled by the deterministic regex detector. Any other requested label
# is passed to the NER model (GLiNER2 accepts arbitrary label strings).
REGEX_LABELS = frozenset(
    {
        "email",
        "phone_number",
        "iban",
        "credit_card",
        "ip_address",
        "api_key",
        "secret",
        "access_token",
        "crypto_wallet_address",
    }
)

DEFAULT_NER_LABELS = (
    "person",
    "full_name",
    "address",
    "street_address",
    "city",
    "organization",
)

# crypto_wallet_address is deliberately NOT in the defaults: in a blockchain
# product, on-chain addresses are frequently legitimate content rather than
# incidental PII. Opt in via INCLUDE_CRYPTO_WALLET_IN_DEFAULT_LABELS=true, or
# request the label explicitly per request.
DEFAULT_REGEX_LABELS = (
    "email",
    "phone_number",
    "iban",
    "credit_card",
    "ip_address",
    "api_key",
    "secret",
    "access_token",
)

# The GLiNER2 privacy model over-predicts on proper nouns (per its model card),
# so person-like labels get a higher default threshold.
DEFAULT_THRESHOLDS = {
    "person": 0.7,
    "full_name": 0.7,
}
FALLBACK_THRESHOLD = 0.5


def _env_str(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _env_list(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    api_key: str
    num_threads: int = 1
    log_level: str = "INFO"
    model_path: str = "/opt/model"
    model_name: str = DEFAULT_MODEL_NAME
    denylist_path: str = str(CONFIG_DIR / "denylist.yaml")
    secret_patterns_path: str = str(CONFIG_DIR / "secret_patterns.yaml")
    phone_regions: tuple[str, ...] = ("US",)
    max_text_length: int = 50_000
    include_crypto_wallet_in_defaults: bool = False
    ner_window_chars: int = 1_500
    ner_overlap_chars: int = 200

    @classmethod
    def from_env(cls) -> "Settings":
        api_key = os.environ.get("API_KEY", "").strip()
        if not api_key:
            raise RuntimeError(
                "API_KEY environment variable is required. In ECS it must be injected "
                "from AWS Secrets Manager via the task definition 'secrets' block; "
                "locally pass -e API_KEY=... to docker run."
            )
        return cls(
            api_key=api_key,
            num_threads=max(1, _env_int("NUM_THREADS", 1)),
            log_level=_env_str("LOG_LEVEL", "INFO").upper(),
            model_path=_env_str("MODEL_PATH", "/opt/model"),
            model_name=_env_str("MODEL_NAME", DEFAULT_MODEL_NAME),
            denylist_path=_env_str("DENYLIST_PATH", str(CONFIG_DIR / "denylist.yaml")),
            secret_patterns_path=_env_str(
                "SECRET_PATTERNS_PATH", str(CONFIG_DIR / "secret_patterns.yaml")
            ),
            phone_regions=tuple(r.upper() for r in _env_list("PHONE_REGIONS", ("US",))),
            max_text_length=_env_int("MAX_TEXT_LENGTH", 50_000),
            include_crypto_wallet_in_defaults=_env_bool(
                "INCLUDE_CRYPTO_WALLET_IN_DEFAULT_LABELS", False
            ),
            ner_window_chars=_env_int("NER_WINDOW_CHARS", 1_500),
            ner_overlap_chars=_env_int("NER_OVERLAP_CHARS", 200),
        )

    @property
    def default_labels(self) -> list[str]:
        labels = list(DEFAULT_NER_LABELS) + list(DEFAULT_REGEX_LABELS)
        if self.include_crypto_wallet_in_defaults:
            labels.append("crypto_wallet_address")
        return labels


def resolve_thresholds(overrides: dict[str, float] | None) -> dict[str, float]:
    """Defaults from this module overlaid with per-request overrides."""
    thresholds = dict(DEFAULT_THRESHOLDS)
    if overrides:
        thresholds.update({label.lower(): value for label, value in overrides.items()})
    return thresholds


def get_threshold(label: str, thresholds: dict[str, float]) -> float:
    return thresholds.get(label.lower(), FALLBACK_THRESHOLD)


def load_denylist(path: str | Path) -> frozenset[str]:
    """Case-insensitive denylist of terms that must never be reported as PII."""
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    terms = data.get("terms") or []
    if not isinstance(terms, list):
        raise RuntimeError(f"denylist file {path} must contain a top-level 'terms' list")
    return frozenset(str(term).strip().lower() for term in terms if str(term).strip())


class _JsonFormatter(logging.Formatter):
    """Structured metadata-only log lines. Request/entity text must never reach these."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        meta = getattr(record, "meta", None)
        if isinstance(meta, dict):
            payload.update(meta)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    # uvicorn's access log is disabled via --no-access-log; keep its error logs.
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).setLevel(level)
