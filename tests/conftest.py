from __future__ import annotations

import contextlib
import time

import pytest
import yaml
from fastapi.testclient import TestClient

from app.detectors import ner_detector
from app.detectors.ner_detector import NERDetector
from app.main import app

TEST_API_KEY = "test-api-key-123"


class FakeGLiNER2:
    """Stands in for gliner2.GLiNER2.

    Returns canned entities for substrings it knows, in the grouped-dict-with-
    scores output shape. `known` maps substring -> (label, score).
    """

    def __init__(self, known: dict[str, tuple[str, float]] | None = None):
        self.known = (
            known
            if known is not None
            else {
                "Mario Rossi": ("person", 0.82),
                "VeChain": ("organization", 0.91),
                "Via Roma 1, Milano": ("address", 0.66),
            }
        )
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def extract_entities(self, text, labels, threshold=0.5, include_confidence=True):
        self.calls.append((text, tuple(labels)))
        grouped: dict[str, list[dict]] = {}
        for needle, (label, score) in self.known.items():
            start = text.find(needle)
            while start != -1:
                grouped.setdefault(label, []).append(
                    {"text": needle, "start": start, "end": start + len(needle), "score": score}
                )
                start = text.find(needle, start + len(needle))
        return {"entities": grouped}


def wait_until_ready(client: TestClient, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if client.get("/health").status_code == 200:
            return
        time.sleep(0.02)
    raise AssertionError("service did not become ready in time")


@pytest.fixture()
def denylist_file(tmp_path):
    path = tmp_path / "denylist.yaml"
    path.write_text(yaml.safe_dump({"terms": ["VeChain", "TestBrand"]}), encoding="utf-8")
    return path


@pytest.fixture()
def make_client(monkeypatch, denylist_file):
    """Factory for a live TestClient with the NER model mocked (never loads torch)."""
    stack = contextlib.ExitStack()

    def _make(fake_model=None, env: dict[str, str] | None = None, loader=None) -> TestClient:
        model = fake_model if fake_model is not None else FakeGLiNER2()
        monkeypatch.setenv("API_KEY", TEST_API_KEY)
        monkeypatch.setenv("DENYLIST_PATH", str(denylist_file))
        for key, value in (env or {}).items():
            monkeypatch.setenv(key, value)
        ner_detector.reset_singleton()
        monkeypatch.setattr(
            NERDetector, "_load_model", staticmethod(loader or (lambda settings: model))
        )
        return stack.enter_context(TestClient(app))

    yield _make
    stack.close()
    ner_detector.reset_singleton()


@pytest.fixture()
def client(make_client):
    """Ready-to-use client: default fake model, model 'loaded'."""
    c = make_client()
    wait_until_ready(c)
    return c


@pytest.fixture()
def auth_headers():
    return {"X-API-Key": TEST_API_KEY}
