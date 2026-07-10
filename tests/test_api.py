"""Full request/response cycle against the FastAPI app with the model mocked."""
from __future__ import annotations

import threading

from tests.conftest import FakeGLiNER2, wait_until_ready

ACCEPTANCE_TEXT = "Mario Rossi, mario@test.com"


def test_detect_requires_api_key(client):
    response = client.post("/detect", json={"text": ACCEPTANCE_TEXT})
    assert response.status_code == 401
    assert "entities" not in response.json()


def test_detect_rejects_wrong_api_key(client):
    response = client.post(
        "/detect", json={"text": ACCEPTANCE_TEXT}, headers={"X-API-Key": "wrong-key"}
    )
    assert response.status_code == 401


def test_health_needs_no_auth(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["model_loaded"] is True


def test_detect_returns_ner_and_regex_entities(client, auth_headers):
    """Mirrors the acceptance criterion: person from NER + email from regex."""
    response = client.post("/detect", json={"text": ACCEPTANCE_TEXT}, headers=auth_headers)
    assert response.status_code == 200
    entities = response.json()["entities"]
    by_type = {e["type"]: e for e in entities}

    person = by_type["person"]
    assert person["source"] == "ner"
    assert person["text"] == "Mario Rossi"

    email = by_type["email"]
    assert email["source"] == "regex"
    assert email["text"] == "mario@test.com"
    assert email["confidence"] == 1.0

    for e in entities:
        assert ACCEPTANCE_TEXT[e["start"] : e["end"]] == e["text"]


def test_denylist_drops_matching_entities(client, auth_headers):
    response = client.post(
        "/detect",
        json={"text": "VeChain and Mario Rossi", "labels": ["organization", "person"]},
        headers=auth_headers,
    )
    types = [e["type"] for e in response.json()["entities"]]
    assert "person" in types
    assert "organization" not in types  # 'VeChain' is denylisted in the test fixture


def test_labels_restrict_detection(client, auth_headers):
    response = client.post(
        "/detect", json={"text": ACCEPTANCE_TEXT, "labels": ["email"]}, headers=auth_headers
    )
    assert [e["type"] for e in response.json()["entities"]] == ["email"]


def test_threshold_override_per_request(client, auth_headers):
    payload = {"text": "Mario Rossi", "labels": ["person"]}  # fake model scores person at 0.82
    ok = client.post("/detect", json=payload, headers=auth_headers)
    assert len(ok.json()["entities"]) == 1

    strict = client.post(
        "/detect", json={**payload, "thresholds": {"person": 0.9}}, headers=auth_headers
    )
    assert strict.json()["entities"] == []


def test_default_threshold_applies_to_other_ner_labels(client, auth_headers):
    payload = {"text": "I live at Via Roma 1, Milano", "labels": ["address"]}  # scored 0.66
    ok = client.post("/detect", json=payload, headers=auth_headers)  # default 0.5 -> kept
    assert len(ok.json()["entities"]) == 1

    strict = client.post(
        "/detect", json={**payload, "thresholds": {"address": 0.7}}, headers=auth_headers
    )
    assert strict.json()["entities"] == []


def test_max_text_length_returns_413(make_client, auth_headers):
    client = make_client(env={"MAX_TEXT_LENGTH": "100"})
    wait_until_ready(client)
    response = client.post("/detect", json={"text": "x" * 101}, headers=auth_headers)
    assert response.status_code == 413


def test_health_503_while_loading_then_200(make_client, auth_headers):
    gate = threading.Event()
    fake = FakeGLiNER2()

    def slow_loader(settings):
        gate.wait(5)
        return fake

    client = make_client(loader=slow_loader)
    try:
        assert client.get("/health").status_code == 503
        response = client.post("/detect", json={"text": "hello"}, headers=auth_headers)
        assert response.status_code == 503
    finally:
        gate.set()
    wait_until_ready(client)
    assert client.get("/health").status_code == 200


def test_unknown_body_fields_rejected(client, auth_headers):
    response = client.post(
        "/detect", json={"text": "x", "threshold": {"person": 1}}, headers=auth_headers
    )
    assert response.status_code == 422


def test_invalid_threshold_value_rejected(client, auth_headers):
    response = client.post(
        "/detect", json={"text": "x", "thresholds": {"person": 1.5}}, headers=auth_headers
    )
    assert response.status_code == 422


def test_request_id_header_roundtrip(client, auth_headers):
    response = client.post(
        "/detect", json={"text": "x"}, headers={**auth_headers, "X-Request-ID": "req-abc-123"}
    )
    assert response.headers["X-Request-ID"] == "req-abc-123"


def test_regex_only_labels_work_and_crypto_is_opt_in(client, auth_headers):
    address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    text = f"wallet {address} and mario@test.com"

    # Default labels: crypto_wallet_address is NOT included
    default = client.post("/detect", json={"text": text}, headers=auth_headers)
    assert "crypto_wallet_address" not in {e["type"] for e in default.json()["entities"]}

    # ...but explicit request works
    explicit = client.post(
        "/detect", json={"text": text, "labels": ["crypto_wallet_address"]}, headers=auth_headers
    )
    assert [e["type"] for e in explicit.json()["entities"]] == ["crypto_wallet_address"]
