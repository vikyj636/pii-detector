from __future__ import annotations

from pathlib import Path

import pytest

from app.detectors.regex_detector import RegexDetector, iban_checksum_valid, luhn_valid

SECRET_PATTERNS = Path(__file__).resolve().parents[1] / "app" / "config" / "secret_patterns.yaml"


@pytest.fixture(scope="module")
def detector():
    return RegexDetector(SECRET_PATTERNS, phone_regions=("US", "GB"))


def assert_spans_match(text, entities):
    for e in entities:
        assert text[e.start : e.end] == e.text


def test_emails(detector):
    text = "contact mario@test.com or admin@sub.example.co.uk today"
    entities = detector.detect(text, {"email"})
    assert sorted(e.text for e in entities) == ["admin@sub.example.co.uk", "mario@test.com"]
    assert all(e.type == "email" and e.source == "regex" and e.confidence == 1.0 for e in entities)
    assert_spans_match(text, entities)


def test_phone_international_and_national(detector):
    text = "call +44 20 7946 0958 or (415) 555-2671 tomorrow"
    entities = detector.detect(text, {"phone_number"})
    assert len(entities) == 2
    assert all(e.type == "phone_number" for e in entities)
    assert_spans_match(text, entities)


def test_phone_ignores_plain_numbers(detector):
    assert detector.detect("order #123456 costs 99 dollars", {"phone_number"}) == []


def test_luhn():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


def test_credit_card_with_separators(detector):
    text = "pay with 4111 1111 1111 1111 now"
    entities = detector.detect(text, {"credit_card"})
    assert [e.text for e in entities] == ["4111 1111 1111 1111"]
    assert_spans_match(text, entities)


def test_credit_card_luhn_rejects(detector):
    assert detector.detect("number 4111111111111112 fails", {"credit_card"}) == []


def test_iban_checksum():
    assert iban_checksum_valid("GB82WEST12345698765432")
    assert iban_checksum_valid("DE89 3704 0044 0532 0130 00")
    assert not iban_checksum_valid("GB82WEST12345698765431")


def test_iban(detector):
    text = "wire to DE89 3704 0044 0532 0130 00 by friday"
    entities = detector.detect(text, {"iban"})
    assert len(entities) == 1 and entities[0].type == "iban"
    assert_spans_match(text, entities)
    assert detector.detect("wire to DE89 3704 0044 0532 0130 01", {"iban"}) == []


def test_ip_addresses(detector):
    text = "server 192.168.1.10 and 2001:db8::1 but not 999.1.1.1 or 1.2.3"
    entities = detector.detect(text, {"ip_address"})
    assert sorted(e.text for e in entities) == ["192.168.1.10", "2001:db8::1"]
    assert_spans_match(text, entities)


def test_aws_and_openai_keys(detector):
    text = "creds: AKIAIOSFODNN7EXAMPLE plus sk-abcdefghijklmnopqrstuvwx"
    entities = detector.detect(text, {"api_key"})
    assert {e.text for e in entities} == {"AKIAIOSFODNN7EXAMPLE", "sk-abcdefghijklmnopqrstuvwx"}
    assert all(e.type == "api_key" for e in entities)


def test_github_token(detector):
    token = "ghp_" + "A1b2C3d4" * 5  # 40 chars after the prefix
    text = f"use {token} here"
    entities = detector.detect(text, {"access_token"})
    assert [e.text for e in entities] == [token]
    assert_spans_match(text, entities)


def test_secret_assignment_captures_value_only(detector):
    text = 'config: password = "hunter2hunter2hunter2"'
    entities = detector.detect(text, {"secret"})
    assert [e.text for e in entities] == ["hunter2hunter2hunter2"]
    assert_spans_match(text, entities)


def test_crypto_wallet(detector):
    address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    text = f"send to {address} please"
    entities = detector.detect(text, {"crypto_wallet_address"})
    assert [e.text for e in entities] == [address]
    assert_spans_match(text, entities)
    # 64-hex transaction hashes must not match
    assert detector.detect("tx 0x" + "ab" * 32, {"crypto_wallet_address"}) == []


def test_only_requested_labels_run(detector):
    text = "mario@test.com 4111111111111111 192.168.1.1"
    entities = detector.detect(text, {"email"})
    assert {e.type for e in entities} == {"email"}
