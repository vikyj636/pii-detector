"""Deterministic detectors for structured, format-constrained PII.

Zero inference: regular expressions plus checksum validation (Luhn for credit
cards, mod-97 for IBANs) and libphonenumber for phone numbers. Vendor secret
patterns live in app/config/secret_patterns.yaml so the list can grow without
code changes. All matches are emitted with confidence 1.0 and source="regex".
"""
from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path

import phonenumbers
import yaml

from ..schemas import Entity

logger = logging.getLogger("pii_detector.regex")

EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}\b"
)

# Candidate card numbers: 13-19 digits, optionally separated by single spaces
# or dashes. Luhn-validated afterwards to cut false positives.
CREDIT_CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")

# 2-letter country + 2 check digits + body either compact or in groups of 4
# (the standard presentation format), ending in a short final group. Keeping the
# groups rigid stops the match from swallowing following words; the mod-97
# checksum validated afterwards kills remaining false positives.
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Za-z0-9]{4}){2,7}(?: ?[A-Za-z0-9]{1,4})?\b")

_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
IPV4_RE = re.compile(rf"(?<![\w.]){_IPV4_OCTET}(?:\.{_IPV4_OCTET}){{3}}(?![\w.])")
# Loose candidate; ipaddress.ip_address() decides what is really IPv6.
IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:.])")

# EVM-style account address (0x + 40 hex). The negative lookahead keeps 64-hex
# transaction hashes from partially matching. See README: in a blockchain
# product these are often legitimate payload, so the label is opt-in.
CRYPTO_WALLET_RE = re.compile(r"(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9A-Za-z])")

# Italian tax code: 6 letters, 2 digits, 1 letter, 2 digits, 1 letter, 3 digits,
# 1 letter. Structure-checked here; the mod-26 checksum (codice_fiscale_valid)
# does the real false-positive filtering.
CODICE_FISCALE_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z]{6}\d{2}[A-Za-z]\d{2}[A-Za-z]\d{3}[A-Za-z](?![A-Za-z0-9])"
)

# Odd/even position conversion tables for the check-character algorithm.
# Verified against an authoritative source rather than trusted from memory —
# a commonly-circulated "example" codice fiscale turned out to not actually be
# checksum-valid, which would have silently broken this if copied blind.
_CF_ODD_DIGITS = {"0": 1, "1": 0, "2": 5, "3": 7, "4": 9, "5": 13, "6": 15, "7": 17, "8": 19, "9": 21}
_CF_ODD_LETTERS = {
    c: v
    for c, v in zip(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        [1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23],
    )
}
_CF_ODD_TABLE = {**_CF_ODD_DIGITS, **_CF_ODD_LETTERS}
_CF_EVEN_TABLE = {str(d): d for d in range(10)} | {
    c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}
_CF_VALID_MONTH_LETTERS = frozenset("ABCDEHLMPRST")


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def codice_fiscale_checksum_valid(candidate: str) -> bool:
    cf = candidate.upper()
    if len(cf) != 16:
        return False
    body, check = cf[:15], cf[15]
    if body[8] not in _CF_VALID_MONTH_LETTERS:  # position 9 (1-indexed): month code
        return False
    total = 0
    for index, char in enumerate(body):
        # Position 1 (index 0) is odd; odd 1-indexed positions are even indices.
        table = _CF_ODD_TABLE if index % 2 == 0 else _CF_EVEN_TABLE
        if char not in table:
            return False
        total += table[char]
    expected = chr(ord("A") + total % 26)
    return check == expected


def iban_checksum_valid(candidate: str) -> bool:
    compact = candidate.replace(" ", "").upper()
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    digits = ""
    for char in rearranged:
        if char.isdigit():
            digits += char
        elif char.isalpha():
            digits += str(ord(char) - ord("A") + 10)
        else:
            return False
    return int(digits) % 97 == 1


class RegexDetector:
    """Structured-PII detection. Patterns compile once at startup; stateless afterwards."""

    def __init__(self, secret_patterns_path: str | Path, phone_regions: tuple[str, ...] = ("US",)):
        self.phone_regions = tuple(phone_regions) or ("US",)
        self.secret_patterns = self._load_secret_patterns(secret_patterns_path)
        self.secret_labels = frozenset(label for _, label, _, _ in self.secret_patterns)

    @staticmethod
    def _load_secret_patterns(path: str | Path) -> list[tuple[str, str, re.Pattern, int]]:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        patterns: list[tuple[str, str, re.Pattern, int]] = []
        for entry in data.get("patterns") or []:
            name = entry.get("name")
            label = str(entry.get("label", "")).strip().lower()
            regex = entry.get("regex")
            group = int(entry.get("group", 0))
            if not name or not label or not regex:
                raise RuntimeError(f"secret pattern entry {name!r} needs name, label and regex")
            patterns.append((name, label, re.compile(regex), group))
        logger.info("loaded %d secret patterns from %s", len(patterns), path)
        return patterns

    def detect(self, text: str, labels: set[str]) -> list[Entity]:
        entities: list[Entity] = []
        if "email" in labels:
            entities.extend(self._emails(text))
        if "phone_number" in labels:
            entities.extend(self._phone_numbers(text))
        if "iban" in labels:
            entities.extend(self._ibans(text))
        if "credit_card" in labels:
            entities.extend(self._credit_cards(text))
        if "ip_address" in labels:
            entities.extend(self._ip_addresses(text))
        if "crypto_wallet_address" in labels:
            entities.extend(self._crypto_wallets(text))
        if "codice_fiscale" in labels:
            entities.extend(self._codice_fiscale(text))
        requested_secret_labels = labels & self.secret_labels
        if requested_secret_labels:
            entities.extend(self._secrets(text, requested_secret_labels))
        return entities

    @staticmethod
    def _entity(text: str, type_: str, start: int, end: int) -> Entity:
        return Entity(
            text=text[start:end], type=type_, start=start, end=end, confidence=1.0, source="regex"
        )

    def _emails(self, text: str) -> list[Entity]:
        return [self._entity(text, "email", m.start(), m.end()) for m in EMAIL_RE.finditer(text)]

    def _phone_numbers(self, text: str) -> list[Entity]:
        entities: list[Entity] = []
        spans: list[tuple[int, int]] = []
        for region in self.phone_regions:
            try:
                matcher = phonenumbers.PhoneNumberMatcher(text, region)
                matches = list(matcher)
            except Exception:
                logger.warning("phone matching failed for region %r; skipping", region)
                continue
            for match in matches:
                if any(match.start < end and start < match.end for start, end in spans):
                    continue  # same number already found via another region
                spans.append((match.start, match.end))
                entities.append(self._entity(text, "phone_number", match.start, match.end))
        return entities

    def _ibans(self, text: str) -> list[Entity]:
        return [
            self._entity(text, "iban", m.start(), m.end())
            for m in IBAN_RE.finditer(text)
            if iban_checksum_valid(m.group())
        ]

    def _credit_cards(self, text: str) -> list[Entity]:
        entities: list[Entity] = []
        for m in CREDIT_CARD_RE.finditer(text):
            digits = re.sub(r"[ -]", "", m.group())
            if 13 <= len(digits) <= 19 and luhn_valid(digits):
                entities.append(self._entity(text, "credit_card", m.start(), m.end()))
        return entities

    def _ip_addresses(self, text: str) -> list[Entity]:
        # The IPv4 pattern fully constrains octets to 0-255; no re-validation needed.
        entities = [self._entity(text, "ip_address", m.start(), m.end()) for m in IPV4_RE.finditer(text)]
        for m in IPV6_CANDIDATE_RE.finditer(text):
            try:
                parsed = ipaddress.ip_address(m.group())
            except ValueError:
                continue
            if parsed.version == 6:
                entities.append(self._entity(text, "ip_address", m.start(), m.end()))
        return entities

    def _crypto_wallets(self, text: str) -> list[Entity]:
        return [
            self._entity(text, "crypto_wallet_address", m.start(), m.end())
            for m in CRYPTO_WALLET_RE.finditer(text)
        ]

    def _codice_fiscale(self, text: str) -> list[Entity]:
        return [
            self._entity(text, "codice_fiscale", m.start(), m.end())
            for m in CODICE_FISCALE_RE.finditer(text)
            if codice_fiscale_checksum_valid(m.group())
        ]

    def _secrets(self, text: str, labels: set[str]) -> list[Entity]:
        entities: list[Entity] = []
        for _, label, pattern, group in self.secret_patterns:
            if label not in labels:
                continue
            for m in pattern.finditer(text):
                try:
                    start, end = m.span(group)
                except (IndexError, re.error):
                    start, end = m.span()
                if start >= 0 and end > start:  # span is (-1, -1) for a non-participating group
                    entities.append(self._entity(text, label, start, end))
        return entities
