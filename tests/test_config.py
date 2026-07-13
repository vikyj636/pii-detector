from __future__ import annotations

import phonenumbers

from app.config import WORLDWIDE_PHONE_REGIONS, _resolve_phone_regions


def test_passthrough_for_explicit_region_list():
    assert _resolve_phone_regions(("US", "IT")) == ("US", "IT")


def test_single_explicit_region_is_not_a_sentinel():
    assert _resolve_phone_regions(("US",)) == ("US",)


def test_worldwide_sentinel_expands_to_curated_list():
    assert _resolve_phone_regions(("WORLDWIDE",)) == WORLDWIDE_PHONE_REGIONS
    assert _resolve_phone_regions(("worldwide",)) == WORLDWIDE_PHONE_REGIONS  # case-insensitive


def test_all_sentinel_expands_to_every_supported_region():
    resolved = _resolve_phone_regions(("ALL",))
    assert resolved == tuple(sorted(phonenumbers.SUPPORTED_REGIONS))
    assert len(resolved) > len(WORLDWIDE_PHONE_REGIONS)  # strictly broader than the curated list
