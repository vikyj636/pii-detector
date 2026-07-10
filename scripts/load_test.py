#!/usr/bin/env python3
"""Async load test for the PII detection service.

Fires N total POST /detect requests with bounded concurrency and prints a
latency summary (p50/p95/p99/max), throughput, and per-status counts.

Examples:
  # Local container
  python scripts/load_test.py --url http://localhost:8000 --api-key "$API_KEY" -n 200 -c 8

  # Deployed ALB endpoint (use your DNS name that matches the ACM cert)
  python scripts/load_test.py --url https://pii.example.com --api-key "$API_KEY" -n 500 -c 20

See the README for how to turn these numbers into cpu/memory/desired_count changes.
"""
from __future__ import annotations

import argparse
import asyncio
import math
import os
import statistics
import sys
import time

try:
    import httpx
except ImportError:
    sys.exit("httpx is required: pip install httpx  (or pip install -r requirements-dev.txt)")

DEFAULT_TEXT = (
    "Hi, this is Mario Rossi from Milano. You can reach me at mario.rossi@example.com "
    "or +1 415 555 2671. My card is 4111 1111 1111 1111 and my IBAN is "
    "DE89 3704 0044 0532 0130 00. The server is 192.168.1.10, key AKIAIOSFODNN7EXAMPLE."
)


def percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return math.nan
    rank = max(1, math.ceil(pct / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


async def one_request(client, url, headers, payload, results, errors, semaphore):
    async with semaphore:
        started = time.perf_counter()
        try:
            response = await client.post(url, headers=headers, json=payload)
        except Exception as exc:  # timeouts, connection failures
            errors.append(type(exc).__name__)
            return None
        elapsed_ms = (time.perf_counter() - started) * 1000
        results.append((response.status_code, elapsed_ms))
        if response.status_code == 200:
            return len(response.json().get("entities", []))
        return None


async def run(args) -> int:
    url = args.url.rstrip("/") + "/detect"
    headers = {"X-API-Key": args.api_key}
    payload = {"text": args.text}
    semaphore = asyncio.Semaphore(args.concurrency)
    results: list[tuple[int, float]] = []
    errors: list[str] = []

    started = time.perf_counter()
    async with httpx.AsyncClient(timeout=args.timeout, verify=not args.insecure) as client:
        entity_counts = await asyncio.gather(
            *(
                one_request(client, url, headers, payload, results, errors, semaphore)
                for _ in range(args.requests)
            )
        )
    wall = time.perf_counter() - started

    by_status: dict[int, int] = {}
    for status, _ in results:
        by_status[status] = by_status.get(status, 0) + 1
    latencies = sorted(ms for status, ms in results if status == 200)
    ok_entity_counts = [c for c in entity_counts if c is not None]

    print(
        f"\nrequests: {args.requests}  concurrency: {args.concurrency}  "
        f"wall: {wall:.1f}s  throughput: {len(results) / wall:.1f} req/s"
    )
    print(f"status counts: {by_status or {}}  transport errors: {len(errors)}")
    if errors:
        error_summary: dict[str, int] = {}
        for name in errors:
            error_summary[name] = error_summary.get(name, 0) + 1
        print(f"error types: {error_summary}")
    if latencies:
        print("latency (ms), HTTP 200 only:")
        print(f"  p50:  {percentile(latencies, 50):8.1f}")
        print(f"  p95:  {percentile(latencies, 95):8.1f}")
        print(f"  p99:  {percentile(latencies, 99):8.1f}")
        print(f"  max:  {latencies[-1]:8.1f}")
        print(f"  mean: {statistics.fmean(latencies):8.1f}")
    if ok_entity_counts:
        print(f"avg entities per 200 response: {statistics.fmean(ok_entity_counts):.1f}")

    return 0 if by_status.get(200, 0) == args.requests else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument(
        "--api-key",
        default=os.environ.get("PII_API_KEY", ""),
        help="X-API-Key value (or set PII_API_KEY)",
    )
    parser.add_argument("-n", "--requests", type=int, default=100)
    parser.add_argument("-c", "--concurrency", type=int, default=8)
    parser.add_argument("--text", default=DEFAULT_TEXT)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument(
        "--insecure", action="store_true", help="skip TLS verification (raw ALB DNS name)"
    )
    args = parser.parse_args()
    if not args.api_key:
        parser.error("--api-key (or PII_API_KEY env var) is required")
    sys.exit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
