"""Benchmark: Detection F1, false positive rate, and false negative rate.

Runs the RegexInjectionScanner against the public attack dataset and
computes precision, recall, F1, and false positive rate.

Competitor context
------------------
- NeMo Guardrails (NVIDIA): published detection rate ~85-90% on OWASP
  prompt injection test suite with significant FP rate on benign technical text.
  Source: NeMo Guardrails documentation, 2024.
- LLM Guard (Protect AI): claims 95%+ detection but requires LLM-based scoring
  for the semantic layer; regex layer alone is lower.
  Source: https://github.com/protectai/llm-guard, README 2024.

This benchmark measures the regex-only commodity layer, which is intentionally
conservative (high precision, lower recall) — it pairs with plugin-based
semantic scanners for full coverage.
"""
from __future__ import annotations

import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent / "datasets"))

from agentshield.core.context import ScanContext
from agentshield.core.scanner import ScanPhase
from agentshield.scanners.regex_injection import RegexInjectionScanner
from datasets.attack_dataset import get_all_cases


async def _scan_case(
    scanner: RegexInjectionScanner,
    text: str,
) -> tuple[bool, float]:
    """Scan a single case and return (detected, elapsed_ms).

    Parameters
    ----------
    scanner:
        The scanner to use.
    text:
        Text to scan.

    Returns
    -------
    tuple of (detected as injection, elapsed milliseconds)
    """
    context = ScanContext(
        phase=ScanPhase.INPUT,
        agent_id="bench-agent",
        session_id="bench-session",
    )
    start = time.perf_counter()
    findings = await scanner.scan(text, context)
    elapsed_ms = (time.perf_counter() - start) * 1000
    detected = len(findings) > 0
    return detected, elapsed_ms


async def _run_all(
    scanner: RegexInjectionScanner,
) -> dict[str, object]:
    """Run scanner over all dataset cases and collect metrics."""
    cases = get_all_cases()
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0
    latencies_ms: list[float] = []

    for case in cases:
        detected, elapsed_ms = await _scan_case(scanner, case.text)
        latencies_ms.append(elapsed_ms)

        if case.is_injection and detected:
            true_positives += 1
        elif case.is_injection and not detected:
            false_negatives += 1
        elif not case.is_injection and detected:
            false_positives += 1
        else:
            true_negatives += 1

    n_positives = true_positives + false_negatives
    n_negatives = true_negatives + false_positives

    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0
        else 0.0
    )
    recall = (
        true_positives / n_positives if n_positives > 0 else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    false_positive_rate = (
        false_positives / n_negatives if n_negatives > 0 else 0.0
    )

    sorted_lats = sorted(latencies_ms)
    n = len(sorted_lats)

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "latency_ms": {
            "p50": round(sorted_lats[int(n * 0.50)], 4),
            "p95": round(sorted_lats[min(int(n * 0.95), n - 1)], 4),
            "p99": round(sorted_lats[min(int(n * 0.99), n - 1)], 4),
            "mean": round(statistics.mean(latencies_ms), 4),
        },
    }


def run_benchmark() -> dict[str, object]:
    """Run detection rate benchmark over the public attack dataset.

    Returns
    -------
    dict with precision, recall, F1, FPR, and latency stats.
    """
    scanner = RegexInjectionScanner()
    metrics = asyncio.run(_run_all(scanner))
    metrics["benchmark"] = "detection_rate"
    metrics["scanner"] = scanner.name
    metrics["n_patterns"] = len(scanner.pattern_names)
    metrics["n_positive_cases"] = 10
    metrics["n_negative_cases"] = 10
    metrics["note"] = (
        "Regex-only commodity layer. NeMo Guardrails: ~85-90% detection on OWASP suite "
        "(NeMo Guardrails docs, 2024). LLM Guard: 95%+ with LLM-based semantic layer. "
        "This layer intentionally favours precision over recall; pair with semantic scanners."
    )
    return metrics  # type: ignore[return-value]


if __name__ == "__main__":
    print("Running detection rate benchmark...")
    result = run_benchmark()
    print(json.dumps(result, indent=2))
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    output_path = results_dir / "baseline.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"\nResults saved to {output_path}")
