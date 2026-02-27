"""Comparison visualiser for agentshield benchmark results."""
from __future__ import annotations

import json
from pathlib import Path


COMPETITOR_NOTES = {
    "detection_rate": (
        "NeMo Guardrails: ~85-90% detection on OWASP suite (docs, 2024). "
        "LLM Guard: 95%+ with LLM-based semantic layer. "
        "agentshield regex layer intentionally favours precision over recall."
    ),
    "evasion": (
        "Unicode and whitespace evasion patterns from OWASP LLM01 (2023) "
        "and Greshake et al. (arXiv:2302.12173). IGNORECASE is active."
    ),
    "latency": (
        "NeMo Guardrails regex layer: <5ms. "
        "LLM Guard regex layer: <1ms. "
        "Source: GitHub READMEs and docs, 2024."
    ),
}


def _fmt_table(rows: list[tuple[str, str]], title: str) -> None:
    col1_width = max(len(r[0]) for r in rows) + 2
    print(f"\n{'=' * 65}")
    print(f"  {title}")
    print(f"{'=' * 65}")
    for key, value in rows:
        print(f"  {key:<{col1_width}} {value}")


def _load(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)  # type: ignore[return-value]


def display_detection(data: dict[str, object]) -> None:
    rows: list[tuple[str, str]] = [
        ("Precision", str(data.get("precision"))),
        ("Recall", str(data.get("recall"))),
        ("F1", str(data.get("f1"))),
        ("False positive rate", str(data.get("false_positive_rate"))),
        ("True positives", str(data.get("true_positives"))),
        ("False negatives", str(data.get("false_negatives"))),
        ("False positives", str(data.get("false_positives"))),
        ("Scan p50 (ms)", str(data.get("latency_ms", {}).get("p50"))),
        ("Scan p99 (ms)", str(data.get("latency_ms", {}).get("p99"))),
    ]
    _fmt_table(rows, "Detection Rate Results")
    print(f"\n  Competitor: {COMPETITOR_NOTES['detection_rate']}")


def display_evasion(data: dict[str, object]) -> None:
    rows: list[tuple[str, str]] = [
        ("Resistance rate", f"{data.get('evasion_resistance_rate'):.2%}"),
        ("Correct / Total", f"{data.get('correct')} / {data.get('total')}"),
        ("Scan p50 (ms)", str(data.get("latency_ms", {}).get("p50"))),
    ]
    _fmt_table(rows, "Evasion Resistance Results")
    print(f"\n  Competitor: {COMPETITOR_NOTES['evasion']}")


def display_latency(data: dict[str, object]) -> None:
    rows: list[tuple[str, str]] = []
    scanner_stats = data.get("per_scanner_latency_ms", {})
    for scanner_name, stats in scanner_stats.items():
        rows.append((f"{scanner_name} p50 (ms)", str(stats.get("p50_ms"))))
        rows.append((f"{scanner_name} p99 (ms)", str(stats.get("p99_ms"))))
    _fmt_table(rows, "Per-Scanner Latency Results")
    print(f"\n  Competitor: {COMPETITOR_NOTES['latency']}")


def main() -> None:
    results_dir = Path(__file__).parent / "results"
    for fname, display_fn in [
        ("baseline.json", display_detection),
        ("evasion_baseline.json", display_evasion),
        ("latency_baseline.json", display_latency),
    ]:
        data = _load(results_dir / fname)
        if data:
            display_fn(data)  # type: ignore[arg-type]
        else:
            print(f"No {fname} found. Run the corresponding benchmark first.")

    print("\n" + "=" * 65)
    print("  Run all benchmarks:")
    print("    python benchmarks/bench_detection_rate.py")
    print("    python benchmarks/bench_evasion_resistance.py")
    print("    python benchmarks/bench_latency.py")
    print("=" * 65)


if __name__ == "__main__":
    main()
