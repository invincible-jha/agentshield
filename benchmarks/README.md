# agentshield Benchmarks

Reproducible benchmark suite measuring detection F1, evasion resistance, and per-scanner latency.

## Quick Start

```bash
cd repos/agentshield
python benchmarks/bench_detection_rate.py
python benchmarks/bench_evasion_resistance.py
python benchmarks/bench_latency.py
python benchmarks/compare.py
```

## Benchmarks

### bench_detection_rate.py

**What it measures:** Precision, recall, F1, and false-positive rate against a public attack dataset.

**Dataset:** `datasets/attack_dataset.py` — 10 positive cases (injection) + 10 negative cases (benign).
All cases are drawn from publicly published academic sources (OWASP LLM01 2023, arXiv:2302.12173,
arXiv:2211.09527). No novel attack payloads are included.

**Key metrics:**
- `f1` — primary detection quality metric
- `false_positive_rate` — rate at which benign inputs are flagged

**Competitor reference:**
- NeMo Guardrails: ~85-90% detection on OWASP suite (NeMo docs, 2024)
- LLM Guard: 95%+ with LLM-based semantic layer (GitHub README, 2024)

Note: agentshield's regex layer is intentionally high-precision (conservative).
It pairs with plugin-based semantic scanners for full coverage.

---

### bench_evasion_resistance.py

**What it measures:** Correctness rate when known evasion techniques are applied.

**Techniques tested:**
1. Unicode bidirectional control characters (U+202E RTLO, U+200B ZWSP)
2. Excessive whitespace padding
3. ALL-CAPS variations (IGNORECASE check)
4. Benign lookalike sentences (true-negative verification)

**Key metrics:**
- `evasion_resistance_rate` — fraction of cases correctly classified

---

### bench_latency.py

**What it measures:** Wall-clock scan latency (p50/p95/p99) per scanner and for the full pipeline.

**Scanners measured:**
- `regex_injection` — prompt injection patterns
- `pii_detector` — PII detection
- `credential_detector` — API key/credential detection
- `full_pipeline_default` — all built-in scanners combined

**Key metrics:**
- `p50_ms`, `p99_ms` per scanner

**Competitor reference:**
- NeMo Guardrails regex layer: <5ms
- LLM Guard regex layer: <1ms

---

## Security Policy

This benchmark suite adheres strictly to the AumOS security guidelines:
- Only defensive measurement code is included
- No novel payloads are generated or stored
- All positive test cases reference published academic/OWASP sources
- The dataset uses ABSTRACT structural descriptions, not complete injection strings

## Competitor Numbers (public only)

| Competitor | Metric | Value | Source |
|------------|--------|-------|--------|
| NeMo Guardrails | Detection rate | 85-90% | NeMo Guardrails docs, 2024 |
| LLM Guard | Detection rate (with LLM) | 95%+ | GitHub README, 2024 |
| NeMo Guardrails | Regex latency | <5ms | NeMo docs |
| LLM Guard | Regex latency | <1ms | GitHub README |
