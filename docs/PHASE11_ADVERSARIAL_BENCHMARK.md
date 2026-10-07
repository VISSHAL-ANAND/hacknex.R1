# Phase 11 — Adversarial Detection Benchmark

## Objective

Phase 11 is a measurement-first precision/recall hardening phase. The detector is attacked with known attacks, benign lookalikes, missing telemetry, identity collisions, ordering problems, noise and decoys **before** detector logic is changed.

The benchmark distinguishes:

- **validated** — deterministic incident gate passed
- **hypothesis** — incomplete evidence surfaced without validating an incident
- **watchlist** — suspicious but below the incident gate
- **suppressed** — no actionable campaign hypothesis

### Adversarial matrix

| Case | Ground truth | Purpose |
|---|---|---|
| baseline_attack | malicious | Full-chain control |
| noisy_attack | malicious | Interleaved benign telemetry |
| out_of_order_input | malicious | Input ordering must not matter |
| decoy_attack | malicious | Distractor evidence |
| missing_telemetry | malicious | Recall pressure / partial evidence |
| clean_control | benign | Basic suppression |
| slow_attack | benign control | Fixed-window boundary |
| reversed_order | benign control | Temporal causality |
| mismatched_entities | benign control | Entity consistency |
| shared_ip_collision | benign control | IP-only stitching |
| authorized_transfer | benign | Explicit authorization suppression |
| benign_usb_lookalike | benign | Look-alike attack chain |
| benign_backup | benign | Large-volume benign transfer |
| legitimate_sensitive_access | benign | Sensitive access without attack |
| partial_attack | benign/control | Hypothesis boundary |

## Metrics

The benchmark records precision, recall, F1, false-positive rate and false-negative rate for **validated incidents only**. Hypotheses are tracked separately so incomplete evidence does not inflate incident recall.

No quality threshold is claimed from the baseline run. The first run is deliberately a break test. A later fix must improve the measured failure mode and preserve all existing Phase 2–10 regressions.

## Gate

Phase 11 cannot advance until:

1. adversarial benchmark has been executed;
2. every failure has a root-cause classification;
3. fixes are supported by evidence, not scenario-specific hardcoding;
4. full regression remains green;
5. final precision/recall thresholds are explicitly recorded and reproducible.
