# Phase 13 — Independent Campaign Generalization Benchmark

## Purpose

Phase 13 answers a narrower and more defensible question:

> **Can the deterministic detector recognize independently constructed attack campaigns that satisfy the project's declared evidence contract, rather than merely recognizing mutations of the known demo fixture?**

This is a held-out synthetic benchmark. Malicious campaigns are constructed directly in the test and **do not clone, mutate, or import `backend/data/scenarios.json`**.

### What this proves

The benchmark measures generalization across independently chosen:

- users, devices and IPs
- applications and resources
- event IDs
- timing
- session continuity
- removable-media evidence forms
- decoy telemetry
- simultaneous campaigns

It also includes benign controls and an explicit out-of-contract network-exfiltration case.

### What this does NOT prove

This benchmark does **not** establish:

- recall on arbitrary real-world attack campaigns
- recall on attack techniques outside the current evidence contract
- production prevalence-weighted performance
- immunity to previously unknown attacker behavior

Public/raw dataset validation remains separate. The CERT compatibility figure is not detector recall.

## Gate

For independently constructed campaigns **inside the declared identity → sensitive-data → removable-media evidence contract**:

- validated recall = **100%**
- validated benign FPR = **0%**

For the explicit out-of-contract network-exfiltration case:

- **must not become a validated incident**

This boundary test is reported separately rather than being incorrectly counted as a detector false negative.

## Why this is stronger than the previous benchmark

The previous Phase 13 implementation started most cases from `full_attack` and applied transformations. That was useful structural robustness testing, but it did not justify a broad "unseen attack" claim.

The current benchmark constructs each malicious campaign independently. It therefore tests a different failure mode: whether the detector is overfit to the exact fixture's user/device/application/timestamp/resource values.

The benchmark still deliberately stays within the detector's declared evidence contract. A detector cannot honestly be credited for detecting a modality it was never designed to recognize.

## Evaluation hierarchy

1. **Phase 11 — Adversarial precision/coverage:** attacks, decoys, missing telemetry, identity contamination and haystacks.
2. **Phase 12 — Drift robustness:** bounded temporal drift and confidence behavior.
3. **Phase 13 — Independent campaign generalization:** independently constructed in-contract campaigns.
4. **Phase 14 — Stress robustness:** 20,000-event haystacks, duplicate events and reversed input.
5. **Phase 15 — Final release gate:** repository, tests and release contract.

Loop: **BUILD → BREAK → MEASURE → FIX → REGRESSION → GATE.**
