# Phase 13 — Generalization / Unseen Attack Benchmark

Purpose: test whether deterministic campaign reconstruction generalizes beyond the scenario shapes used in earlier phases.

The benchmark attacks structure, benign interleaving, decoys, telemetry variation, simultaneous campaigns, benign lookalikes, and haystack size.

Gate: 100% validated recall on malicious complete campaigns and 0% validated false-positive rate on benign controls. Hypotheses are measured separately and are not counted as validated incidents.

Loop: BUILD → BREAK → MEASURE → FIX → REGRESSION → GATE.
