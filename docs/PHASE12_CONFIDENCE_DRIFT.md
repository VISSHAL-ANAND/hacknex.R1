# Phase 12 — Confidence Calibration + Drift Robustness

## Objective

Attack the deterministic detector's confidence and temporal assumptions before adding adaptive behavior.

Phase 11 established adversarial campaign coverage and cross-identity fail-closed behavior. Phase 12 asks a different question:

> When evidence quality or attacker timing changes, does the detector's confidence still communicate the real strength of the evidence?

## Discovery benchmark

The frozen benchmark contains:
- baseline complete attack
- clock-drifted attack
- long-spacing attack with ordered stages beyond the current fixed 30-minute cluster horizon
- noisy long-spacing attack
- ambiguous partial evidence with weakened entity corroboration
- clean benign control
- benign backup
- authorized transfer

The discovery gates are intentionally strict:
1. long-spacing attack validated recall = 1.0
2. benign validated false-positive rate = 0.0
3. complete-vs-ambiguous confidence gap >= 0.10

A failure is a measurement result, not a reason to loosen the gate.

## Why this matters

The detector currently combines fixed temporal windows with deterministic confidence components. A confidence number must fall when evidence is incomplete, contradictory, or weakly connected. Conversely, an attacker should not evade campaign reconstruction merely by stretching otherwise coherent stages across a longer period.

## Required engineering loop

BUILD → TEST → BREAK → FIX → REGRESSION → GATE

No Phase 13 work starts until the Phase 12 gates pass on CI and the complete regression suite remains green.

## Non-goals

- no LLM-based confidence
- no automatic retraining
- no synthetic benchmark-only detector exceptions
- no using ATT&CK labels as detection evidence
