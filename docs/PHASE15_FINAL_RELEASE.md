# Phase 15 — Final Release / Judge Gate

This is the release boundary after deterministic detection, evidence coverage, adversarial testing, confidence/drift testing, unseen-attack generalization, and robustness stress.

Required gates:
- Phase 2–14 regression remains green.
- Phase 13 unseen malicious complete campaigns remain validated with zero validated benign FPR in its benchmark.
- Phase 14 large-haystack stress remains validated for the attack and silent for benign controls.
- Final targeted regression and full pytest pass.
- Frontend JavaScript syntax check passes.

The Raw CERT workflow remains a separate externally-triggered gate by design; its completed benchmark is documented in Phase 8 and it is not treated as a normal PR failure.

No claim here implies production-grade recall on arbitrary real-world attacks. The final claim is that the implemented evidence-first contract is reproducible and regression-gated against the project's measured benchmarks.
