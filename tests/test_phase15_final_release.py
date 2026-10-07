from pathlib import Path

from backend.detector import analyze
from backend.models import SecurityEvent

ROOT = Path(__file__).resolve().parents[1]


def _scenario(name: str) -> list[SecurityEvent]:
    import json

    scenarios = json.loads((ROOT / "backend/data/scenarios.json").read_text(encoding="utf-8"))
    return [SecurityEvent.model_validate(item) for item in scenarios[name]]


def test_final_release_contract():
    required = [
        "backend/detector.py",
        "backend/reconstructor.py",
        "backend/models.py",
        "backend/investigator.py",
        "tests/test_phase11_adversarial_benchmark.py",
        "tests/test_phase12_confidence_drift.py",
        "tests/test_phase13_generalization_benchmark.py",
        "tests/test_phase14_final_robustness.py",
        "docs/PHASE8_CERT_RAW_GATE.md",
        "docs/PHASE13_GENERALIZATION.md",
        "docs/PHASE14_FINAL_ROBUSTNESS.md",
        ".github/workflows/phase13.yml",
        ".github/workflows/phase14.yml",
    ]
    missing = [path for path in required if not (ROOT / path).exists()]
    assert not missing, missing

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for marker in [
        "Phase 13",
        "Phase 14",
        "Phase 15",
        "Evidence first, explanation second.",
        "4.29% is compatibility coverage, NOT detector recall.",
    ]:
        assert marker in readme, marker


def test_final_release_behavioral_contract():
    """
    Final release must preserve the judge-facing behavior, not only file presence.

    This is intentionally small and deterministic. Deep adversarial/generalization/
    stress coverage remains owned by Phases 11–14.
    """
    full = analyze(_scenario("full_attack"))
    clean = analyze(_scenario("clean_control"))
    partial = analyze(_scenario("partial_attack"))
    mismatch = analyze(_scenario("mismatched_entities"))
    authorized = analyze(_scenario("authorized_transfer"))

    assert full.correlated_incidents == 1
    assert full.incidents[0].status == "validated"
    assert all(stage.evidence for stage in full.incidents[0].stages)

    assert clean.correlated_incidents == 0
    assert clean.suppressed is True

    assert partial.correlated_incidents == 0
    assert partial.campaign_hypotheses

    assert mismatch.correlated_incidents == 0
    assert mismatch.suppressed is True

    assert authorized.correlated_incidents == 0
    assert authorized.suppressed is True
