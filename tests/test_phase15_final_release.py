from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_final_release_contract():
    required = [
        "backend/detector.py",
        "backend/reconstructor.py",
        "backend/models.py",
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
    phase13 = (ROOT / "docs/PHASE13_GENERALIZATION.md").read_text(encoding="utf-8")
    phase13_test = (ROOT / "tests/test_phase13_generalization_benchmark.py").read_text(encoding="utf-8")

    for marker in ["Phase 13", "Phase 14", "Phase 15", "Evidence first, explanation second."]:
        assert marker in readme, marker

    # Release claims must distinguish fixture perturbation from independent
    # synthetic campaigns and must not overstate real-world recall.
    for marker in [
        "Transformation suite",
        "Independent campaign suite",
        "does not establish arbitrary real-world",
    ]:
        assert marker in phase13, marker

    for marker in [
        "independent_campaigns",
        "independent_web_usb",
        "independent_device_first",
        "independent_session",
        "independent_mixed_sources",
    ]:
        assert marker in phase13_test, marker

    assert "100% recall on unseen attacks in the wild" not in readme
