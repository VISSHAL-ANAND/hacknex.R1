from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def test_final_release_contract():
 required=[
  "backend/detector.py","backend/reconstructor.py","backend/models.py",
  "tests/test_phase11_adversarial_benchmark.py","tests/test_phase12_confidence_drift.py",
  "tests/test_phase13_generalization_benchmark.py","tests/test_phase14_final_robustness.py",
  "docs/PHASE8_CERT_RAW_GATE.md","docs/PHASE13_GENERALIZATION.md","docs/PHASE14_FINAL_ROBUSTNESS.md",
  ".github/workflows/phase13.yml",".github/workflows/phase14.yml"
 ]
 missing=[p for p in required if not (ROOT/p).exists()]
 assert not missing,missing
 readme=(ROOT/"README.md").read_text(encoding="utf-8")
 for marker in ["Phase 13","Phase 14","Phase 15","Evidence first, explanation second."]:
  assert marker in readme,marker
