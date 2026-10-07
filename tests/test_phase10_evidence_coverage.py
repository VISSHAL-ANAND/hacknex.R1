import json
from pathlib import Path

from backend.detector import analyze
from backend.models import SecurityEvent


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "backend" / "data" / "scenarios.json"
RESULTS = ROOT / "docs" / "results" / "phase10_evidence_coverage_baseline.json"


def load_full_attack():
    raw = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    return [SecurityEvent.model_validate(item) for item in raw["full_attack"]]


def without_stage(events, stage):
    stage_types = {
        "identity": {"login", "device_enroll"},
        "sensitive": {"file_access"},
        "exfil": {"usb_mount", "file_copy"},
    }
    return [
        event
        for event in events
        if event.event_type not in stage_types[stage]
    ]


def classify(result):
    if result.correlated_incidents:
        return "validated"
    if result.watchlist_candidates:
        return "watchlist"
    return "suppressed"


def test_phase10_evidence_coverage_baseline():
    events = load_full_attack()
    cases = {
        "complete": events,
        "missing_identity": without_stage(events, "identity"),
        "missing_sensitive": without_stage(events, "sensitive"),
        "missing_exfil": without_stage(events, "exfil"),
    }

    observations = {}
    for name, case_events in cases.items():
        result = analyze(case_events)
        observations[name] = {
            "input_events": len(case_events),
            "disposition": classify(result),
            "incidents": result.correlated_incidents,
            "watchlist_candidates": result.watchlist_candidates,
            "suspicious_events": result.suspicious_events,
        }

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "experiment": "Phase 10 evidence coverage baseline",
                "description": (
                    "Controlled ablation of the existing full_attack scenario. "
                    "One complete evidence stage is removed at a time; no detector "
                    "logic is changed by this experiment."
                ),
                "baseline_gate": {
                    "complete_attack_must_validate": True,
                    "partial_attacks_must_not_validate": True,
                },
                "observations": observations,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    assert observations["complete"]["disposition"] == "validated"
    assert observations["complete"]["incidents"] == 1

    for name in ("missing_identity", "missing_sensitive", "missing_exfil"):
        assert observations[name]["disposition"] != "validated", name


def test_phase10_partial_chain_hypotheses_cover_single_stage_loss():
    events = load_full_attack()
    expected_missing = {
        "missing_identity": {"Initial Access / Identity Anomaly"},
        "missing_sensitive": {"Sensitive Data Access"},
        "missing_exfil": {"Collection / Exfiltration"},
    }

    for name, missing in expected_missing.items():
        result = analyze(without_stage(events, {
            "missing_identity": "identity",
            "missing_sensitive": "sensitive",
            "missing_exfil": "exfil",
        }[name]))

        assert result.correlated_incidents == 0, name
        assert result.campaign_hypotheses, name
        hypothesis = result.campaign_hypotheses[0]
        assert set(hypothesis.missing_stages) == missing
        assert len(hypothesis.observed_stages) == 2
        assert hypothesis.evidence_event_ids
        assert hypothesis.temporal_valid is True
        assert hypothesis.entity_consistency_score >= 0.60
        assert hypothesis.confidence >= 0.65
        assert result.suppressed is False, name


def test_phase10_complete_attack_remains_incident_only():
    result = analyze(load_full_attack())
    assert result.correlated_incidents == 1
    assert result.campaign_hypotheses == []
    assert result.suppressed is False


def test_phase10_hypothesis_does_not_change_incident_gate():
    events = load_full_attack()
    result = analyze(without_stage(events, "sensitive"))
    assert result.correlated_incidents == 0
    assert result.incidents == []
    assert result.watchlist_candidates == 1
