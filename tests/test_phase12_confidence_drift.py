import json
from datetime import timedelta
from pathlib import Path

from backend.detector import analyze
from backend.models import SecurityEvent


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "docs" / "results" / "phase12_confidence_drift_baseline.json"
SCENARIOS = ROOT / "backend" / "data" / "scenarios.json"


def load_scenarios():
    raw = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    return {name: [SecurityEvent.model_validate(x) for x in events] for name, events in raw.items()}


def clone(events):
    return [SecurityEvent.model_validate(e.model_dump()) for e in events]


def long_spacing_attack(base):
    events = clone(base)
    # Preserve causal order but stretch the campaign beyond the detector's
    # current fixed 30-minute cluster horizon.
    anchor = events[0].timestamp
    targets = [events[0], events[2], events[4]]
    offsets = [0, 20, 40]
    for event, minutes in zip(targets, offsets):
        event.timestamp = anchor + timedelta(minutes=minutes)
    return sorted(events, key=lambda e: e.timestamp)


def noisy_long_spacing_attack(base):
    events = long_spacing_attack(base)
    anchor = events[0].timestamp
    events.extend(
        SecurityEvent(
            event_id=f"DRIFT-NOISE-{i}",
            timestamp=anchor + timedelta(minutes=i),
            event_type="process_start",
            user="alice",
            device="DEV-07",
            src_ip="185.12.22.14",
            application="browser",
            source="endpoint",
            metadata={"benign_fixture": True},
        )
        for i in (5, 12, 27, 34)
    )
    return sorted(events, key=lambda e: e.timestamp)


def ambiguous_partial(base):
    events = clone(base)
    # Keep two stages but weaken the entity bridge and remove corroboration.
    events = [e for e in events if e.event_type != "usb_mount"]
    for e in events:
        if e.event_type == "file_access":
            e.device = None
            e.src_ip = None
    return events


def confidence(result):
    if result.incidents:
        return result.incidents[0].confidence
    if result.campaign_hypotheses:
        return max(h.confidence for h in result.campaign_hypotheses)
    return 0.0


def disposition(result):
    if result.correlated_incidents:
        return "validated"
    if result.campaign_hypotheses:
        return "hypothesis"
    if result.watchlist_candidates:
        return "watchlist"
    return "suppressed"


def build_cases():
    s = load_scenarios()
    attack = s["full_attack"]
    return [
        ("baseline_attack", attack, "validated", True),
        ("clock_drift_attack", [
            e.model_copy(update={"timestamp": e.timestamp + (timedelta(minutes=4) if e.event_type in {"file_access", "usb_mount", "file_copy"} else timedelta())})
            for e in clone(attack)
        ], "validated", True),
        ("long_spacing_attack", long_spacing_attack(attack), "validated", True),
        ("noisy_long_spacing_attack", noisy_long_spacing_attack(attack), "validated", True),
        ("ambiguous_partial", ambiguous_partial(attack), "hypothesis", True),
        ("benign_control", s["clean"], "suppressed", False),
        ("benign_backup", s["benign_backup"], "suppressed", False),
        ("authorized_transfer", s["authorized_transfer"], "suppressed", False),
    ]


def test_phase12_confidence_drift_baseline():
    cases = build_cases()
    observations = []

    for name, events, expected, malicious in cases:
        result = analyze(events)
        observations.append({
            "case": name,
            "malicious": malicious,
            "expected": expected,
            "actual": disposition(result),
            "confidence": confidence(result),
            "incidents": result.correlated_incidents,
            "hypotheses": len(result.campaign_hypotheses),
        })

    baseline = next(x for x in observations if x["case"] == "baseline_attack")
    partial = next(x for x in observations if x["case"] == "ambiguous_partial")
    long_cases = [x for x in observations if x["case"] in {"long_spacing_attack", "noisy_long_spacing_attack"}]

    validated = [x for x in observations if x["actual"] == "validated"]
    hypotheses = [x for x in observations if x["actual"] == "hypothesis"]
    confidence_gap = baseline["confidence"] - partial["confidence"]

    # Phase 12 discovery gates:
    # 1. Causal drift must not erase a still-ordered attack.
    # 2. Reduced evidence must materially reduce confidence.
    # 3. Benign controls must remain silent.
    long_spacing_recall = sum(x["actual"] == "validated" for x in long_cases) / len(long_cases)
    benign_fps = sum(
        x["actual"] == "validated"
        for x in observations
        if not x["malicious"]
    ) / sum(not x["malicious"] for x in observations)

    report = {
        "experiment": "Phase 12 confidence calibration and drift baseline",
        "purpose": "Break confidence and fixed-window assumptions before changing the detector.",
        "metrics": {
            "cases": len(cases),
            "validated_cases": len(validated),
            "hypothesis_cases": len(hypotheses),
            "long_spacing_validated_recall": round(long_spacing_recall, 4),
            "benign_false_positive_rate": round(benign_fps, 4),
            "baseline_confidence": baseline["confidence"],
            "ambiguous_partial_confidence": partial["confidence"],
            "confidence_gap": round(confidence_gap, 4),
        },
        "observations": observations,
    }
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    assert len(observations) == 8
    assert all(x["actual"] in {"validated", "hypothesis", "watchlist", "suppressed"} for x in observations)
    assert benign_fps == 0.0
    # Discovery gate: long ordered campaigns are expected to survive drift.
    assert long_spacing_recall == 1.0, observations
    # Discovery gate: uncertainty must be visible in confidence.
    assert confidence_gap >= 0.10, observations
