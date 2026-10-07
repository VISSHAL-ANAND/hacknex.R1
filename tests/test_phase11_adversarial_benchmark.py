import copy
import json
from pathlib import Path

from backend.detector import analyze
from backend.models import SecurityEvent


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "backend" / "data" / "scenarios.json"
RESULTS = ROOT / "docs" / "results" / "phase11_adversarial_baseline.json"


def load_scenarios():
    raw = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    return {
        name: [SecurityEvent.model_validate(item) for item in events]
        for name, events in raw.items()
    }


def clone(events):
    return [SecurityEvent.model_validate(event.model_dump()) for event in events]


def shifted(events, minutes):
    result = clone(events)
    from datetime import timedelta

    return [
        event.model_copy(update={"timestamp": event.timestamp + timedelta(minutes=minutes)})
        for event in result
    ]


def noisy_attack(base):
    events = clone(base)
    noise = SecurityEvent(
        event_id="NOISE-001",
        timestamp=events[1].timestamp + __import__("datetime").timedelta(minutes=1),
        event_type="process_start",
        user="alice",
        device="DEV-07",
        src_ip="185.12.22.14",
        application="Office",
        source="endpoint",
        severity="info",
        metadata={},
    )
    events.insert(2, noise)
    return events


def decoy_attack(base):
    events = clone(base)
    decoy = SecurityEvent(
        event_id="DECOY-001",
        timestamp=events[2].timestamp,
        event_type="file_access",
        user="mallory",
        device="DEV-99",
        src_ip="198.51.100.7",
        application="FileServer",
        resource="/finance/decoy.pdf",
        action="read",
        source="file_server",
        severity="high",
        metadata={"sensitive": True},
    )
    events.append(decoy)
    return events


def out_of_order_attack(base):
    events = clone(base)
    events[2], events[4] = events[4], events[2]
    return events


def missing_telemetry(base):
    return [event for event in clone(base) if event.event_type != "file_access"]


def benign_usb_lookalike(base):
    events = clone(base)
    for event in events:
        metadata = dict(event.metadata)
        metadata.pop("unusual_ip", None)
        metadata.pop("new_device", None)
        metadata["authorized_activity"] = True
        if event.event_type == "usb_mount":
            metadata["sanctioned_usb"] = True
        if event.event_type == "file_copy":
            metadata["approved_transfer"] = True
            metadata["sanctioned_usb"] = True
        event.metadata = metadata
    return events


def build_cases():
    scenarios = load_scenarios()
    attack = scenarios["full_attack"]
    cases = [
        ("clean_control", scenarios["clean"], False, "suppressed"),
        ("baseline_attack", attack, True, "validated"),
        ("noisy_attack", noisy_attack(attack), True, "validated"),
        ("slow_attack", scenarios["slow_attack"], False, "suppressed"),
        ("reversed_order", scenarios["reversed_order"], False, "suppressed"),
        ("mismatched_entities", scenarios["mismatched_entities"], False, "suppressed"),
        ("shared_ip_collision", scenarios["shared_ip_collision"], False, "suppressed"),
        ("missing_telemetry", missing_telemetry(attack), True, "hypothesis"),
        ("decoy_attack", decoy_attack(attack), True, "validated"),
        ("out_of_order_input", out_of_order_attack(attack), True, "validated"),
        ("authorized_transfer", scenarios["authorized_transfer"], False, "suppressed"),
        ("benign_usb_lookalike", benign_usb_lookalike(attack), False, "suppressed"),
        ("benign_backup", scenarios["benign_backup"], False, "suppressed"),
        ("legitimate_sensitive_access", scenarios["legitimate_sensitive_access"], False, "suppressed"),
        ("partial_attack", scenarios["partial_attack"], True, "hypothesis"),
    ]
    return cases


def disposition(result):
    if result.correlated_incidents:
        return "validated"
    if result.campaign_hypotheses:
        return "hypothesis"
    if result.watchlist_candidates:
        return "watchlist"
    return "suppressed"


def test_phase11_adversarial_benchmark():
    cases = build_cases()
    observations = []
    tp = fp = fn = tn = 0

    for name, events, malicious, expected in cases:
        result = analyze(events)
        actual = disposition(result)
        predicted_attack = actual == "validated"

        if malicious and predicted_attack:
            tp += 1
        elif malicious and not predicted_attack:
            fn += 1
        elif not malicious and predicted_attack:
            fp += 1
        else:
            tn += 1

        observations.append({
            "case": name,
            "ground_truth_malicious": malicious,
            "expected_disposition": expected,
            "actual_disposition": actual,
            "incidents": result.correlated_incidents,
            "hypotheses": len(result.campaign_hypotheses),
            "watchlist_candidates": result.watchlist_candidates,
            "suspicious_events": result.suspicious_events,
            "passed_expected_disposition": actual == expected,
        })

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0

    report = {
        "experiment": "Phase 11 adversarial detection benchmark",
        "purpose": "Break the deterministic campaign detector before changing it.",
        "metrics": {
            "cases": len(cases),
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "true_negative": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
        },
        "observations": observations,
    }
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    # The benchmark is a discovery gate in Phase 11: every case must be
    # deterministic and produce one of the defined dispositions. Quality
    # thresholds are intentionally NOT asserted yet; the first run measures
    # where the current detector breaks.
    assert len(observations) == 15
    assert all(item["actual_disposition"] in {"validated", "hypothesis", "watchlist", "suppressed"} for item in observations)
    assert all(item["passed_expected_disposition"] for item in observations), observations
    assert tp + fp + fn + tn == len(cases)
