import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.detector import analyze
from backend.models import SecurityEvent

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "docs/results/phase13_generalization.json"
SCENARIOS = ROOT / "backend/data/scenarios.json"


def load():
    raw = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    return {k: [SecurityEvent.model_validate(x) for x in v] for k, v in raw.items()}


def clone(events):
    return [SecurityEvent.model_validate(e.model_dump()) for e in events]


def event(
    event_id,
    minute,
    event_type,
    user,
    device,
    ip,
    application,
    source,
    metadata=None,
    resource=None,
    action=None,
    severity="info",
    session_id=None,
):
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(2026, 10, 7, 9, 0, tzinfo=timezone.utc) + timedelta(minutes=minute),
        event_type=event_type,
        user=user,
        device=device,
        src_ip=ip,
        application=application,
        source=source,
        severity=severity,
        metadata=metadata or {},
        resource=resource,
        action=action,
        session_id=session_id,
    )


def disp(result):
    if result.correlated_incidents:
        return "validated"
    if result.campaign_hypotheses:
        return "hypothesis"
    if result.watchlist_candidates:
        return "watchlist"
    return "suppressed"


# Suite A: controlled transformations of the established demo attack.
# This remains useful, but is explicitly NOT called unseen-world recall.
def rotate_attack(base):
    events = clone(base)
    anchor = events[0].timestamp
    for i, event_item in enumerate(events):
        event_item.timestamp = anchor + timedelta(minutes=[0, 3, 7, 8, 11][i])
    for event_item in events:
        event_item.application = f"svc-{event_item.application}"
        event_item.src_ip = "203.0.113.77"
    return events


def interleave(base):
    events = clone(base)
    anchor = events[0].timestamp
    noise = [
        SecurityEvent(
            event_id=f"UNSEEN-N-{i}",
            timestamp=anchor + timedelta(minutes=minute),
            event_type="process_start",
            user="benign",
            device="DEV-B",
            src_ip="10.9.0.2",
            application="backup",
            source="endpoint",
            metadata={"benign_fixture": True},
        )
        for i, minute in enumerate([1, 4, 6, 9, 10])
    ]
    return sorted(events + noise, key=lambda item: item.timestamp)


def decoys(base):
    events = clone(base)
    anchor = events[0].timestamp
    for i, minute in enumerate([2, 5, 6, 9, 10, 12, 14]):
        events.append(
            SecurityEvent(
                event_id=f"DECOY-{i}",
                timestamp=anchor + timedelta(minutes=minute),
                event_type="file_access" if i % 2 else "usb_mount",
                user="alice",
                device="DEV-07",
                src_ip="10.0.0.9",
                application="decoy",
                source="endpoint",
                metadata={"sensitive": i % 2 == 1, "removable": i % 2 == 0},
            )
        )
    return sorted(events, key=lambda item: item.timestamp)


def missing_noise(base):
    events = [item for item in clone(base) if item.event_type != "device_enroll"]
    for event_item in events:
        event_item.metadata = {**event_item.metadata, "collector": "sensor-v2"}
    return events


def simultaneous(base):
    first = clone(base)
    second = clone(base)
    for event_item in second:
        event_item.event_id = "B-" + event_item.event_id
        event_item.user = "bob"
        event_item.device = "DEV-88"
        event_item.src_ip = "198.51.100.9"
    return sorted(first + second, key=lambda item: item.timestamp)


# Suite B: independently authored campaigns. These events are constructed
# directly and do not clone or mutate full_attack/slow_attack/etc.
def independent_campaigns():
    malicious = [
        (
            "independent_web_usb",
            [
                event("WEB-101", 0, "login", "maya", "LAP-41", "198.18.10.41", "RemoteGateway", "vpn",
                      {"unusual_ip": True}, severity="medium"),
                event("WEB-102", 4, "file_access", "maya", "LAP-41", "198.18.10.41", "SharePointSync", "cloud",
                      {"sensitive": True}, resource="/legal/merger-plan.docx", action="read", severity="high"),
                event("WEB-103", 7, "usb_mount", "maya", "LAP-41", "198.18.10.41", "DeviceControl", "edr",
                      {"removable": True}, resource="REM-441", action="mount", severity="high"),
                event("WEB-104", 8, "file_copy", "maya", "LAP-41", "198.18.10.41", "SyncClient", "edr",
                      {"bytes": 1800000000, "destination": "REM-441"}, resource="/legal/merger-plan.docx",
                      action="copy_to_removable", severity="critical"),
            ],
        ),
        (
            "independent_device_first",
            [
                event("RND-201", 0, "device_enroll", "omar", "WS-52", "198.18.20.52", "DeviceTrust", "endpoint",
                      {"new_device": True}, severity="medium"),
                event("RND-202", 9, "file_access", "omar", "WS-52", "198.18.20.52", "ResearchVault", "file_audit",
                      {"sensitive": True}, resource="/research/prototype.zip", action="read", severity="high"),
                event("RND-203", 14, "file_copy", "omar", "WS-52", "198.18.20.52", "ArchiveTool", "endpoint",
                      {"bytes": 1500000000, "destination": "removable-drive-52"}, resource="/research/prototype.zip",
                      action="copy_to_removable", severity="critical"),
            ],
        ),
        (
            "independent_session",
            [
                event("OPS-301", 0, "login", "priya", "WS-63", "198.18.30.63", "RemoteAccess", "gateway",
                      {"unusual_ip": True}, severity="medium", session_id="S-900"),
                event("OPS-302", 6, "file_access", "priya", "WS-63", "198.18.30.63", "RecordsAPI", "database",
                      {"sensitive": True}, resource="/records/board-minutes.csv", action="read", severity="high",
                      session_id="S-900"),
                event("OPS-303", 11, "usb_mount", "priya", "WS-63", "198.18.30.63", "RemovableMedia", "edr",
                      {"removable": True}, resource="MEDIA-63", action="mount", severity="high", session_id="S-900"),
                event("OPS-304", 12, "file_copy", "priya", "WS-63", "198.18.30.63", "ExportAgent", "edr",
                      {"bytes": 2100000000, "destination": "MEDIA-63"}, resource="/records/board-minutes.csv",
                      action="copy_to_usb", severity="critical", session_id="S-900"),
            ],
        ),
        (
            "independent_mixed_sources",
            [
                event("HR-401", 0, "login", "noah", "VDI-17", "198.18.40.17", "SAMLBroker", "identity",
                      {"unusual_ip": True, "new_device": True}, severity="medium"),
                event("HR-402", 3, "file_access", "noah", "VDI-17", "198.18.40.17", "DocumentIndex", "dlp",
                      {"sensitive": True}, resource="/hr/compensation.xlsx", action="read", severity="high"),
                event("HR-403", 5, "usb_mount", "noah", "VDI-17", "198.18.40.17", "USBGuard", "linux-audit",
                      {"removable": True}, resource="THUMB-17", action="mount", severity="high"),
                event("HR-404", 6, "file_copy", "noah", "VDI-17", "198.18.40.17", "ShellCopy", "linux-audit",
                      {"bytes": 1300000000, "destination": "THUMB-17"}, resource="/hr/compensation.xlsx",
                      action="copy_to_usb", severity="critical"),
            ],
        ),
    ]

    benign = [
        (
            "independent_authorized_media",
            [
                event("BEN-501", 0, "login", "ravi", "WS-71", "10.60.0.71", "Identity", "auth",
                      {"unusual_ip": False, "new_device": False, "authorized_activity": True}),
                event("BEN-502", 4, "file_access", "ravi", "WS-71", "10.60.0.71", "Records", "file_audit",
                      {"sensitive": True, "authorized_activity": True}, resource="/finance/q4.xlsx",
                      action="read", severity="high"),
                event("BEN-503", 6, "usb_mount", "ravi", "WS-71", "10.60.0.71", "DeviceControl", "edr",
                      {"removable": True, "sanctioned_usb": True, "authorized_activity": True},
                      resource="APPROVED-71", action="mount"),
                event("BEN-504", 7, "file_copy", "ravi", "WS-71", "10.60.0.71", "ExportTool", "edr",
                      {"bytes": 2200000000, "destination": "APPROVED-71", "approved_transfer": True,
                       "sanctioned_usb": True}, resource="/finance/q4.xlsx", action="copy_to_usb", severity="high"),
            ],
        ),
        (
            "independent_normal_media",
            [
                event("BEN-601", 0, "login", "sana", "WS-82", "10.61.0.82", "Identity", "auth",
                      {"unusual_ip": False, "new_device": False}),
                event("BEN-602", 5, "file_access", "sana", "WS-82", "10.61.0.82", "Docs", "file_audit",
                      {"sensitive": False}, resource="/team/plan.txt", action="read"),
                event("BEN-603", 8, "usb_mount", "sana", "WS-82", "10.61.0.82", "DeviceControl", "edr",
                      {"removable": True}, resource="USB-82", action="mount"),
                event("BEN-604", 9, "file_copy", "sana", "WS-82", "10.61.0.82", "FileManager", "edr",
                      {"bytes": 120000000, "destination": "USB-82"}, resource="/team/plan.txt",
                      action="copy_to_usb"),
            ],
        ),
        (
            "independent_network_backup",
            [
                event("BEN-701", 0, "login", "tariq", "SRV-91", "10.62.0.91", "Identity", "auth",
                      {"unusual_ip": False, "new_device": False}),
                event("BEN-702", 5, "file_access", "tariq", "SRV-91", "10.62.0.91", "DataCatalog", "file_audit",
                      {"sensitive": True, "authorized_activity": True}, resource="/finance/ledger.db",
                      action="read", severity="high"),
                event("BEN-703", 9, "file_copy", "tariq", "SRV-91", "10.62.0.91", "BackupAgent", "backup",
                      {"bytes": 9000000000, "destination": "backup-cluster", "authorized_activity": True},
                      resource="/finance/ledger.db", action="backup", severity="critical"),
            ],
        ),
        (
            "independent_weak_partial",
            [
                event("BEN-801", 0, "login", "uma", "LAP-99", "10.63.0.99", "Identity", "auth",
                      {"unusual_ip": True, "new_device": True}, severity="medium"),
                event("BEN-802", 5, "file_access", "uma", "LAP-99", "10.63.0.99", "Docs", "file_audit",
                      {"sensitive": True}, resource="/public/roadmap.pdf", action="read", severity="high"),
            ],
        ),
    ]
    return malicious, benign


def test_phase13_generalization_gate():
    scenarios = load()

    # Existing transformation suite retained as a separate measurement.
    transformed = [
        ("rotated_structure", rotate_attack(scenarios["full_attack"]), True),
        ("interleaved_benign", interleave(scenarios["full_attack"]), True),
        ("decoy_heavy", decoys(scenarios["full_attack"]), True),
        ("missing_device_enroll", missing_noise(scenarios["full_attack"]), True),
        ("simultaneous_campaigns", simultaneous(scenarios["full_attack"]), True),
    ]

    independent_malicious, independent_benign = independent_campaigns()
    independent = [(name, events, True) for name, events in independent_malicious] + [
        (name, events, False) for name, events in independent_benign
    ]

    cases = transformed + independent
    # Retain a large benign control, but construct it without reusing full_attack.
    clean_haystack = scenarios["clean"] + clone(scenarios["benign_backup"]) * 100
    cases.append(("benign_haystack", clean_haystack, False))

    observations = []
    for name, events, malicious in cases:
        result = analyze(events)
        observations.append(
            {
                "case": name,
                "actual": disp(result),
                "malicious": malicious,
                "incidents": result.correlated_incidents,
                "hypotheses": len(result.campaign_hypotheses),
            }
        )

    transformed_rows = [row for row in observations if row["case"] in {x[0] for x in transformed}]
    independent_rows = [row for row in observations if row["case"] not in {x[0] for x in transformed}]

    transformed_tp = sum(row["malicious"] and row["actual"] == "validated" for row in transformed_rows)
    transformed_total = sum(row["malicious"] for row in transformed_rows)
    transformed_fp = sum((not row["malicious"]) and row["actual"] == "validated" for row in transformed_rows)
    transformed_benign = sum(not row["malicious"] for row in transformed_rows)

    independent_tp = sum(row["malicious"] and row["actual"] == "validated" for row in independent_rows)
    independent_total = sum(row["malicious"] for row in independent_rows)
    independent_fp = sum((not row["malicious"]) and row["actual"] == "validated" for row in independent_rows)
    independent_benign = sum(not row["malicious"] for row in independent_rows)

    report = {
        "experiment": "Phase 13 generalization benchmark",
        "interpretation": (
            "Two suites are reported separately. Suite A applies controlled transformations "
            "to the established fixture. Suite B is independently authored from scratch and "
            "is the stronger synthetic generalization test. Neither suite establishes recall "
            "on arbitrary real-world attack campaigns."
        ),
        "metrics": {
            "transformation_suite": {
                "malicious_cases": transformed_total,
                "validated_recall": round(transformed_tp / transformed_total, 4),
                "benign_cases": transformed_benign,
                "validated_fpr": round(transformed_fp / transformed_benign, 4) if transformed_benign else 0.0,
            },
            "independent_campaign_suite": {
                "malicious_cases": independent_total,
                "validated_recall": round(independent_tp / independent_total, 4),
                "benign_cases": independent_benign,
                "validated_fpr": round(independent_fp / independent_benign, 4),
            },
        },
        "observations": observations,
    }

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    assert transformed_tp == transformed_total, observations
    assert transformed_fp == 0, observations
    assert independent_tp == independent_total, observations
    assert independent_fp == 0, observations
    assert all(row["actual"] in {"validated", "hypothesis", "watchlist", "suppressed"} for row in observations)
