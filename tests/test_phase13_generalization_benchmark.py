from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.detector import analyze
from backend.models import SecurityEvent

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "docs/results/phase13_generalization.json"


def event(event_id, minute, event_type, *, user, device, ip, application,
          metadata=None, resource=None, action=None, session=None, severity="info"):
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(2026, 10, 7, 9, 0, tzinfo=timezone.utc) + timedelta(minutes=minute),
        event_type=event_type,
        user=user,
        device=device,
        src_ip=ip,
        application=application,
        resource=resource,
        action=action,
        session_id=session,
        source="independent-benchmark",
        severity=severity,
        metadata=metadata or {},
    )


def disposition(response):
    if response.correlated_incidents:
        return "validated"
    if response.campaign_hypotheses:
        return "hypothesis"
    if response.watchlist_candidates:
        return "watchlist"
    return "suppressed"


# Deliberately constructed from scratch. No scenario fixture is imported,
# cloned, transformed, or mutated.
def media_a():
    return [
        event("IA-A1", 0, "login", user="maya", device="WS-41", ip="198.18.1.41",
              application="SSO-Gateway", metadata={"unusual_ip": True, "new_device": True}),
        event("IA-A2", 6, "file_access", user="maya", device="WS-41", ip="198.18.1.41",
              application="RecordsPortal", resource="/legal/merger-plan.pdf", action="read",
              metadata={"sensitive": True}, severity="high"),
        event("IA-A3", 10, "usb_mount", user="maya", device="WS-41", ip="198.18.1.41",
              application="DeviceService", resource="MEDIA-17", action="mount",
              metadata={"removable": True}, severity="high"),
        event("IA-A4", 12, "file_copy", user="maya", device="WS-41", ip="198.18.1.41",
              application="TransferAgent", resource="/legal/merger-plan.pdf",
              action="write_to_removable",
              metadata={"bytes": 3_200_000_000, "destination": "MEDIA-17"}, severity="critical"),
    ]


def media_b():
    return [
        event("IA-B1", 2, "login", user="noah", device="LAP-92", ip="198.18.2.92",
              application="AccessHub", metadata={"unusual_ip": True}),
        event("IA-B2", 8, "file_access", user="noah", device="LAP-92", ip="198.18.2.92",
              application="ResearchVault", resource="/research/formula.csv", action="export",
              metadata={"sensitive": True}, severity="high"),
        event("IA-B3", 13, "file_copy", user="noah", device="LAP-92", ip="198.18.2.92",
              application="SyncUtility", resource="/research/formula.csv",
              action="copy_to_removable",
              metadata={"bytes": 1_750_000_000, "destination": "removable-drive-92"},
              severity="critical"),
    ]


def slow_session():
    return [
        event("IA-C1", 0, "login", user="rhea", device="ENG-18", ip="198.18.3.18",
              application="RemoteAccess", session="S-318",
              metadata={"unusual_ip": True, "new_device": True}),
        event("IA-C2", 43, "file_access", user="rhea", device="ENG-18", ip="198.18.3.18",
              application="EngineeringVault", resource="/design/engine-v2.zip", action="read",
              session="S-318", metadata={"sensitive": True, "behavior_score": 0.65},
              severity="high"),
        event("IA-C3", 82, "file_copy", user="rhea", device="ENG-18", ip="198.18.3.18",
              application="ArchiveTool", resource="/design/engine-v2.zip", action="copy_to_usb",
              session="S-318",
              metadata={"bytes": 2_100_000_000, "destination": "USB-318", "behavior_score": 0.65},
              severity="critical"),
    ]


def decoy_campaign():
    events = media_a()
    events += [
        event("IA-DX1", 4, "file_access", user="service", device="BACKUP-01", ip="10.10.0.5",
              application="BackupAgent", resource="/team/readme.txt", metadata={"sensitive": True}),
        event("IA-DX2", 9, "usb_mount", user="service", device="BACKUP-01", ip="10.10.0.5",
              application="BackupAgent", resource="USB-BACKUP", metadata={"removable": True}),
        event("IA-DX3", 11, "file_copy", user="service", device="BACKUP-01", ip="10.10.0.5",
              application="BackupAgent", resource="/team/", action="backup",
              metadata={"bytes": 8_000_000_000, "destination": "backup-server"}),
    ]
    return events


def dual_campaigns():
    return media_a() + media_b()


def benign_authorized():
    return [
        event("BEN-A1", 0, "login", user="ops", device="OPS-7", ip="10.20.0.7",
              application="SSO", metadata={"unusual_ip": True, "new_device": True}),
        event("BEN-A2", 4, "file_access", user="ops", device="OPS-7", ip="10.20.0.7",
              application="Records", resource="/ops/archive.tar", metadata={"sensitive": True}),
        event("BEN-A3", 7, "usb_mount", user="ops", device="OPS-7", ip="10.20.0.7",
              application="DeviceService", resource="USB-OPS", metadata={"removable": True}),
        event("BEN-A4", 9, "file_copy", user="ops", device="OPS-7", ip="10.20.0.7",
              application="ApprovedExporter", resource="/ops/archive.tar", action="copy_to_usb",
              metadata={"bytes": 4_000_000_000, "destination": "USB-OPS",
                        "approved_transfer": True, "authorized_activity": True},
              severity="critical"),
    ]


def benign_sensitive():
    return [
        event("BEN-B1", 0, "login", user="legal", device="LAW-2", ip="10.20.1.2",
              application="SSO", metadata={"unusual_ip": False}),
        event("BEN-B2", 5, "file_access", user="legal", device="LAW-2", ip="10.20.1.2",
              application="CaseVault", resource="/cases/contract.pdf", action="read",
              metadata={"sensitive": True}),
        event("BEN-B3", 8, "file_close", user="legal", device="LAW-2", ip="10.20.1.2",
              application="CaseVault", resource="/cases/contract.pdf"),
    ]


def benign_shared_endpoint():
    return [
        event("BEN-C1", 0, "login", user="alice2", device="SHARED-5", ip="10.20.2.5",
              application="SSO", metadata={"unusual_ip": True}),
        event("BEN-C2", 4, "file_access", user="alice2", device="SHARED-5", ip="10.20.2.5",
              application="Vault", resource="/data/payroll.xlsx", metadata={"sensitive": True}),
        event("BEN-C3", 7, "usb_mount", user="bob2", device="SHARED-5", ip="10.20.2.5",
              application="DeviceService", resource="USB-5", metadata={"removable": True}),
        event("BEN-C4", 8, "file_copy", user="bob2", device="SHARED-5", ip="10.20.2.5",
              application="Exporter", resource="/data/payroll.xlsx", action="copy_to_usb",
              metadata={"bytes": 2_000_000_000, "destination": "USB-5"}),
    ]


def unsupported_network_exfil():
    # Outside the removable-media contract. It must never become validated.
    return [
        event("BOUND-X1", 0, "login", user="sara", device="NET-44", ip="198.18.4.44",
              application="VPN", metadata={"unusual_ip": True}),
        event("BOUND-X2", 12, "file_access", user="sara", device="NET-44", ip="198.18.4.44",
              application="DBPortal", resource="/customer/export.csv",
              metadata={"sensitive": True}, severity="high"),
        event("BOUND-X3", 18, "network_transfer", user="sara", device="NET-44",
              ip="198.18.4.44", application="Uploader", action="upload",
              metadata={"bytes": 3_000_000_000, "destination": "203.0.113.44"},
              severity="critical"),
    ]


def test_phase13_independent_generalization_gate():
    cases = [
        ("independent_media_a", media_a(), "in_contract_malicious"),
        ("independent_media_b", media_b(), "in_contract_malicious"),
        ("independent_slow_session", slow_session(), "in_contract_malicious"),
        ("independent_decoy_campaign", decoy_campaign(), "in_contract_malicious"),
        ("independent_dual_campaigns", dual_campaigns(), "in_contract_malicious"),
        ("benign_authorized_transfer", benign_authorized(), "benign"),
        ("benign_sensitive_access", benign_sensitive(), "benign"),
        ("benign_shared_endpoint_collision", benign_shared_endpoint(), "benign"),
        ("unsupported_network_exfil", unsupported_network_exfil(), "out_of_contract"),
    ]

    observations = []
    for name, events, category in cases:
        result = analyze(events)
        observations.append({
            "case": name,
            "category": category,
            "actual": disposition(result),
            "incidents": result.correlated_incidents,
            "hypotheses": len(result.campaign_hypotheses),
            "event_count": len(events),
        })

    in_contract = [o for o in observations if o["category"] == "in_contract_malicious"]
    benign = [o for o in observations if o["category"] == "benign"]
    boundary = [o for o in observations if o["category"] == "out_of_contract"]

    recall = sum(o["actual"] == "validated" for o in in_contract) / len(in_contract)
    fpr = sum(o["actual"] == "validated" for o in benign) / len(benign)

    report = {
        "experiment": "Phase 13 independent campaign generalization benchmark",
        "methodology": (
            "Malicious campaigns are constructed independently from project fixtures. "
            "No test case imports, clones, mutates, or transforms full_attack. "
            "Results are measured within the declared removable-media evidence contract."
        ),
        "metrics": {
            "independent_in_contract_cases": len(in_contract),
            "validated_recall": round(recall, 4),
            "benign_cases": len(benign),
            "validated_fpr": round(fpr, 4),
            "out_of_contract_cases": len(boundary),
            "out_of_contract_validated": sum(o["actual"] == "validated" for o in boundary),
        },
        "observations": observations,
    }
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(report, indent=2) + "\n")

    assert recall == 1.0, observations
    assert fpr == 0.0, observations
    assert all(o["actual"] != "validated" for o in boundary), observations
