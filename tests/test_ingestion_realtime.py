import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.cli import detect_format, parse_file, run_pipeline
from backend.main import app

ROOT = Path(__file__).resolve().parents[1]


def test_cli_produces_reproducible_artifacts(tmp_path):
    source = tmp_path / "events.json"
    source.write_text(json.dumps([{
        "id": "CLI-1",
        "timestamp": "2026-10-07T09:00:00Z",
        "type": "login",
        "user": "alice",
        "device": "WS-1",
        "source": "test",
    }]), encoding="utf-8")

    assert detect_format(source) == "json"
    events = parse_file(source)
    assert len(events) == 1

    out = tmp_path / "out"
    result = run_pipeline(source, out)
    assert result.total_events == 1
    for name in ("normalized.jsonl", "enriched.jsonl", "incidents.json", "report.md", "run_summary.json"):
        assert (out / name).exists()


def test_upload_rejects_unsupported_extension():
    client = TestClient(app)
    response = client.post(
        "/api/analyze/upload",
        files={"file": ("events.exe", b"not-log", "application/octet-stream")},
    )
    assert response.status_code == 415


def test_upload_enforces_event_limit(monkeypatch):
    monkeypatch.setenv("HNX_MAX_API_EVENTS", "1")
    payload = json.dumps([
        {"id": "LIMIT-1", "timestamp": "2026-10-07T09:00:00Z", "type": "login"},
        {"id": "LIMIT-2", "timestamp": "2026-10-07T09:01:00Z", "type": "login"},
    ])
    client = TestClient(app)
    response = client.post(
        "/api/analyze/upload",
        files={"file": ("events.json", payload, "application/json")},
    )
    assert response.status_code == 413


def test_realtime_websocket_replays_scenario():
    client = TestClient(app)
    with client.websocket_connect("/ws/simulate/full_attack?delay=0") as websocket:
        start = websocket.receive_json()
        assert start["type"] == "start"
        count = 0
        final = None
        while True:
            message = websocket.receive_json()
            if message["type"] == "event":
                count += 1
            if message["type"] == "complete":
                final = message
                break
        assert count > 0
        assert final["analysis"]["correlated_incidents"] == 1
