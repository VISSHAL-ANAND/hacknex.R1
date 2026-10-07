from __future__ import annotations

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .adapters import normalize_sysmon_event, normalize_windows_event, normalize_windows_event_xml, normalize_zeek_event
from .detector import analyze
from .enrichment import enrich_events
from .models import SecurityEvent
from .normalizer import normalize_events


class PipelineInputError(ValueError):
    pass


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PipelineInputError(f"invalid JSON in {path}: {exc}") from exc


def _records(path: Path, kind: str) -> list[dict[str, Any]]:
    if kind == "json":
        payload = _read_json(path)
        if isinstance(payload, dict):
            return [payload]
        if isinstance(payload, list):
            return [x for x in payload if isinstance(x, dict)]
        raise PipelineInputError("JSON input must contain an object or list of objects")
    if kind == "jsonl":
        out = []
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise PipelineInputError(f"invalid JSONL at line {line_no}") from exc
            if not isinstance(value, dict):
                raise PipelineInputError(f"JSONL line {line_no} must contain an object")
            out.append(value)
        return out
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def detect_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    if suffix == ".csv":
        return "csv"
    if suffix == ".xml":
        return "windows"
    payload = _read_json(path)
    sample = payload[0] if isinstance(payload, list) and payload else payload
    if isinstance(sample, dict):
        keys = set(sample)
        if {"System", "EventData"} & keys:
            return "windows"
        if {"EventID", "UtcTime", "RuleName"} & keys:
            return "sysmon"
        if {"uid", "id.orig_h", "id.resp_h"} & keys:
            return "zeek"
    return "json"


def _windows_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith((bytes((0xFF, 0xFE)), bytes((0xFE, 0xFF)))):
        return raw.decode("utf-16")
    if raw.startswith(bytes((0xEF, 0xBB, 0xBF))):
        return raw.decode("utf-8-sig")
    return raw.decode("utf-8")


def parse_file(path: str | Path, format_name: str = "auto") -> list[SecurityEvent]:
    source = Path(path)
    if not source.exists():
        raise PipelineInputError(f"input file does not exist: {source}")
    fmt = detect_format(source) if format_name == "auto" else format_name
    if fmt in {"json", "jsonl", "csv"}:
        records = _records(source, fmt)
        if not records:
            raise PipelineInputError("input contains no records")
        return normalize_events(records)
    if fmt == "windows":
        text = _windows_text(source)
        if text.lstrip().startswith("<"):
            root = ET.fromstring(text)
            return [normalize_windows_event_xml(ET.tostring(root, encoding="unicode"))]
        return [normalize_windows_event(x, i) for i, x in enumerate(_records(source, "json"))]
    if fmt == "sysmon":
        return [normalize_sysmon_event(x, i) for i, x in enumerate(_records(source, "json"))]
    if fmt == "zeek":
        payload = _read_json(source)
        stream = "conn"
        if isinstance(payload, dict):
            stream = str(payload.get("stream") or "conn")
            payload = payload.get("events") or []
        if not isinstance(payload, list):
            raise PipelineInputError("Zeek JSON input must be a list or {stream, events}")
        return [normalize_zeek_event(x, stream=stream, index=i) for i, x in enumerate(payload)]
    raise PipelineInputError(f"unsupported format: {fmt}")


def _write_jsonl(path: Path, events: list[SecurityEvent]) -> None:
    path.write_text(
        "".join(json.dumps(e.model_dump(mode="json"), sort_keys=True) + "\n" for e in events),
        encoding="utf-8",
    )


def run_pipeline(path: str | Path, out_dir: str | Path, format_name: str = "auto") -> Any:
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    normalized = parse_file(path, format_name)
    enriched = enrich_events(normalized)
    analysis = analyze(normalized)
    _write_jsonl(output / "normalized.jsonl", normalized)
    _write_jsonl(output / "enriched.jsonl", enriched)
    (output / "incidents.json").write_text(
        json.dumps([i.model_dump(mode="json") for i in analysis.incidents], indent=2, sort_keys=True),
        encoding="utf-8",
    )
    report = [
        "# Evidence-First Analysis Report", "",
        f"- Events processed: **{analysis.total_events}**",
        f"- Suspicious events: **{analysis.suspicious_events}**",
        f"- Watchlist candidates: **{analysis.watchlist_candidates}**",
        f"- Validated incidents: **{analysis.correlated_incidents}**", "",
    ]
    if not analysis.incidents:
        report += ["## Disposition", "", "No validated incident. Evidence did not form a complete attack chain."]
    for incident in analysis.incidents:
        report += [
            f"## {incident.incident_id}: {incident.title}", "",
            f"- Severity: **{incident.severity}**",
            f"- Risk: **{incident.risk_score}/100**",
            f"- Confidence: **{incident.confidence:.2f}**", "",
            "### Evidence", "",
            *[f"- {e.event_id} — {e.event_type}" for e in incident.timeline], "",
        ]
    (output / "report.md").write_text("\n".join(report), encoding="utf-8")
    (output / "run_summary.json").write_text(
        json.dumps({
            "input": str(path),
            "format": detect_format(Path(path)) if format_name == "auto" else format_name,
            "counts": {
                "input_records": len(normalized),
                "normalized_events": len(normalized),
                "enriched_events": len(enriched),
                "suspicious_events": analysis.suspicious_events,
                "watchlist_candidates": analysis.watchlist_candidates,
                "validated_incidents": analysis.correlated_incidents,
            },
        }, indent=2) + "\n",
        encoding="utf-8",
    )
    return analysis


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m backend.cli")
    parser.add_argument("path")
    parser.add_argument("--out", required=True)
    parser.add_argument("--format", dest="format_name",
                        choices=["auto", "json", "jsonl", "csv", "windows", "sysmon", "zeek"],
                        default="auto")
    args = parser.parse_args(argv)
    try:
        run_pipeline(args.path, args.out, args.format_name)
        return 0
    except (OSError, ET.ParseError, PipelineInputError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
