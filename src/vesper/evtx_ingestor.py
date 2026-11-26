"""Genuine binary Windows EVTX ingestion (python-evtx), SHA-256 chain of custody, and normalized telemetry."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as SafeET
from Evtx.Evtx import Evtx

EVTX_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


@dataclass
class NormalizedEvent:
    event_id: int
    timestamp: str
    channel: str
    computer: str
    user: str
    image: str = ""
    command_line: str = ""
    parent_image: str = ""
    target_object: str = ""
    script_block_text: str = ""
    source_file: str = ""
    source_sha256: str = ""
    provenance: str = "laboratory_synthetic"
    raw_fields: dict[str, Any] = field(default_factory=dict)

    def to_sigma_dict(self) -> dict[str, Any]:
        return {
            "EventID": self.event_id,
            "Timestamp": self.timestamp,
            "Channel": self.channel,
            "Computer": self.computer,
            "User": self.user,
            "Image": self.image,
            "CommandLine": self.command_line,
            "ParentImage": self.parent_image,
            "TargetObject": self.target_object,
            "ScriptBlockText": self.script_block_text,
        }


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_ns(parent: Any, tag: str) -> Any:
    node = parent.find(f"e:{tag}", EVTX_NS)
    return node if node is not None else parent.find(tag)


def parse_evtx_xml_record(xml_str: str, source_file: str = "", source_sha256: str = "", provenance: str = "genuine_evtx") -> NormalizedEvent:
    """Parse a single Windows Event Log XML record (from binary EVTX or XML dump) using XXE-safe defusedxml."""
    root = SafeET.fromstring(xml_str)
    sys_node = _find_ns(root, "System")
    event_id = 0
    timestamp = ""
    channel = ""
    computer = ""
    if sys_node is not None:
        eid_el = _find_ns(sys_node, "EventID")
        if eid_el is not None and eid_el.text:
            event_id = int(eid_el.text.strip())
        tc_el = _find_ns(sys_node, "TimeCreated")
        if tc_el is not None:
            timestamp = tc_el.attrib.get("SystemTime", "")
        ch_el = _find_ns(sys_node, "Channel")
        if ch_el is not None and ch_el.text:
            channel = ch_el.text.strip()
        comp_el = _find_ns(sys_node, "Computer")
        if comp_el is not None and comp_el.text:
            computer = comp_el.text.strip()

    data_fields: dict[str, str] = {}
    ed_node = _find_ns(root, "EventData")
    if ed_node is not None:
        for child in ed_node:
            name = child.attrib.get("Name")
            if name:
                data_fields[name] = (child.text or "").strip()

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        channel=channel,
        computer=computer,
        user=data_fields.get("User") or data_fields.get("SubjectUserName") or "UNKNOWN",
        image=data_fields.get("Image") or data_fields.get("NewProcessName") or "",
        command_line=data_fields.get("CommandLine") or "",
        parent_image=data_fields.get("ParentImage") or data_fields.get("ParentProcessName") or "",
        target_object=data_fields.get("TargetObject") or "",
        script_block_text=data_fields.get("ScriptBlockText") or "",
        source_file=source_file,
        source_sha256=source_sha256,
        provenance=provenance,
        raw_fields=data_fields,
    )


def ingest_binary_evtx(evtx_path: Path, max_records: int = 5000) -> tuple[list[NormalizedEvent], dict[str, Any]]:
    """Parse a genuine binary Windows .evtx file via python-evtx and return normalized events + custody manifest."""
    if not evtx_path.is_file():
        raise FileNotFoundError(f"EVTX artifact not found: {evtx_path}")
    sha = compute_sha256(evtx_path)
    events: list[NormalizedEvent] = []
    parse_errors = 0

    with Evtx(str(evtx_path)) as log:
        for idx, record in enumerate(log.records()):
            if idx >= max_records:
                break
            try:
                events.append(
                    parse_evtx_xml_record(
                        record.xml(),
                        source_file=evtx_path.name,
                        source_sha256=sha,
                        provenance="genuine_binary_evtx",
                    )
                )
            except Exception:
                parse_errors += 1

    manifest = {
        "artifact": evtx_path.name,
        "format": "Windows Binary EVTX (ElfFile)",
        "size_bytes": evtx_path.stat().st_size,
        "sha256": sha,
        "records_parsed": len(events),
        "parse_errors": parse_errors,
        "provenance": "genuine_binary_evtx",
    }
    return events, manifest


def ingest_json_triage(json_path: Path, provenance: str = "laboratory_synthetic") -> tuple[list[NormalizedEvent], dict[str, Any]]:
    """Load structured JSON triage telemetry and normalize into VESPER schema with SHA-256 hash."""
    sha = compute_sha256(json_path)
    raw = json.loads(json_path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = [raw]
    events: list[NormalizedEvent] = []
    for item in raw:
        events.append(
            NormalizedEvent(
                event_id=int(item.get("EventID", 1)),
                timestamp=str(item.get("Timestamp", "")),
                channel=str(item.get("Channel", "Microsoft-Windows-Sysmon/Operational")),
                computer=str(item.get("Hostname") or item.get("Computer") or "UNKNOWN"),
                user=str(item.get("User", "UNKNOWN")),
                image=str(item.get("Image", "")),
                command_line=str(item.get("CommandLine") or item.get("Command") or ""),
                parent_image=str(item.get("ParentImage", "")),
                target_object=str(item.get("TargetObject", "")),
                script_block_text=str(item.get("ScriptBlockText", "")),
                source_file=json_path.name,
                source_sha256=sha,
                provenance=provenance,
                raw_fields=item,
            )
        )
    manifest = {
        "artifact": json_path.name,
        "format": "Normalized JSON Triage Bundle",
        "size_bytes": json_path.stat().st_size,
        "sha256": sha,
        "records_parsed": len(events),
        "provenance": provenance,
    }
    return events, manifest
