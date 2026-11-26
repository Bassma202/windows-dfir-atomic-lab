"""Comprehensive VESPER test suite & remediation regression tests (VESPER-01 & VESPER-02)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vesper.case_manager import build_investigation_case
from vesper.evtx_ingestor import ingest_json_triage, parse_evtx_xml_record
from vesper.regression import run_detection_regression
from vesper.sigma_engine import (
    UnsupportedSigmaConstructError,
    evaluate_sigma_rule_on_event,
    load_and_compile_sigma_rules,
    validate_supported_sigma_subset,
    verify_compiled_query_parity,
)
from vesper.web import create_app

ROOT = Path(__file__).resolve().parents[1]

SAMPLE_WINDOWS_EVTX_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-11-24T09:16:18.000000Z" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>ARC-WS-04.archives.local</Computer>
  </System>
  <EventData>
    <Data Name="User">NT AUTHORITY\\SYSTEM</Data>
    <Data Name="Image">C:\\Windows\\System32\\rundll32.exe</Data>
    <Data Name="CommandLine">rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 656 C:\\Temp\\dump.bin full</Data>
  </EventData>
</Event>"""


def test_vesper01_pysigma_compilation_subset_rejection_logsource_and_parity() -> None:
    """VESPER-01: Reject unsupported Sigma constructs, enforce logsource filtering, and verify backend parity."""
    rules = load_and_compile_sigma_rules(ROOT / "sigma_rules")
    assert len(rules) == 6
    for r in rules:
        assert r.rule_id and r.splunk_spl and r.elastic_lucene
        parity = verify_compiled_query_parity(r)
        assert parity["splunk_fields_present"] is True
        assert parity["elastic_ecs_fields_present"] is True

    # Reject unsupported modifier (`|re`)
    with pytest.raises(UnsupportedSigmaConstructError):
        validate_supported_sigma_subset(
            {
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {"selection": {"CommandLine|re": ".*bad.*"}, "condition": "selection"},
            },
            "bad_re.yml",
        )

    # Reject unsupported aggregation pipe condition
    with pytest.raises(UnsupportedSigmaConstructError):
        validate_supported_sigma_subset(
            {
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection | count() > 5"},
            },
            "bad_agg.yml",
        )

    # Logsource enforcement: a PowerShell process_creation rule MUST NOT match EventID 13 (registry_set)
    ps_rule = [r for r in rules if r.source_file == "proc_creation_win_powershell_base64_encoded.yml"][0]
    wrong_logsource_event = {
        "EventID": 13,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -enc AAAA",
    }
    assert evaluate_sigma_rule_on_event(ps_rule, wrong_logsource_event) is False

    # Missing required field returns False cleanly
    assert evaluate_sigma_rule_on_event(ps_rule, {"EventID": 1, "Image": r"C:\Windows\System32\powershell.exe"}) is False


def test_detection_regression_achieves_high_precision_and_zero_false_positives() -> None:
    rules = load_and_compile_sigma_rules(ROOT / "sigma_rules")
    reg = run_detection_regression(rules)
    assert reg["counts"] == {"tp": 6, "fp": 0, "tn": 6, "fn": 0}
    assert reg["metrics"] == {"precision_pct": 100.0, "recall_pct": 100.0, "false_positive_rate_pct": 0.0, "f1_pct": 100.0}


def test_vesper02_artifact_provenance_hash_mismatch_and_evidence_gated_hypotheses(tmp_path: Path) -> None:
    """VESPER-02: Enforce full artifact provenance, detect manifest hash mismatch, and gate hypotheses on evidence."""
    # 1. Valid synthetic case carries complete provenance fields & explicitly labels synthetic source
    case = build_investigation_case(ROOT)
    assert case["historical_uemf_provenance"]["source_classification"] == "historical_academic_artifact_readonly"
    assert case["historical_uemf_provenance"]["verified_sha256"].startswith("d0ca8894")
    assert len(case["verified_findings"]) == 6
    f0 = case["verified_findings"][0]
    for required_field in (
        "artifact_id", "source_classification", "artifact_sha256", "manifest_integrity_verified",
        "acquisition_metadata", "event_record_index", "original_timestamp", "normalized_utc_timestamp",
        "parser", "rule_id", "observations", "limitations",
    ):
        assert required_field in f0
    assert f0["source_classification"] == "synthetic_data"
    assert f0["manifest_integrity_verified"] is True
    assert len(case["analyst_hypotheses"]) == 2

    # 2. Invalid expected manifest SHA-256 MUST prevent verified classification AND block hypotheses!
    tampered_case = build_investigation_case(
        ROOT, expected_hashes={"sample_incident_telemetry.json": "0" * 64}
    )
    assert all(f["manifest_integrity_verified"] is False for f in tampered_case["verified_findings"])
    assert all(f["classification"] == "UNVERIFIED_MANIFEST_HASH_MISMATCH" for f in tampered_case["verified_findings"])
    assert tampered_case["analyst_hypotheses"] == []

    # 3. Unrelated benign case MUST NOT receive fixed hardcoded compromise hypotheses!
    benign_file = tmp_path / "benign_only.json"
    benign_file.write_text(
        json.dumps([
            {
                "Timestamp": "2026-11-24T08:00:00Z",
                "Computer": "CLEAN-HOST-01",
                "User": "CORP\\alice",
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Image": r"C:\Windows\System32\notepad.exe",
                "CommandLine": "notepad.exe notes.txt",
            }
        ]),
        encoding="utf-8",
    )
    benign_case = build_investigation_case(ROOT, telemetry_path=benign_file)
    assert benign_case["verified_findings"] == []
    assert benign_case["analyst_hypotheses"] == []


def test_evtx_xml_ingestion_and_fastapi_workbench() -> None:
    ev = parse_evtx_xml_record(SAMPLE_WINDOWS_EVTX_XML, source_file="sample.evtx", source_sha256="a" * 64)
    assert ev.event_id == 1 and ev.computer == "ARC-WS-04.archives.local" and "comsvcs.dll" in ev.command_line

    events, manifest = ingest_json_triage(ROOT / "data" / "sample_incident_telemetry.json")
    assert len(events) >= 1 and len(manifest["sha256"]) == 64

    client = TestClient(create_app(repo_root=ROOT))
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200
    assert client.get("/api/case").status_code == 200
    assert "Verified Artifact-Backed Findings" in client.get("/api/report.md").json()["markdown"]
