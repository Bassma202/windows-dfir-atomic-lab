"""Automated test suite for VESPER pySigma compilation, EVTX/XML parsing, regression scoring, and FastAPI UI."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from vesper.case_manager import build_investigation_case
from vesper.evtx_ingestor import ingest_json_triage, parse_evtx_xml_record
from vesper.regression import run_detection_regression
from vesper.sigma_engine import load_and_compile_sigma_rules
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


def test_pysigma_validates_and_compiles_all_six_rules() -> None:
    rules = load_and_compile_sigma_rules(ROOT / "sigma_rules")
    assert len(rules) == 6
    for r in rules:
        assert r.rule_id
        assert r.splunk_spl, f"Empty Splunk SPL for {r.source_file}"
        assert r.elastic_lucene, f"Empty Elastic Lucene for {r.source_file}"
        assert len(r.mitre_tags) >= 1


def test_detection_regression_achieves_high_precision_and_zero_false_positives() -> None:
    rules = load_and_compile_sigma_rules(ROOT / "sigma_rules")
    reg = run_detection_regression(rules)
    assert reg["counts"]["tp"] == 6
    assert reg["counts"]["tn"] == 6
    assert reg["counts"]["fp"] == 0
    assert reg["counts"]["fn"] == 0
    assert reg["metrics"]["precision_pct"] == 100.0
    assert reg["metrics"]["recall_pct"] == 100.0
    assert reg["metrics"]["false_positive_rate_pct"] == 0.0


def test_evtx_xml_and_json_ingestion_with_sha256_custody() -> None:
    ev = parse_evtx_xml_record(SAMPLE_WINDOWS_EVTX_XML, source_file="sample.evtx", source_sha256="a" * 64)
    assert ev.event_id == 1
    assert ev.computer == "ARC-WS-04.archives.local"
    assert "comsvcs.dll" in ev.command_line

    events, manifest = ingest_json_triage(ROOT / "data" / "sample_incident_telemetry.json")
    assert len(events) >= 1
    assert len(manifest["sha256"]) == 64


def test_case_manager_and_fastapi_workbench() -> None:
    case = build_investigation_case(ROOT)
    assert case["historical_uemf_provenance"]["verified_sha256"].startswith("d0ca8894")
    assert len(case["verified_findings"]) >= 1
    assert len(case["analyst_hypotheses"]) >= 1

    app = create_app(repo_root=ROOT)
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200
    assert client.get("/api/case").status_code == 200
    rep = client.get("/api/report.md")
    assert rep.status_code == 200
    assert "Verified Artifact-Backed Findings" in rep.json()["markdown"]
