"""Archival Forensic Case Manager separating verified artifact-backed findings from analyst hypotheses."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vesper.evtx_ingestor import ingest_binary_evtx, ingest_json_triage
from vesper.regression import run_detection_regression
from vesper.sigma_engine import load_and_compile_sigma_rules, scan_events_with_sigma

# Read-only reference to Bassma's verified historical UEMF forensic VM image on external SanDisk storage.
# Documented transparently without fabricating Sysmon logs that Windows 11 ARM could not natively generate.
HISTORICAL_UEMF_PROVENANCE = {
    "artifact_name": "62EA0032-532F-447D-B4C8-B3D6D84C8AF2.qcow2",
    "storage_classification": "Read-only historical UEMF academic evidence (external archive; not redistributed in repo)",
    "size_bytes": 30906007552,
    "verified_sha256": "d0ca8894ba0b9486093a1ca9275d97f389216aec84eaf731d9fe13e0130370d2",
    "platform_constraint_documented": (
        "Original UEMF Windows 11 ARM VM on Apple Silicon (UTM) encountered native Sysmon kernel driver "
        "incompatibility on ARM64; VESPER therefore separates this historical acquisition provenance from "
        "the reproducible laboratory case and runs live Windows PowerShell triage validation on x64 windows-latest CI."
    ),
}


def build_investigation_case(repo_root: Path) -> dict[str, Any]:
    rules_dir = repo_root / "sigma_rules"
    rules = load_and_compile_sigma_rules(rules_dir)
    regression = run_detection_regression(rules)

    evidence_manifests: list[dict[str, Any]] = []
    all_events: list[dict[str, Any]] = []

    sample_json = repo_root / "data" / "sample_incident_telemetry.json"
    if sample_json.exists():
        ev_list, man = ingest_json_triage(sample_json, provenance="laboratory_synthetic_archival_case")
        evidence_manifests.append(man)
        all_events.extend(e.to_sigma_dict() for e in ev_list)

    sample_evtx = repo_root / "data" / "sample_windows_security.evtx"
    if sample_evtx.exists():
        evtx_list, evtx_man = ingest_binary_evtx(sample_evtx)
        evidence_manifests.append(evtx_man)
        all_events.extend(e.to_sigma_dict() for e in evtx_list)

    alerts = scan_events_with_sigma(rules, all_events)
    alerts.sort(key=lambda a: a.get("timestamp", ""))

    # Strictly separate verified findings (directly backed by artifact SHA-256 + Sigma rule match) from hypotheses
    verified_findings = [
        {
            "finding_id": f"FND-{idx + 1:03d}",
            "classification": "VERIFIED_ARTIFACT_FINDING",
            "timestamp": a["timestamp"],
            "rule_id": a["rule_id"],
            "title": a["title"],
            "severity": a["level"].upper(),
            "mitre_tags": a["mitre_tags"],
            "host": a["computer"],
            "user": a["user"],
            "evidence_summary": a["command_line"] or a["target_object"],
        }
        for idx, a in enumerate(alerts)
    ]

    analyst_hypotheses = [
        {
            "hypothesis_id": "HYP-001",
            "classification": "ANALYST_HYPOTHESIS_UNCONFIRMED",
            "statement": "Initial access may have originated from a phishing attachment opened under ARCHIVES\\j.moreau prior to T1059.001.",
            "required_corroboration": "Email gateway logs, browser download history, and NTFS Zone.Identifier ADS.",
        },
        {
            "hypothesis_id": "HYP-002",
            "classification": "ANALYST_HYPOTHESIS_UNCONFIRMED",
            "statement": "Credential material from LSASS dump (T1003.001) could have been staged for lateral movement before log clearing (T1070.001).",
            "required_corroboration": "Domain controller Kerberos/NTLM Event ID 4624/4768 logs and network firewall flows.",
        },
    ]

    return {
        "case_id": "VESPER-CASE-2026-ARC04",
        "case_title": "Archival Workstation ARC-WS-04 Compromise Investigation (Synthetic Laboratory Case)",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "historical_uemf_provenance": HISTORICAL_UEMF_PROVENANCE,
        "evidence_manifests": evidence_manifests,
        "compiled_sigma_rules": [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "level": r.level,
                "source_file": r.source_file,
                "mitre_tags": r.mitre_tags,
                "splunk_spl": r.splunk_spl,
                "elastic_lucene": r.elastic_lucene,
            }
            for r in rules
        ],
        "regression_summary": regression,
        "verified_findings": verified_findings,
        "analyst_hypotheses": analyst_hypotheses,
    }
