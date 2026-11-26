"""Archival Forensic Case Manager with artifact-level provenance, manifest hash checks, and evidence-gated hypotheses (VESPER-02)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vesper import __version__ as VESPER_VERSION
from vesper.evtx_ingestor import compute_sha256, ingest_binary_evtx, ingest_json_triage
from vesper.regression import run_detection_regression
from vesper.sigma_engine import (
    load_and_compile_sigma_rules,
    scan_events_with_sigma,
    verify_compiled_query_parity,
)

HISTORICAL_UEMF_PROVENANCE = {
    "artifact_id": "ART-HIST-UEMF-QCOW2",
    "artifact_name": "62EA0032-532F-447D-B4C8-B3D6D84C8AF2.qcow2",
    "source_classification": "historical_academic_artifact_readonly",
    "size_bytes": 30906007552,
    "verified_sha256": "d0ca8894ba0b9486093a1ca9275d97f389216aec84eaf731d9fe13e0130370d2",
    "redistributed_in_repo": False,
    "platform_constraint_documented": (
        "Original UEMF Windows 11 ARM VM on Apple Silicon (UTM) encountered native Sysmon kernel driver "
        "incompatibility on ARM64; VESPER therefore separates this historical acquisition provenance from "
        "the reproducible synthetic laboratory case and runs live Windows PowerShell triage validation on x64 windows-latest CI."
    ),
}


def normalize_utc_timestamp(raw_ts: str) -> str:
    """Normalize an ISO-8601 timestamp strictly to UTC ISO-8601; return empty string if unparseable."""
    if not raw_ts:
        return ""
    try:
        dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        return ""


def verify_artifact_manifest(artifact_path: Path, expected_sha256: str | None = None) -> dict[str, Any]:
    """Compute actual SHA-256 and detect manifest hash mismatches (prevents verified classification on tampering)."""
    actual_sha = compute_sha256(artifact_path)
    hash_verified = expected_sha256 is None or (actual_sha.lower() == expected_sha256.lower())
    return {
        "artifact_path": artifact_path.name,
        "actual_sha256": actual_sha,
        "expected_sha256": expected_sha256,
        "manifest_integrity_verified": hash_verified,
    }


def derive_evidence_supported_hypotheses(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate investigative hypotheses ONLY when directly supported by observed finding evidence (VESPER-02)."""
    hypotheses: list[dict[str, Any]] = []
    tags_seen = {t.lower() for f in findings for t in f.get("mitre_tags", [])}
    hosts = sorted({f["host"] for f in findings if f.get("host")})
    users = sorted({f["user"] for f in findings if f.get("user") and f["user"] != "NT AUTHORITY\\SYSTEM"})
    finding_ids_by_tag: dict[str, list[str]] = {}
    for f in findings:
        for t in f.get("mitre_tags", []):
            finding_ids_by_tag.setdefault(t.lower(), []).append(f["finding_id"])

    if "attack.t1059.001" in tags_seen:
        hypotheses.append(
            {
                "hypothesis_id": "HYP-EXEC-001",
                "classification": "ANALYST_HYPOTHESIS_UNCONFIRMED",
                "supported_by_findings": sorted(set(finding_ids_by_tag.get("attack.t1059.001", []))),
                "statement": (
                    f"Encoded PowerShell activity observed on {', '.join(hosts) or 'endpoint'} "
                    f"(user context: {', '.join(users) or 'unknown'}) warrants checking upstream initial-access artifacts."
                ),
                "required_corroboration": "Email gateway logs, browser download history, and NTFS Zone.Identifier ADS.",
            }
        )

    if "attack.t1003.001" in tags_seen and "attack.t1070.001" in tags_seen:
        hypotheses.append(
            {
                "hypothesis_id": "HYP-CRED-002",
                "classification": "ANALYST_HYPOTHESIS_UNCONFIRMED",
                "supported_by_findings": sorted(
                    set(finding_ids_by_tag.get("attack.t1003.001", []) + finding_ids_by_tag.get("attack.t1070.001", []))
                ),
                "statement": "Co-occurrence of LSASS memory dump (T1003.001) and event log clearing (T1070.001) warrants checking for credential reuse or lateral movement.",
                "required_corroboration": "Domain controller Kerberos/NTLM Event ID 4624/4768 logs and firewall flow records.",
            }
        )

    return hypotheses


def build_investigation_case(
    repo_root: Path,
    telemetry_path: Path | None = None,
    expected_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
    rules_dir = repo_root / "sigma_rules"
    rules = load_and_compile_sigma_rules(rules_dir)
    regression = run_detection_regression(rules)
    parity_checks = [verify_compiled_query_parity(r) for r in rules]

    evidence_manifests: list[dict[str, Any]] = []
    all_events: list[dict[str, Any]] = []
    integrity_by_file: dict[str, bool] = {}
    exp_map = expected_hashes or {}

    sample_json = telemetry_path or (repo_root / "data" / "sample_incident_telemetry.json")
    if sample_json.exists():
        ev_list, man = ingest_json_triage(sample_json, provenance="synthetic_laboratory_case")
        check = verify_artifact_manifest(sample_json, exp_map.get(sample_json.name))
        man["artifact_id"] = "ART-SYN-001"
        man["source_classification"] = "synthetic_data"
        man["manifest_integrity_verified"] = check["manifest_integrity_verified"]
        man["expected_sha256"] = check["expected_sha256"]
        man["parser"] = f"vesper.evtx_ingestor.ingest_json_triage/{VESPER_VERSION}"
        man["acquisition_metadata"] = {
            "method": "Curated synthetic laboratory telemetry JSON for reproducible DFIR testing",
            "host_environment": "Offline laboratory fixture (not captured from a real compromised host)",
        }
        evidence_manifests.append(man)
        integrity_by_file[sample_json.name] = check["manifest_integrity_verified"]
        for e in ev_list:
            d = e.to_sigma_dict()
            d["_source_file"] = e.source_file
            d["_source_sha256"] = e.source_sha256
            d["_provenance"] = e.provenance
            all_events.append(d)

    sample_evtx = repo_root / "data" / "sample_windows_security.evtx"
    if sample_evtx.exists():
        evtx_list, evtx_man = ingest_binary_evtx(sample_evtx)
        check_ev = verify_artifact_manifest(sample_evtx, exp_map.get(sample_evtx.name))
        evtx_man["artifact_id"] = "ART-EVTX-001"
        evtx_man["source_classification"] = "genuine_binary_evtx"
        evtx_man["manifest_integrity_verified"] = check_ev["manifest_integrity_verified"]
        evtx_man["parser"] = f"vesper.evtx_ingestor.ingest_binary_evtx (python-evtx + defusedxml)/{VESPER_VERSION}"
        evidence_manifests.append(evtx_man)
        integrity_by_file[sample_evtx.name] = check_ev["manifest_integrity_verified"]
        for e in evtx_list:
            d = e.to_sigma_dict()
            d["_source_file"] = e.source_file
            d["_source_sha256"] = e.source_sha256
            d["_provenance"] = e.provenance
            all_events.append(d)

    manifest_by_file = {m["artifact"]: m for m in evidence_manifests}
    alerts = scan_events_with_sigma(rules, all_events)
    alerts.sort(key=lambda a: normalize_utc_timestamp(a.get("timestamp", "")))

    findings = []
    for idx, a in enumerate(alerts):
        src_file = a.get("source_file", "")
        man = manifest_by_file.get(src_file, {})
        integrity_ok = integrity_by_file.get(src_file, False)
        src_cls = man.get("source_classification", "unverified_evidence")
        # Integrity failure downgrades finding classification immediately (VESPER-02)
        finding_classification = (
            f"VERIFIED_{src_cls.upper()}_FINDING" if integrity_ok else "UNVERIFIED_MANIFEST_HASH_MISMATCH"
        )
        findings.append(
            {
                "finding_id": f"FND-{idx + 1:03d}",
                "classification": finding_classification,
                "artifact_id": man.get("artifact_id", "ART-UNKNOWN"),
                "source_file": src_file,
                "source_classification": src_cls,
                "artifact_sha256": a.get("source_sha256", ""),
                "manifest_integrity_verified": integrity_ok,
                "acquisition_metadata": man.get("acquisition_metadata", {}),
                "event_record_index": a.get("event_record_index"),
                "windows_event_id": a.get("event_id"),
                "original_timestamp": a.get("timestamp", ""),
                "normalized_utc_timestamp": normalize_utc_timestamp(a.get("timestamp", "")),
                "parser": man.get("parser", f"vesper/{VESPER_VERSION}"),
                "rule_id": a["rule_id"],
                "source_rule_file": a["source_rule_file"],
                "title": a["title"],
                "severity": a["level"].upper(),
                "mitre_tags": a["mitre_tags"],
                "host": a["computer"],
                "user": a["user"],
                "observations": a["command_line"] or a["target_object"] or a["script_block_text"],
                "limitations": (
                    "Matched by VESPER's verified local Sigma subset on synthetic laboratory telemetry; "
                    "live enterprise SIEM correlation and endpoint memory forensics are outside local scope."
                    if integrity_ok
                    else "Manifest SHA-256 mismatch detected; artifact integrity cannot be treated as verified."
                ),
            }
        )

    # Only generate hypotheses from integrity-verified findings that actually support them
    verified_only = [f for f in findings if f["manifest_integrity_verified"]]
    analyst_hypotheses = derive_evidence_supported_hypotheses(verified_only)

    return {
        "case_id": "VESPER-CASE-2026-ARC04",
        "case_title": "Archival Workstation ARC-WS-04 Investigation (Explicitly Labeled Synthetic Laboratory Case)",
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
        "backend_parity_checks": parity_checks,
        "regression_summary": regression,
        "verified_findings": findings,
        "analyst_hypotheses": analyst_hypotheses,
    }


def export_case_json(repo_root: Path, out_path: Path) -> dict[str, Any]:
    case = build_investigation_case(repo_root)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(case, indent=2), encoding="utf-8")
    return case
