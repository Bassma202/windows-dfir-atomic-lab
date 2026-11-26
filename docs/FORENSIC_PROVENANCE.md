# VESPER — Forensic Evidence Provenance & Platform Constraints

## 1. Strict Separation of Evidence Sources
VESPER enforces an explicit boundary between historical academic acquisitions, synthetic laboratory telemetry, and live CI Windows executions:

| Source | Classification | Integrity Reference | Notes |
|---|---|---|---|
| `62EA0032-532F-447D-B4C8-B3D6D84C8AF2.qcow2` | Historical UEMF Academic VM Disk Image (Read-Only External Archive) | SHA-256 `d0ca8894ba0b9486093a1ca9275d97f389216aec84eaf731d9fe13e0130370d2` (30,906,007,552 bytes) | Preserved untouched on external archive storage; not redistributed in Git. |
| `data/sample_incident_telemetry.json` | Synthetic Laboratory Archival Case (`VESPER-CASE-2026-ARC04`) | SHA-256 computed dynamically in `evidence/vesper_case_evidence.json` | Reproducible laboratory timeline used for offline Sigma evaluation and UI demonstration. |
| `triage_collector/collect_triage.ps1` + `adversary_emulation/atomic_tests.ps1` | Live Windows PowerShell Execution (`windows-latest` CI runner) | Per-artifact SHA-256 written into `manifest_sha256.json` | Executed non-destructively on GitHub Actions `windows-latest` runner on every CI build. |

## 2. Documented Apple Silicon / Windows 11 ARM Sysmon Constraint
During the original UEMF laboratory acquisition on Apple Silicon (UTM running Windows 11 ARM64), native Sysmon kernel driver installation encountered platform driver compatibility constraints documented in the archival acquisition notes. Rather than fabricating Sysmon `.evtx` records from that VM, VESPER:
1. Documents the historical QCOW2 disk image provenance and verified SHA-256 honestly.
2. Implements a genuine binary `.evtx` ingestion pipeline (`python-evtx` + XXE-safe `defusedxml`) ready for any real Windows binary `.evtx` artifact.
3. Validates live Windows PowerShell triage collection (with SHA-256 manifest generation) and safe benign telemetry execution natively on GitHub Actions `windows-latest` x64 runners.
