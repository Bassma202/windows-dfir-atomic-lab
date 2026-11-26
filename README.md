# VESPER — Digital Forensics, Incident Investigation & Detection Engineering

VESPER is a Detection-as-Code and Digital Forensics & Incident Response (DFIR) engineering platform implementing genuine `pySigma` SIEM compilation, XXE-safe binary Windows `.evtx` ingestion (`python-evtx` + `defusedxml`), labeled precision/recall/FPR detection regression testing, non-destructive Windows PowerShell triage collection with SHA-256 chain-of-custody manifests, and an archival case-management workbench separating verified findings from analyst hypotheses.

## Architecture & Core Capabilities
- **Genuine `pySigma` Detection-as-Code (`src/vesper/sigma_engine.py`):** Parses and schema-validates six MITRE ATT&CK-mapped Sigma YAML rules (`sigma_rules/*.yml`) using `SigmaRule.from_yaml()` and compiles them via official `pysigma-backend-splunk` (Splunk SPL) and `pysigma-backend-elasticsearch` (Elastic Lucene ECS) pipelines.
- **Binary Windows EVTX & Triage Ingestion (`src/vesper/evtx_ingestor.py`):** Ingests binary Windows `.evtx` logs via `python-evtx` with `defusedxml` XXE protection, computes SHA-256 chain-of-custody hashes for every artifact, and normalizes records into a unified forensic event schema.
- **Detection Regression Suite (`src/vesper/regression.py`):** Scores every rule against a 12-case labeled corpus (`6` attack cases + `6` realistic benign administrative Windows events) to measure Precision, Recall, F1-score, and False Positive Rate (`FPR`).
- **Windows Live Triage & Safe Emulation (`triage_collector/collect_triage.ps1`, `adversary_emulation/atomic_tests.ps1`):** Non-destructive PowerShell scripts producing SHA-256 hashed triage manifests (`manifest_sha256.json`) and separating planned, safely executed, and cleanup-verified telemetry—validated natively on GitHub Actions `windows-latest`.
- **Archival Forensic Workbench (`src/vesper/web.py`):** FastAPI investigation interface clearly distinguishing verified artifact-backed findings from unconfirmed analyst hypotheses, with Markdown report export (`/api/report.md`).

## Verified Engineering Evidence
- **Sigma Rules Compiled via `pySigma`:** `6` rules (`T1059.001` PowerShell Base64 & ScriptBlock 4104 cradle, `T1003.001` LSASS Comsvcs MiniDump, `T1547.001` Registry Run persistence, `T1105` Certutil download, `T1070.001` Wevtutil log clearing) compiled cleanly to Splunk SPL and Elastic Lucene ECS.
- **Regression Metrics (12 labeled cases):** `Precision = 100.0%`, `Recall = 100.0%`, `FPR = 0.0%`, `F1 = 100.0%` (`TP=6, TN=6, FP=0, FN=0`).
- **Dual-OS CI:** Verified across both `ubuntu-latest` (Python `pySigma`, `python-evtx`, `pytest`, `ruff`, `bandit`) and `windows-latest` (PowerShell AST validation + live triage collection with SHA-256 manifest + safe benign execution).
- **Evidence Provenance:** See [docs/FORENSIC_PROVENANCE.md](docs/FORENSIC_PROVENANCE.md) for the transparent separation of historical UEMF academic VM provenance from the reproducible laboratory case.

## Quickstart
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make test lint security case
make serve   # http://127.0.0.1:8006
```
