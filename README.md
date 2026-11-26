# VESPER — Digital Forensics, Incident Investigation & Detection Engineering

VESPER is a Detection-as-Code and Digital Forensics & Incident Response (DFIR) engineering platform implementing genuine `pySigma` SIEM compilation, strict Sigma-subset local evaluation with logsource & boolean-condition enforcement, XXE-safe binary Windows `.evtx` ingestion (`python-evtx` + `defusedxml`), labeled precision/recall/FPR detection regression testing, non-destructive Windows PowerShell triage collection with SHA-256 chain-of-custody manifests, and an archival forensic case workbench enforcing artifact-level provenance and evidence-gated hypotheses.

## Architecture & Core Capabilities
- **Genuine `pySigma` Detection-as-Code & Strict Subset Evaluator (`src/vesper/sigma_engine.py`):**
  - Parses and schema-validates six MITRE ATT&CK-mapped Sigma YAML rules (`sigma_rules/*.yml`) using `SigmaRule.from_yaml()` and compiles isolated rule instances via official `pysigma-backend-splunk` (`splunk_windows_pipeline`) and `pysigma-backend-elasticsearch` (`ecs_windows`) backends so backend pipeline mutations never cross-contaminate compiled queries.
  - Explicitly validates and enforces the supported local evaluation subset (`contains`, `endswith`, `startswith`, `all`, safe recursive-descent `and`/`or`/`not`/parentheses boolean conditions, and `logsource` EventID/Channel filtering). Unsupported constructs (e.g., `|re`, `|base64offset`, `| count()`) raise `UnsupportedSigmaConstructError` explicitly rather than silently mis-evaluating.
  - Provides static compiled-query field-mapping parity checks (`verify_compiled_query_parity`) across Splunk SPL and Elastic ECS Lucene outputs.
- **Binary Windows EVTX & Triage Ingestion (`src/vesper/evtx_ingestor.py`):** Ingests binary Windows `.evtx` logs via `python-evtx` with `defusedxml` XXE protection, computes SHA-256 chain-of-custody hashes for every artifact, and normalizes records into a unified forensic event schema.
- **Detection Regression Suite (`src/vesper/regression.py`):** Scores every rule against a 12-case labeled corpus (`6` attack cases + `6` realistic benign administrative Windows events) to measure Precision, Recall, F1-score, and False Positive Rate (`FPR`).
- **Windows Live Triage & Safe Emulation (`triage_collector/collect_triage.ps1`, `adversary_emulation/atomic_tests.ps1`):** Non-destructive PowerShell scripts producing SHA-256 hashed triage manifests (`manifest_sha256.json`) and separating planned, safely executed, and cleanup-verified telemetry—validated natively on GitHub Actions `windows-latest`.
- **Artifact-Provenance & Evidence-Gated Case Workbench (`src/vesper/case_manager.py`, `src/vesper/web.py`):**
  - Tracks per-artifact provenance (`source_file`, `artifact_sha256`, `ingestion_timestamp`, `provenance_classification`, `manifest_verification_status`).
  - Verifies artifact hashes against chain-of-custody manifests when provided; hash mismatches automatically downgrade findings to `UNVERIFIED_MANIFEST_HASH_MISMATCH`.
  - Derives follow-up investigative hypotheses dynamically from actual observed telemetry/detections rather than hardcoding static case narratives—unrelated or tampered datasets emit zero unsupported hypotheses.

## Verified Engineering Evidence
- **Sigma Rules Compiled via `pySigma`:** `6` rules (`T1059.001` PowerShell Base64 & ScriptBlock 4104 cradle, `T1003.001` LSASS Comsvcs MiniDump, `T1547.001` Registry Run persistence, `T1105` Certutil download, `T1070.001` Wevtutil log clearing) compiled cleanly to Splunk SPL and Elastic Lucene ECS with verified static field-mapping parity.
- **Regression Metrics (12 labeled synthetic cases):** `Precision = 100.0%`, `Recall = 100.0%`, `FPR = 0.0%`, `F1 = 100.0%` (`TP=6, TN=6, FP=0, FN=0`).
- **Dual-OS CI:** Verified across both `ubuntu-latest` (Python `pySigma`, `python-evtx`, `pytest`, `ruff`, `bandit`) and `windows-latest` (PowerShell AST validation + live triage collection with SHA-256 manifest + safe benign execution).
- **Evidence Provenance:** See [docs/FORENSIC_PROVENANCE.md](docs/FORENSIC_PROVENANCE.md) for the transparent separation of historical UEMF academic VM provenance from the reproducible laboratory case.

## Known Limitations & Scope Boundaries
- The local Python Sigma evaluator intentionally supports a strict, documented Sigma subset (standard Windows process/registry/PowerShell logsources, basic string modifiers, and boolean conditions without aggregations/timeframes) and fails closed on unsupported Sigma syntax.
- Static query compilation and field-mapping parity are verified locally via `pySigma`, while live SIEM search execution requires external Splunk or Elasticsearch deployments not bundled in this repository.
- The 12-case detection regression corpus is a controlled laboratory corpus (6 attack + 6 benign administrative events); real-world enterprise tuning requires testing against production host telemetry baselines.

## Quickstart
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make test lint security case
make serve   # http://127.0.0.1:8006
```
