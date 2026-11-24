#!/usr/bin/env python3
"""
DFIR Event Log Parser & Sigma Detection Engine
Author: Bassma Alaoui Sossey
Maps Windows process creation and PowerShell telemetry to MITRE ATT&CK techniques.
"""

import json
import os
import sys
import argparse
import re
from datetime import datetime, timezone

class DetectionRule:
    def __init__(self, rule_id, title, technique_id, severity, pattern_func):
        self.rule_id = rule_id
        self.title = title
        self.technique_id = technique_id
        self.severity = severity
        self.pattern_func = pattern_func

def build_detection_engine():
    rules = [
        DetectionRule(
            rule_id="SIGMA-001",
            title="Suspicious PowerShell Base64 Encoded Command",
            technique_id="T1059.001",
            severity="HIGH",
            pattern_func=lambda event: bool(
                re.search(r"powershell(\.exe)?", event.get("Command", ""), re.IGNORECASE) and
                re.search(r"-(enc|encodedcommand|e|ec)\b", event.get("Command", ""), re.IGNORECASE)
            )
        ),
        DetectionRule(
            rule_id="SIGMA-002",
            title="LSASS Memory Dumping via Comsvcs MiniDump",
            technique_id="T1003.001",
            severity="CRITICAL",
            pattern_func=lambda event: bool(
                re.search(r"rundll32(\.exe)?", event.get("Command", ""), re.IGNORECASE) and
                re.search(r"comsvcs(\.dll)?", event.get("Command", ""), re.IGNORECASE) and
                re.search(r"minidump", event.get("Command", ""), re.IGNORECASE)
            )
        ),
        DetectionRule(
            rule_id="SIGMA-003",
            title="Persistence via Registry Run Key Addition",
            technique_id="T1547.001",
            severity="MEDIUM",
            pattern_func=lambda event: bool(
                re.search(r"reg(\.exe)?\s+add", event.get("Command", ""), re.IGNORECASE) and
                re.search(r"CurrentVersion\\Run", event.get("Command", ""), re.IGNORECASE)
            )
        ),
        DetectionRule(
            rule_id="SIGMA-004",
            title="PowerShell In-Memory Web Download Cradle",
            technique_id="T1059.001",
            severity="HIGH",
            pattern_func=lambda event: bool(
                re.search(r"(DownloadString|DownloadFile|Invoke-WebRequest|iwr|irm)", event.get("Command", ""), re.IGNORECASE) and
                re.search(r"(Invoke-Expression|iex)", event.get("Command", ""), re.IGNORECASE)
            )
        ),
        DetectionRule(
            rule_id="SIGMA-005",
            title="System Information Discovery via Command Line",
            technique_id="T1082",
            severity="LOW",
            pattern_func=lambda event: bool(
                re.search(r"systeminfo(\.exe)?", event.get("Command", ""), re.IGNORECASE)
            )
        )
    ]
    return rules

def analyze_events(events):
    engine = build_detection_engine()
    alerts = []
    
    for event in events:
        for rule in engine:
            if rule.pattern_func(event):
                alerts.append({
                    "timestamp": event.get("Timestamp", datetime.now(timezone.utc).isoformat()),
                    "rule_id": rule.rule_id,
                    "title": rule.title,
                    "technique_id": rule.technique_id,
                    "severity": rule.severity,
                    "command": event.get("Command", ""),
                    "user": event.get("User", "SYSTEM"),
                    "host": event.get("Hostname", "UNKNOWN")
                })
    return alerts

def main():
    parser = argparse.ArgumentParser(description="Windows DFIR Triage Log & Sigma Detection Engine")
    parser.add_argument("--input", required=True, help="Path to JSON event log file")
    parser.add_argument("--output", help="Path to write JSON alert report")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file {args.input} not found.")
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8") as f:
        events = json.load(f)

    alerts = analyze_events(events)

    print(f"\n==================================================================")
    print(f"  DFIR DETECTION SUMMARY: {len(alerts)} ALERTS GENERATED")
    print(f"==================================================================")
    for alert in alerts:
        color = "\033[91m" if alert["severity"] in ["CRITICAL", "HIGH"] else "\033[93m"
        reset = "\033[0m"
        print(f"{color}[{alert['severity']}]{reset} {alert['title']} ({alert['technique_id']})")
        print(f"       Command: {alert['command']}")
        print(f"       Host: {alert['host']} | User: {alert['user']}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2)
        print(f"\n[✓] Alerts exported to: {args.output}")

if __name__ == "__main__":
    main()
