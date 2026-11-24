#!/usr/bin/env python3
"""
Detection-as-Code: Sigma Rule Transpiler & SIEM Query Compiler
Author: Bassma Alaoui Sossey
Converts generic Sigma YAML rules into Elasticsearch KQL, Splunk SPL, and Microsoft Sentinel queries.
"""

import os
import sys

def compile_sigma_to_splunk(rule_title, detection_selection):
    """Compiles basic Sigma detection criteria to Splunk SPL."""
    conditions = []
    for field, values in detection_selection.items():
        clean_field = field.split("|")[0]
        if isinstance(values, list):
            val_str = " OR ".join([f'{clean_field}="*{v}*"' for v in values])
            conditions.append(f"({val_str})")
        else:
            conditions.append(f'{clean_field}="*{values}*"')
    spl = "index=windows_sysmon " + " AND ".join(conditions)
    return spl

def compile_sigma_to_elastic(rule_title, detection_selection):
    """Compiles basic Sigma detection criteria to Elasticsearch KQL."""
    conditions = []
    for field, values in detection_selection.items():
        clean_field = field.split("|")[0]
        if clean_field == "Image":
            clean_field = "process.executable"
        elif clean_field == "CommandLine":
            clean_field = "process.command_line"
        elif clean_field == "TargetObject":
            clean_field = "registry.path"

        if isinstance(values, list):
            val_str = " or ".join([f'{clean_field}: *{v}*' for v in values])
            conditions.append(f"({val_str})")
        else:
            conditions.append(f'{clean_field}: *{values}*')
    kql = " and ".join(conditions)
    return kql

def print_compiled_matrix():
    rules_demo = [
        {
            "title": "Suspicious PowerShell Base64 Encoded Command (T1059.001)",
            "selection": {
                "Image": ["powershell.exe", "pwsh.exe"],
                "CommandLine": ["-enc", "-encodedcommand", "-ec"]
            }
        },
        {
            "title": "LSASS Memory Dump via Comsvcs DLL MiniDump (T1003.001)",
            "selection": {
                "Image": "rundll32.exe",
                "CommandLine": ["comsvcs.dll", "MiniDump"]
            }
        },
        {
            "title": "Persistence via Windows Registry Run Keys (T1547.001)",
            "selection": {
                "TargetObject": ["\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce"]
            }
        }
    ]

    print("\n" + "=" * 75)
    print("  DETECTION-AS-CODE: SIGMA TRANSPILED SIEM QUERIES")
    print("=" * 75)
    for r in rules_demo:
        print(f"\n[RULE] {r['title']}")
        print(f"  • Splunk SPL   : {compile_sigma_to_splunk(r['title'], r['selection'])}")
        print(f"  • Elastic KQL  : {compile_sigma_to_elastic(r['title'], r['selection'])}")
    print("=" * 75 + "\n")

if __name__ == "__main__":
    print_compiled_matrix()
