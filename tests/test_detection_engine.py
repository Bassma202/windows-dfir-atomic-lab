"""
Unit Tests for DFIR Event Log Parser & Sigma Detection Rules
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from triage_collector.evtx_parser import analyze_events

class TestDetectionEngine(unittest.TestCase):
    def test_detect_encoded_powershell(self):
        sample_event = [{
            "Command": "powershell.exe -NoProfile -ExecutionPolicy Bypass -enc JAB4ACAAPQAgACIAMQAiAA==",
            "User": "LabUser",
            "Hostname": "WIN11-VICTIM"
        }]
        alerts = analyze_events(sample_event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "SIGMA-001")
        self.assertEqual(alerts[0]["technique_id"], "T1059.001")

    def test_detect_lsass_dump(self):
        sample_event = [{
            "Command": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 656 C:\\Temp\\lsass.dmp full",
            "User": "LabUser",
            "Hostname": "WIN11-VICTIM"
        }]
        alerts = analyze_events(sample_event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "SIGMA-002")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_detect_registry_persistence(self):
        sample_event = [{
            "Command": 'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Backdoor" /t REG_SZ /d "C:\\payload.exe" /f',
            "User": "LabUser",
            "Hostname": "WIN11-VICTIM"
        }]
        alerts = analyze_events(sample_event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "SIGMA-003")
        self.assertEqual(alerts[0]["technique_id"], "T1547.001")

    def test_benign_event_no_alert(self):
        sample_event = [{
            "Command": "notepad.exe C:\\Users\\LabUser\\Documents\\notes.txt",
            "User": "LabUser",
            "Hostname": "WIN11-VICTIM"
        }]
        alerts = analyze_events(sample_event)
        self.assertEqual(len(alerts), 0)

if __name__ == "__main__":
    unittest.main()
