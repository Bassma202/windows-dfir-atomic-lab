#!/usr/bin/env python3
"""Run VESPER pySigma compilation, detection regression, and forensic case generation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vesper.case_manager import build_investigation_case  # noqa: E402


def main() -> None:
    case = build_investigation_case(ROOT)
    out = ROOT / "evidence" / "vesper_case_evidence.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(case, indent=2), encoding="utf-8")

    reg = case["regression_summary"]["metrics"]
    print("=" * 72)
    print(f"VESPER CASE REPORT | {case['case_id']}")
    print(f"Compiled Sigma Rules (pySigma) : {len(case['compiled_sigma_rules'])}")
    print(
        f"Regression Metrics             : Precision={reg['precision_pct']}% | "
        f"Recall={reg['recall_pct']}% | FPR={reg['false_positive_rate_pct']}% | F1={reg['f1_pct']}%"
    )
    print(f"Verified Findings              : {len(case['verified_findings'])}")
    print(f"Unconfirmed Hypotheses         : {len(case['analyst_hypotheses'])}")
    print("=" * 72)


if __name__ == "__main__":
    main()
