"""VESPER Archival Forensic Case-Management FastAPI UI (Dark Charcoal / Warm Parchment / Muted Burgundy)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from vesper.case_manager import build_investigation_case


def create_app(repo_root: Path | None = None) -> FastAPI:
    root = repo_root or Path(__file__).resolve().parents[2]
    app = FastAPI(title="VESPER — Digital Forensics & Detection Engineering", version="2.0.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "vesper"}

    @app.get("/api/case")
    def get_case() -> dict[str, Any]:
        return build_investigation_case(root)

    @app.get("/api/report.md")
    def export_markdown_report() -> dict[str, str]:
        case = build_investigation_case(root)
        lines = [
            f"# {case['case_title']} (`{case['case_id']}`)",
            "",
            "## Verified Artifact-Backed Findings",
        ]
        for f in case["verified_findings"]:
            lines.append(f"- **{f['finding_id']} [{f['severity']}]** `{f['normalized_utc_timestamp']}` — {f['title']} (`{f['host']}` / `{f['user']}` | `{f['source_classification']}` | sha256:`{f['artifact_sha256'][:12]}`)")
        lines.append("")
        lines.append("## Unconfirmed Analyst Hypotheses")
        for h in case["analyst_hypotheses"]:
            lines.append(f"- **{h['hypothesis_id']}**: {h['statement']} *(Needs: {h['required_corroboration']})*")
        return {"case_id": case["case_id"], "markdown": "\n".join(lines)}

    @app.get("/", response_class=HTMLResponse)
    def workbench() -> str:
        case = build_investigation_case(root)
        reg = case["regression_summary"]["metrics"]
        finding_rows = "".join(
            f"<tr><td><code>{f['finding_id']}</code></td><td><span class='sev'>{f['severity']}</span></td>"
            f"<td>{f['normalized_utc_timestamp']}</td><td>{f['title']}</td><td><code>{f['observations'][:72]}</code></td></tr>"
            for f in case["verified_findings"]
        )
        rule_rows = "".join(
            f"<tr><td><strong>{r['title']}</strong><br><small>{r['source_file']}</small></td>"
            f"<td><code>{r['splunk_spl'][:90]}</code></td>"
            f"<td><code>{r['elastic_lucene'][:90]}</code></td></tr>"
            for r in case["compiled_sigma_rules"]
        )
        hyp_items = "".join(
            f"<li><strong>{h['hypothesis_id']} (Unconfirmed):</strong> {h['statement']} "
            f"<br><small>Required corroboration: {h['required_corroboration']}</small></li>"
            for h in case["analyst_hypotheses"]
        )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VESPER — Digital Forensics &amp; Detection Engineering</title>
<style>
  body {{ margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:#F5F3EF; color:#1C1917; }}
  header {{ background:#1C1917; color:#F5F3EF; padding:24px 36px; border-bottom:3px solid #7F1D1D; }}
  header h1 {{ margin:0; font-size:22px; letter-spacing:0.06em; }}
  header p {{ margin:6px 0 0; color:#A8A29E; font-size:13px; }}
  main {{ max-width:1160px; margin:28px auto; padding:0 24px; }}
  .card {{ background:#FFFFFF; border:1px solid #D6D3D1; border-radius:6px; padding:20px 24px; margin-bottom:20px; }}
  .tag {{ display:inline-block; background:#7F1D1D; color:#F5F3EF; font-size:11px; padding:3px 8px; border-radius:4px; }}
  .sev {{ display:inline-block; background:#FEE2E2; color:#7F1D1D; font-weight:600; font-size:11px; padding:2px 6px; border-radius:3px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:12px; font-size:13px; }}
  th, td {{ text-align:left; padding:9px 10px; border-bottom:1px solid #E7E5E4; vertical-align:top; }}
  th {{ background:#F5F3EF; color:#57534E; text-transform:uppercase; font-size:11px; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; }}
</style>
</head>
<body>
<header>
  <h1>VESPER — Digital Forensics, Incident Investigation &amp; Detection Engineering</h1>
  <p>Case: {case['case_id']} | pySigma Rules Compiled: {len(case['compiled_sigma_rules'])} | Regression Precision: {reg['precision_pct']}% | Recall: {reg['recall_pct']}% | FPR: {reg['false_positive_rate_pct']}%</p>
</header>
<main>
  <section class="card">
    <span class="tag">VERIFIED ARTIFACT-BACKED FINDINGS</span>
    <h2>Incident Timeline Reconstruction</h2>
    <table>
      <thead><tr><th>ID</th><th>Severity</th><th>UTC Timestamp</th><th>Sigma Rule Matched</th><th>Observed Evidence</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>
  </section>
  <section class="card">
    <span class="tag">ANALYST HYPOTHESES (SEPARATED FROM FINDINGS)</span>
    <h2>Unconfirmed Working Hypotheses</h2>
    <ul>{hyp_items}</ul>
  </section>
  <section class="card">
    <span class="tag">PYSIGMA DETECTION-AS-CODE COMPILATION</span>
    <h2>Compiled SIEM Queries (Splunk SPL &amp; Elastic Lucene)</h2>
    <table>
      <thead><tr><th>Sigma Rule</th><th>Splunk SPL (pySigma)</th><th>Elastic Lucene ECS (pySigma)</th></tr></thead>
      <tbody>{rule_rows}</tbody>
    </table>
  </section>
</main>
</body>
</html>"""

    return app
