# Reports/api_reporter.py
import json
import html as ihtml
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from colorama import Fore, Style

OUTPUT_DIR = Path("Reports/output")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def _sev_class(sev: str) -> str:
    s = (sev or "").upper()
    if s == "CRITICAL":
        return "sev-critical"
    if s == "HIGH":
        return "sev-high"
    if s == "MEDIUM":
        return "sev-medium"
    if s == "LOW":
        return "sev-low"
    if s == "INFO":
        return "sev-info"
    return "sev-unknown"

def _section_count(results: Dict[str, List[Dict[str, Any]]]) -> int:
    return sum(len(v) for v in results.values())

def generate_json(results: Dict[str, List[Dict[str, Any]]], cfg: Dict[str, Any]) -> Path:
    path = OUTPUT_DIR / "api_security_report.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    return path

def generate_html(results: Dict[str, List[Dict[str, Any]]], cfg: Dict[str, Any]) -> Path:
    title = cfg.get("report", {}).get("report_header", "Header")
    report_type = cfg.get("report", {}).get("API_report", "API Security Report")
    api_link = cfg.get("API_Scanner", {}).get("base_url", "N/A")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    company = cfg.get("tool_info", {}).get("company_name", "Your Company")
    footer = cfg.get("report", {}).get("report_footer", "Footer")
    year = cfg.get("tool_info", {}).get("year", "2025")
    total = _section_count(results)

    # minimal, focused stylesheet (kept lean)
    css = """
    body {
        font-family: 'Inter', Arial, sans-serif;
        background: #eef2ff; /* soft pastel background */
        color: #1e293b;
        margin: 0;
        padding: 30px;
    }
    .container {
        max-width: 1200px;
        margin: auto;
        background: #ffffff;
        border-radius: 16px;
        padding: 25px 30px;
        box-shadow: 0 4px 18px rgba(0, 0, 0, 0.08);
    }

    /* --- HEADER --- */
    .header {
        background: linear-gradient(90deg, #2563eb, #3b82f6);
        color: white;
        border-radius: 15px;
        padding: 10px 10px;
        text-align: center;
        vertical-align: middle;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.25);
    }
    .header h1 {
        font-size: 35px;
        margin: 0;
        font-weight: 800;
    }
    .header h1 span.emoji {
        font-size: 40px;
    }

    /* --- SUBHEADER --- */
    .subheader {
        background: #c9d6f7;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 15px 15px;
        margin-top: 5px;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    }
    .subheader h2 {
        color: #1e3a8a;
        margin: 0 0 8px;
        font-size: 22px;
        font-weight: 700;
    }
    .subheader h4 {
        color: #475569;
        margin: 4px 0 0;
        font-size: 15px;
    }

    .timestamp {
        font-size: 14px;
        text-align: right;
        color: #64748b;
        margin-top: 10px;
    }

    /* --- SECTION STYLING --- */
    .section {
        margin-top: 28px;
        border-radius: 12px;
        border: 1px solid #e2e8f0;
        background: #ffffff;
        overflow: hidden;
        box-shadow: 0 2px 10px rgba(0,0,0,0.04);
    }
    .section-title {
        padding: 12px 18px;
        font-weight: 700;
        font-size: 18px;
        display: flex;
        align-items: center;
        gap: 8px;
        color: white;
    }
    .zap { background: linear-gradient(90deg, #06b6d4, #0ea5e9); }
    .sth { background: linear-gradient(90deg,#10b981,#34d399); }
    .fuz { background: linear-gradient(90deg, #8b5cf6, #a78bfa); }

    .card { padding: 18px; }
    .item {
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 12px 14px;
        margin-bottom: 10px;
        background: #f9fafb;
        transition: box-shadow 0.2s ease;
    }
    .item:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.1); }

    .k {
        display: inline-block;
        width: 160px;
        color: #580202;
        font-weight: 600;
    }

    .sev-badge, .sev-critical, .sev-high, .sev-warning, .sev-medium, .sev-low, .sev-info, .sev-unknown {
        padding: 2px 8px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 13px;
    }
    
    
    .sev-critical { background: #dc2626; color: #ffffff; }   /* Deep Red */
    .sev-high     { background: #f87171; color: #1e293b; }   /* Light Red */
    .sev-warning  { background: #facc15; color: #78350f; }   /* Amber/Yellow Warning */
    .sev-medium   { background: #fde68a; color: #1e293b; }   /* Soft Yellow */
    .sev-low      { background: #bbf7d0; color: #064e3b; }   /* Green */
    .sev-info     { background: #bfdbfe; color: #1e3a8a; }   /* Blue Info */
    .sev-unknown  { background: #e5e7eb; color: #374151; }   /* ⚪ Unknown - Neutral Gray */

    footer {
        text-align: center;
        background: #2563eb;
        color: white;
        font-weight: 600;
        border-radius: 8px;
        margin-top: 35px;
        padding: 10px;
        box-shadow: 0 4px 10px rgba(37, 99, 235, 0.3);
    }
    """

    html = [f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1.0">
        <title>{title} - API Report</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
        <style>{css}</style>
    </head>
    <body>
    <div class="container">
        <div class="header">
            <h1><span class="emoji">🕵️</span> {title}</h1>
        </div>

        <div class="subheader">
            <h2>🛡️ {report_type} - Total Findings ({total})</h2>
            <h4>API Link: {api_link}</h4>
        </div>

        <div class="timestamp">
            🕒 Report Generated: {timestamp}
        </div>
    """]

    def render_section(section_key: str, section_results: List[Dict[str, Any]], label: str, banner_class: str):
        html.append(f'<div class="section">')
        html.append(f'<div class="section-title {banner_class}">{label} ({len(section_results)})</div>')
        html.append('<div class="card">')
        if not section_results:
            html.append('<div class="item">No findings.</div>')
        for it in section_results:
            sev = _sev_class(it.get("severity",""))
            html.append('<div class="item">')
            html.append(f'<div><span class="k">Severity:</span> <span class="sev-badge {sev}">{ihtml.escape(it.get("severity","UNKNOWN"))}</span></div>')
            if it.get("title"):
                html.append(f'<div><span class="k">Title:</span> {ihtml.escape(it.get("title",""))}</div>')
            if it.get("endpoint"):
                html.append(f'<div><span class="k">Endpoint:</span> {ihtml.escape(it.get("endpoint",""))}</div>')
            if it.get("method"):
                html.append(f'<div><span class="k">Method:</span> {ihtml.escape(it.get("method",""))}</div>')
            if it.get("parameter"):
                html.append(f'<div><span class="k">Parameter:</span> {ihtml.escape(it.get("parameter",""))}</div>')
            if it.get("owasp"):
                html.append(f'<div><span class="k">OWASP:</span> {ihtml.escape(it.get("owasp",""))}</div>')
            if it.get("cwe"):
                html.append(f'<div><span class="k">CWE:</span> {ihtml.escape(str(it.get("cwe","")))}></div>')
            if it.get("description"):
                html.append(f'<div><span class="k">Description:</span> {ihtml.escape(it.get("description",""))}</div>')
            if it.get("evidence"):
                # Truncate long evidence for readability
                ev = it.get("evidence","")
                if isinstance(ev, str) and len(ev) > 1200:
                    ev = ev[:1200] + "..."
                html.append(f'<div><span class="k">Evidence:</span> <code>{ihtml.escape(ev)}</code></div>')
            refs = it.get("references") or []
            if refs:
                html.append('<div><span class="k">References:</span> ' + ", ".join(ihtml.escape(r) for r in refs) + '</div>')
            html.append('</div>')
        html.append('</div></div>')

    render_section("ZAP", results.get("ZAP", []), "<span style=\"font-size:1.25em;\">🕷️</span> OWASP ZAP", "zap")
    # render_section("Schemathesis", results.get("Schemathesis", []), "Schemathesis", "sth")
    render_section("Fuzzer", results.get("Fuzzer", []), "<span style=\"font-size:1.25em;\">💥</span> Custom Fuzzer", "fuz")

    html.append(f"""
                <footer>
                {footer} &middot; © {year} {company}
                </footer>
                </div></body></html>""")

    out = OUTPUT_DIR / "api_security_report.html"
    out.write_text("".join(html), encoding="utf-8")
    return out

def generate_api_reports(results: Dict[str, List[Dict[str, Any]]], cfg: Dict[str, Any]) -> Dict[str, str]:
    """Convenience wrapper: returns paths as strings."""
    report_dir = cfg.get('report_dir', './reports')
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, 'api_security_report.html')
    html_path = generate_html(results, cfg)
    json_path = generate_json(results, cfg)
    print(Fore.LIGHTMAGENTA_EX + f"\n[+] HTML report generated at: {report_path}", flush=True)
    return {"html": str(html_path), "json": str(json_path)}
