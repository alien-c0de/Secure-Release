from tkinter.ttk import Style
import yaml
import asyncio
import sys
from pathlib import Path
import pandas as pd
import streamlit as st
import altair as alt
import json
import subprocess
import threading
import time
from time import perf_counter
from colorama import Fore, Style

# Windows asyncio fix
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from Core.openapi_parser import load_spec_from_path_or_url, extract_endpoints_from_spec
from Core.fuzzer import parameter_fuzz_values
from Core.detectors import (
    detect_status_anomalies,
    detect_sensitive_keywords,
    detect_exposed_headers,
    detect_cookie_flags
)

# Import Core modules
from Core import dependency_checker, secret_scanner, code_analyzer, code_analyzer_py

# ✅ Import Reports for HTML & JSON generation
from Reports import (
    api_reporter,
    html_report, 
    json_report
)

# inside your API Vulnerability Scanner page action
from Core.api_scanner import scan_api

# --------------------------
# Utility Functions
# --------------------------
def load_config(config_path="config.yaml"):
    """Load YAML config file."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        st.error(f"Failed to load config: {e}")
        return {}

def save_config(config_data, config_path="config.yaml"):
    """Save YAML config file."""
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
        st.success("✅ Config file updated successfully!")
    except Exception as e:
        st.error(f"Failed to save config: {e}")

async def run_scans(config_path="config.yaml"):
    """Run all scans asynchronously and return results + generate reports."""
    cfg = load_config(config_path)
    results = {}

    try:
        if cfg["technology"].upper() == "PYTHON":
            code_results = await code_analyzer_py.scan(cfg)
            if isinstance(code_results, dict) and "results" in code_results:
                code_results = code_results["results"]
            results["Code Analyzer"] = code_results or []
        elif cfg["technology"].upper() == "JAVA":
            code_results = await code_analyzer.scan(cfg)
            if isinstance(code_results, dict) and "results" in code_results:
                code_results = code_results["results"]
            results["Code Analyzer"] = code_results or []
        else:
            pass

    except Exception as e:
        results["Code Analyzer"] = [{"error": str(e)}]

    try:
        dep_results = await dependency_checker.scan(cfg)
        if isinstance(dep_results, dict) and "results" in dep_results:
            dep_results = dep_results["results"]
        results["Dependency Scan"] = dep_results or []
    except Exception as e:
        results["Dependency Scan"] = [{"error": str(e)}]

    try:
        secret_results = await secret_scanner.scan(cfg)
        if isinstance(secret_results, dict) and "results" in secret_results:
            secret_results = secret_results["results"]
        results["Secret Scanner"] = secret_results or []
    except Exception as e:
        results["Secret Scanner"] = [{"error": str(e)}]

    
    # ✅ Generate HTML & JSON reports
    try:
        html_report.generate(results, cfg)
        json_report.generate(results, cfg)
    except Exception as e:
        st.error(f"❌ Failed to generate reports: {e}")

    return results

# --------------------------
# Helpers for Visualization
# --------------------------
def aggregate_by_severity(issues, tool_name=None):
    """Count issues by severity. For Code Analyzer, use 'impact' instead of 'severity'."""
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}

    for issue in issues:
        if tool_name == "Code Analyzer":
            sev = issue.get("impact", "UNKNOWN")
        else:
            sev = issue.get("severity") or issue.get("extra", {}).get("severity") or "UNKNOWN"

        sev = str(sev).upper()
        if sev not in severity_counts:
            sev = "UNKNOWN"
        severity_counts[sev] += 1

    return severity_counts

def plot_severity_chart(severity_counts):
    """Display severity chart with Altair (extra compact)."""
    data = pd.DataFrame(
        {"Severity": list(severity_counts.keys()), "Count": list(severity_counts.values())}
    )
    chart = (
        alt.Chart(data)
        .mark_bar()
        .encode(
            x=alt.X("Severity", sort=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]),
            y=alt.Y("Count"),
            color="Severity",
            tooltip=["Severity", "Count"],
        )
        .properties(title="", height=200, width=370)
    )
    st.altair_chart(chart, use_container_width=False)

def result_card(tool, issues):
    """Render one tool's results inside a styled card box with outline + colored header."""
    count = len(issues)
    # Mild professional header colors per tool
    header_colors = {
        "Dependency Scan": "linear-gradient(90deg, #0ea5e9, #38bdf8)",  # Blue
        "Secret Scanner": "linear-gradient(90deg, #10b981, #34d399)",   # Green
        "Code Analyzer":  "linear-gradient(90deg, #f59e0b, #fbbf24)",   # Amber
        "ZAP": "linear-gradient(90deg, #0ea5e9, #fbbf24)",  # Blue
        "Fuzzer": "linear-gradient(90deg, #10b981, #34d399)",   # Green
    }
    header_bg = header_colors.get(tool, "linear-gradient(90deg, #64748b, #475569)")

    st.markdown(
        f"""
        <div style="
            border: 2px solid #e5e7eb;
            border-radius: 10px;
            margin: 15px 0;
            background-color: #ffffff;
            # box-shadow: 0 4px 14px rgba(0,0,0,0.06);
            overflow: hidden;
        ">
            <div style="
                background: {header_bg};
                color: white;
                padding: 5px 14px;
                width: 100%;
                font-weight: 700;
                font-size: 1.5rem;
                text-align:center;
                letter-spacing: .5px;
                border-radius: 10px;
            ">
                {tool} Results ({count})
            </div>
            <div style="padding: 12px;">
        """,
        unsafe_allow_html=True,
    )

    if not issues or ("error" in issues[0]):
        st.warning(f"{tool} encountered an error or found no issues.")
        st.json(issues)
    else:
        severity_counts = aggregate_by_severity(issues, tool_name=tool)
        plot_severity_chart(severity_counts)

        with st.expander(f"🔎 Detailed {tool} Results"):
            for issue in issues:
                st.json(issue)

    st.markdown("</div></div>", unsafe_allow_html=True)

def report_download_button():
    """Show styled download buttons for HTML and JSON reports if they exist."""
    html_path = Path("Reports/output/security_report.html")
    json_path = Path("Reports/output/security_report.json")

    # Scoped styling so we don't affect other buttons
    st.markdown(
        """
        <style>
        .dl-scope div[data-testid="stDownloadButton"] > button {
            background: linear-gradient(90deg, #2563eb, #3b82f6);
            color: #ffffff;
            font-weight: 700;
            border-radius: 8px;
            padding: 0.6rem 1.1rem;
            border: none;
            transition: filter .15s ease-in-out, transform .05s ease-in-out;
        }
        .dl-scope div[data-testid="stDownloadButton"] > button:hover {
            filter: brightness(0.95);
        }
        .dl-scope div[data-testid="stDownloadButton"] > button:active {
            transform: translateY(1px);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="dl-scope">', unsafe_allow_html=True)

    if html_path.exists():
        with open(html_path, "rb") as f:
            html_data = f.read()
        st.download_button(
            label="📑 Download Security Report (HTML)",
            data=html_data,
            file_name=html_path.name,
            mime="text/html",
            key="download_report_html",
        )
    else:
        st.info("ℹ️ No HTML report found yet.")

    if json_path.exists():
        with open(json_path, "rb") as f:
            json_data = f.read()
        st.download_button(
            label="📂 Download Security Report (JSON)",
            data=json_data,
            file_name=json_path.name,
            mime="application/json",
            key="download_report_json",
        )

    st.markdown('</div>', unsafe_allow_html=True)  # end .dl-scope

def build_fuzzer_targets(fuzzer_cfg):
    """Render fuzzer config section and return updated targets."""
    targets = fuzzer_cfg.get("targets", [])
    new_targets = []
    st.markdown("Define fuzzing targets (endpoints + params).")

    http_methods = ["GET", "POST", "PUT", "DELETE"]

    for i, t in enumerate(targets):
        st.markdown(f"**🎯 Target {i+1}**")
        col1, col2 = st.columns([1, 3])

        with col1:
            method = st.selectbox(
                f"Method {i+1}", http_methods,
                index=http_methods.index(t.get("method", "GET")),
                key=f"method_{i}"
            )
        with col2:
            path = st.text_input(f"Path {i+1}", value=t.get("path", "/"), key=f"path_{i}")

        params = st.text_input(
            f"Params {i+1} (comma-separated)",
            value=",".join(t.get("params", [])),
            key=f"params_{i}"
        )
        body = st.text_area(
            f"Body Template {i+1} (JSON)",
            value=json.dumps(t.get("body_template", {})),
            key=f"body_{i}"
        )
        try:
            body_template = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            body_template = {}

        new_targets.append({
            "method": method,
            "path": path,
            "params": [p.strip() for p in params.split(",") if p.strip()],
            "body_template": body_template
        })

    if st.checkbox("➕ Add a new target"):
        new_targets.append({"method": "GET", "path": "/", "params": [], "body_template": {}})

    return new_targets

# --- Main Page ---
def api_scanner_page(cfg):
    st.header("🌐 API Vulnerability Scanner")

    # --- CSS Styling (cleaned duplicates) ---
    st.markdown(
        """
        <style>
        .stButton>button { 
            font-size: 14px !important; 
            padding: 0.4em 1em !important; 
            border-radius: 8px !important; 
        } 
        .stButton>button[kind="primary"] { 
            background-color: #2e86de !important; 
            color: white !important; 
            border: none !important; 
        }
        .stButton>button[kind="secondary"] {
            background-color: #636e72 !important;
            color: white !important;
            border: none !important;
        }
        .stAlert {
            padding: 0.5rem 0.75rem !important;
            font-size: 14px !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    api_cfg = cfg.get("API_Scanner", {})
    auth_cfg = api_cfg.get("auth", {})
    zap_cfg = api_cfg.get("zap", {})
    fuzzer_cfg = api_cfg.get("fuzzer", {})

    # --- Form for Configuration ---
    with st.form("api_config_form"):
        col1, col2 = st.columns(2)

        with col1:
            with st.expander("🌍 API Target Configuration", expanded=True):
                base_url = st.text_input(
                    "API URL", 
                    value=api_cfg.get("base_url", "https://httpbin.org")
                )

        with col2:
            with st.expander("🔑 Authentication", expanded=False):
                auth_types = ["none", "bearer", "api_key", "basic"]
                auth_type = st.selectbox(
                    "Auth Type", auth_types,
                    index=auth_types.index(auth_cfg.get("type", "none"))
                )

                token = header = value = username = password = ""
                if auth_type == "bearer":
                    token = st.text_input("Bearer Token", value=auth_cfg.get("token", ""), type="password")
                elif auth_type == "api_key":
                    col1, col2 = st.columns(2)
                    header = col1.text_input("API Key Header", value=auth_cfg.get("header", "x-api-key"))
                    value = col2.text_input("API Key Value", value=auth_cfg.get("value", ""), type="password")
                elif auth_type == "basic":
                    col1, col2 = st.columns(2)
                    username = col1.text_input("Username", value=auth_cfg.get("username", ""))
                    password = col2.text_input("Password", value=auth_cfg.get("password", ""), type="password")

        col3, col4 = st.columns(2)
        with col3:
            with st.expander("🕷️ OWASP ZAP Configuration", expanded=False):
                zap_enabled = st.checkbox("Enable ZAP", value=zap_cfg.get("enabled", False))
                zap_api_key = st.text_input("ZAP API Key", value=zap_cfg.get("api_key", ""), type="password")
                zap_proxy = st.text_input("ZAP Proxy", value=zap_cfg.get("proxy", "http://127.0.0.1:8080"))

        with col4:
            with st.expander("💥 Fuzzer Configuration", expanded=False):
                new_targets = build_fuzzer_targets(fuzzer_cfg)

        # --- Save Config ---
        if st.form_submit_button("💾 Save Configuration"):
            cfg["API_Scanner"] = {
                "base_url": base_url,
                "auth": {"type": auth_type if auth_type != "none" else "",
                         "token": token, "header": header, "value": value,
                         "username": username, "password": password},
                "zap": {"enabled": zap_enabled, "api_key": zap_api_key, "proxy": zap_proxy},
                "fuzzer": {"targets": new_targets}
            }
            save_config(cfg, "config.yaml")
            st.success("✅ Configuration saved successfully!")

    # --- Run Scan ---
    if st.button("🚀 Run API Scan"):
        if not base_url:
            st.error("⚠️ Please set `API URL` before scanning.")
        else:
            with st.spinner("Running API vulnerability scans..."):
                try:
                    start_time = perf_counter()
                    print(Fore.YELLOW + Style.BRIGHT + "\n🚀 Starting API security scans...\n", flush=True)

                    api_results = asyncio.run(scan_api(cfg))
                    st.session_state["api_results"] = api_results

                    paths = api_reporter.generate_api_reports(api_results, cfg)
                    st.session_state["api_report_html"] = Path(paths["html"]).read_bytes()
                    st.session_state["api_report_json"] = Path(paths["json"]).read_bytes()

                    elapsed = round(perf_counter() - start_time, 2)
                    st.success(f"✅ API scan complete in {elapsed} seconds! Reports ready ⬇️")
                    print(Fore.YELLOW + Style.BRIGHT + f"\n⏱️ API Scan Completed in {elapsed} Seconds.\n", flush=True)
                except Exception as e:
                    st.error(f"API scan failed: {e}")

    # --- Download Reports ---
    if "api_report_html" in st.session_state and "api_report_json" in st.session_state:
        col1, col2 = st.columns(2)
        col1.download_button("📑 Download HTML Report", 
                             data=st.session_state["api_report_html"], 
                             file_name="api_security_report.html", mime="text/html")
        col2.download_button("📂 Download JSON Report", 
                             data=st.session_state["api_report_json"], 
                             file_name="api_security_report.json", mime="application/json")

    # --- Show Results ---
    results = st.session_state.get("api_results")
    if results:
        if isinstance(results, dict):
            # Expected engines (adjust if needed)
            zap_issues = results.get("ZAP", [])
            fuzzer_issues = results.get("Fuzzer", [])
            # other_issues = results.get("Other", [])

            col1, col2 = st.columns(2)

            with col1:
                result_card("ZAP Findings", zap_issues)
            with col2:
                result_card("Fuzzer Findings", fuzzer_issues)
            # with col3:
            #     result_card("Other Findings", other_issues)

        elif isinstance(results, list):
            st.subheader("🔍 API Scanner Findings")
            if not results:
                st.success("✅ No issues found.")
            else:
                result_card("API Scanner", results)
        else:
            st.warning("⚠️ Unexpected result format from API scanner.")
    else:
        st.info("No API scan results yet. Run a scan to see findings here.")

# --------------------------
# Configuration Page
# --------------------------
TECH_DEPENDENCIES = {
    "Python": ["requirements.txt", "Pipfile", "pyproject.toml"],
    "Java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "NodeJS": ["package.json", "yarn.lock"],
    ".NET": ["packages.config", "*.csproj", "*.vbproj"],
    "Go": ["go.mod", "go.sum"],
    "Ruby": ["Gemfile", "Gemfile.lock"],
}

def SAST_page(cfg, config_path):
    st.header("📊 SAST Dashboard")

    # --- Custom CSS for buttons & cards ---
    st.markdown(
        """
        <style>
       /* Smaller buttons */ 
       .stButton>button { 
            font-size: 14px !important; 
            padding: 0.4em 1em !important; 
            border-radius: 8px !important; 
        } 
       /* Primary button style */ 
       .stButton>button[kind="primary"] { 
            background-color: #2e86de !important; 
            color: white !important; 
            border: none !important; 
        }
        /* Secondary buttons */
        .stButton>button[kind="secondary"] {
            background-color: #636e72 !important;
            color: white !important;
            border: none !important;
        }
        /* Result cards smaller */
        .stAlert {
            padding: 0.5rem 0.75rem !important;
            font-size: 14px !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    # -------------------------
    # Configuration Section
    # -------------------------
    with st.expander("⚙️ Configuration", expanded=False):
        st.subheader("📄 Assessment Project Details")

        project_cfg = cfg.get("Assessment_Project_Details", {})
        name = st.text_input("Project Name", value=project_cfg.get("name", ""))
        version = st.text_input("Project Version", value=project_cfg.get("version", ""))

        technology = st.selectbox(
            "Project Technology",
            list(TECH_DEPENDENCIES.keys()),
            index=list(TECH_DEPENDENCIES.keys()).index(
                project_cfg.get("technology", "Python")
            ) if project_cfg.get("technology") in TECH_DEPENDENCIES else 0
        )

        st.write("📌 Suggested dependency files for", technology, ":")
        st.json(TECH_DEPENDENCIES[technology])

        description = st.text_area("Project Description", value=project_cfg.get("description", ""))

        if st.button("💾 Save Project Details", key="save_project"):
            cfg["Assessment_Project_Details"] = {
                "name": name,
                "version": version,
                "technology": technology,
                "description": description
            }
            cfg["technology"] = technology
            cfg["dependency_files"] = {technology.lower(): TECH_DEPENDENCIES[technology]}
            save_config(cfg, config_path)

        st.markdown("---")

        st.subheader("📂 Target Application Directory")
        folder_path = st.text_input(
            "Select application folder path:",
            value=cfg.get("target_dirs", ["./"])[0],
            help="Enter or paste the path to the application source folder"
        )

        if st.button("💾 Save Target Directory", key="save_target"):
            cfg["target_dirs"] = [folder_path]
            save_config(cfg, config_path)

    # st.markdown("---")

    # -------------------------
    # Run Security Scans
    # -------------------------
    if "results" not in st.session_state:
        st.session_state.results = None

    if st.button("🚀 Run Security Scans", key="run_scans"):
        start_time = perf_counter()
        print(Fore.YELLOW + Style.BRIGHT + "\n🚀 Starting SAST security scans... please wait...\n", flush=True)
        with st.spinner("Running scans... please wait ⏳"):
            st.session_state.results = asyncio.run(run_scans(config_path))
        # st.success("✅ Scans completed!")
        elapsed = round(perf_counter() - start_time, 2)
        st.success(f"✅ SAST scan complete in {elapsed} seconds! Reports ready ⬇️")
        print(Fore.YELLOW + Style.BRIGHT + f"\n⏱️ SAST Scan Completed in {elapsed} Seconds.\n", flush=True)
        print(Style.RESET_ALL)

    # -------------------------
    # Show Scan Results
    # -------------------------
    if st.session_state.results:
        col1, col2, col3 = st.columns(3)

        with col1:
            result_card("Dependency Scan", st.session_state.results["Dependency Scan"])
        with col2:
            result_card("Secret Scanner", st.session_state.results["Secret Scanner"])
        with col3:
            result_card("Code Analyzer", st.session_state.results["Code Analyzer"])

        st.subheader("📑 Consolidated Reports")
        report_download_button()

def start_zap_daemon(zap_path: str, api_key: str, port: int = 8081, startup_delay: int = 15):
    """
    Start OWASP ZAP daemon in a background thread (non-blocking).
    Works on Windows (zap.bat) and Linux/Mac (zap.sh).
    """
    def _run():
        try:
            process = subprocess.Popen(
                [zap_path, "-daemon", "-host", "127.0.0.1", "-port", str(port), "-config", f"api.key={api_key}"],
                stdout=subprocess.DEVNULL,  # hide ZAP logs
                stderr=subprocess.STDOUT,
                shell=False,                # important for Windows stability
            )
            print(f"⚡ ZAP daemon started on port {port}, waiting {startup_delay}s for initialization...")
            time.sleep(startup_delay)
            print("✅ ZAP daemon ready")
        except Exception as e:
            print(f"❌ Failed to start ZAP daemon: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()

# --------------------------
# Streamlit UI
# --------------------------
def main():
    st.set_page_config(page_title="Secure Release Dashboard", layout="wide")

    # Global cosmetic styles (title font + layout tweaks)
    st.markdown(
        """
        <style>
        .title-font {
            font-family: 'Viga', 'Cascadia Mono','Liberation Mono','Courier New', Courier, monospace;
            font-size: 3.5rem;
            font-weight: 900;
            text-align: center;
            # margin-bottom: 0.5rem;
            background: -webkit-linear-gradient(90deg, #9333ea, #ec4899);
            -webkit-background-clip: text;
            letter-spacing: .1px;
        }
        .tagline {
            font-family: 'Viga', 'Courier New', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 1.1rem;
            font-weight: 300;
            text-align: center;
            color: #4b5563;
            # margin-bottom: 1.8rem;
        }
        hr.divider {
            border: none;
            border-top: 1px solid #e5e7eb;
            margin: 0.5rem auto 0.25rem auto;
            width: 80%;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    # 🎯 Choose icon (options: 🧭, 🕵️, 🔐, 🧩, 🚀, 🛡️)
    # --------------------------
    # App Heading + Tagline
    # --------------------------
    st.markdown('<div class="title-font">🕵️ Secure Release</div>', unsafe_allow_html=True)
    st.markdown('<div class="tagline">From Code to Production - Secure Every Release.</div>', unsafe_allow_html=True)
    st.markdown('<hr class="divider">', unsafe_allow_html=True)

    config_path = Path("config.yaml")
    cfg = load_config(config_path)

    ZAP_PATH = cfg.get("API_Scanner", {}).get("zap", {}).get("path", "")
    API_KEY = cfg.get("API_Scanner", {}).get("zap", {}).get("api_key", "")
    PORT = cfg.get("API_Scanner", {}).get("zap", {}).get("port", 8081)
    # 🔥 Start ZAP daemon in background
    # start_zap_daemon(ZAP_PATH, API_KEY, port=PORT)

    # Only 2 menus now
    menu = ["SAST Scanner", "API Vulnerability Scanner", "Contract Scanner"]
    choice = st.sidebar.radio("📌 Menu", menu)
    
    if choice == "SAST Scanner":
        SAST_page(cfg, config_path)
    elif choice == "API Vulnerability Scanner":
        api_scanner_page(cfg)

if __name__ == "__main__":
    main()