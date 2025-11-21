# modules/api_module.py
import asyncio
import json
from pathlib import Path
from time import perf_counter
import streamlit as st
from colorama import Fore, Style
from Core.api_scanner import scan_api
from Reports import api_reporter
import sys
import yaml

# Windows asyncio fix
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

def build_fuzzer_targets(fuzzer_cfg):
    targets = fuzzer_cfg.get("targets", [])
    new_targets = []
    st.markdown("**Define fuzzing targets (endpoints + params).**")

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

def save_config(config_data, config_path="config.yaml"):
    """Save YAML config file."""
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
        st.success("✅ Config file updated successfully!")
    except Exception as e:
        st.error(f"Failed to save config: {e}")

def api_page(cfg, result_card_fn):
    st.subheader("🌐 API Vulnerability Scanner")

    with st.expander("**⚙️ API Configuration**", expanded = True):
    
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
        # with st.form("api_config_form"):
        col1, col2 = st.columns(2)

        with col1:
            with st.expander("**🌍 API Target Configuration**", expanded=True):
                base_url = st.text_input("**🌐 API Base URL:**", value=api_cfg.get("base_url", "https://httpbin.org"), help="Enter the base URL of the target API that you want to scan.")
        with col2:
            with st.expander("**🔑 Authentication**", expanded=True):
                auth_types = ["none", "bearer", "api_key", "basic"]
                auth_type = st.selectbox("**🔐 Authentication Type:**", auth_types, index=auth_types.index(auth_cfg.get("type", "none")), help="Select authentication method required by the API. Choose 'none' if no authentication is needed.")

                token = header = value = username = password = ""
                if auth_type == "bearer":
                    token = st.text_input("Bearer Token", value=auth_cfg.get("token", ""), type="password")
                elif auth_type == "api_key":
                    col1, col2 = st.columns(2)
                    header = col1.text_input("**🔑 API Key Header:**", value=auth_cfg.get("header", "x-api-key"), help="Specify the HTTP header field used to send the API key. Default is 'x-api-key'.")
                    value = col2.text_input("**🧾 API Key Value:**", value=auth_cfg.get("value", ""), type="password", help="Enter the API key value that will authenticate your request (kept confidential).")
                elif auth_type == "basic":
                    col1, col2 = st.columns(2)
                    username = col1.text_input("**👤 Username:**", value=auth_cfg.get("username", ""), help="Provide the username required for Basic Authentication.")
                    password = col2.text_input("**🔒 Password:**", value=auth_cfg.get("password", ""), type="password", help="Enter the password for Basic Authentication (kept hidden).")

        col3, col4 = st.columns(2)
        with col3:
            with st.expander("**🕷️ OWASP ZAP Configuration**", expanded=False):
                zap_enabled = st.checkbox("**Enable OWASP ZAP Scanning**", value=zap_cfg.get("enabled", False), help="Enable to run dynamic vulnerability analysis using OWASP ZAP proxy.")
                zap_api_key = st.text_input("**🔐 ZAP API Key:**", value=zap_cfg.get("api_key", ""), type="password", help="Enter the API key used to authenticate ZAP API requests.")
                zap_proxy = st.text_input("**🌐 ZAP Proxy Address:**", value=zap_cfg.get("proxy", "http://127.0.0.1:8080"), help="Specify the ZAP proxy address where HTTP traffic should be routed.")

        with col4:
            with st.expander("**💥 Fuzzer Configuration**", expanded=False):
                new_targets = build_fuzzer_targets(fuzzer_cfg)

        # --- Save Config ---
        if st.button("💾 Save Configuration"):
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
        col1.download_button("📑 Download HTML Report", data=st.session_state["api_report_html"], file_name="api_security_report.html", mime="text/html")
        col2.download_button("📂 Download JSON Report", data=st.session_state["api_report_json"], file_name="api_security_report.json", mime="application/json")

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
                result_card_fn("ZAP", zap_issues)
            with col2:
                result_card_fn("Fuzzer", fuzzer_issues)
            # with col3:
            #     result_card("Other Findings", other_issues)

        elif isinstance(results, list):
            st.subheader("🔍 API Scanner Findings")
            if not results:
                st.success("✅ No issues found.")
            else:
                result_card_fn("API Scanner", results)
        else:
            st.warning("⚠️ Unexpected result format from API scanner.")
    else:
        st.info("No API scan results yet. Run a scan to see findings here.")

