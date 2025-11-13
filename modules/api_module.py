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

# Windows asyncio fix
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

def build_fuzzer_targets(fuzzer_cfg):
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

def api_page(cfg, result_card_fn):
    st.header("🌐 API Vulnerability Scanner")

    api_cfg = cfg.get("API_Scanner", {})
    auth_cfg = api_cfg.get("auth", {})
    zap_cfg = api_cfg.get("zap", {})
    fuzzer_cfg = api_cfg.get("fuzzer", {})

    with st.form("api_config_form"):
        base_url = st.text_input("API URL", value=api_cfg.get("base_url", "https://httpbin.org"))
        auth_types = ["none", "bearer", "api_key", "basic"]
        auth_type = st.selectbox("Auth Type", auth_types, index=auth_types.index(auth_cfg.get("type", "none")))

        token = header = value = username = password = ""
        if auth_type == "bearer":
            token = st.text_input("Bearer Token", value=auth_cfg.get("token", ""), type="password")
        elif auth_type == "api_key":
            header = st.text_input("API Key Header", value=auth_cfg.get("header", "x-api-key"))
            value = st.text_input("API Key Value", value=auth_cfg.get("value", ""), type="password")
        elif auth_type == "basic":
            username = st.text_input("Username", value=auth_cfg.get("username", ""))
            password = st.text_input("Password", value=auth_cfg.get("password", ""), type="password")

        zap_enabled = st.checkbox("Enable ZAP", value=zap_cfg.get("enabled", False))
        zap_api_key = st.text_input("ZAP API Key", value=zap_cfg.get("api_key", ""), type="password")
        zap_proxy = st.text_input("ZAP Proxy", value=zap_cfg.get("proxy", "http://127.0.0.1:8080"))
        new_targets = build_fuzzer_targets(fuzzer_cfg)

        if st.form_submit_button("💾 Save Configuration"):
            cfg["API_Scanner"] = {
                "base_url": base_url,
                "auth": {"type": auth_type, "token": token, "header": header, "value": value,
                         "username": username, "password": password},
                "zap": {"enabled": zap_enabled, "api_key": zap_api_key, "proxy": zap_proxy},
                "fuzzer": {"targets": new_targets},
            }
            st.success("✅ API configuration saved successfully!")

    if st.button("🚀 Run API Scan"):
        with st.spinner("Running API vulnerability scans..."):
            try:
                start_time = perf_counter()
                api_results = asyncio.run(scan_api(cfg))
                st.session_state["api_results"] = api_results

                paths = api_reporter.generate_api_reports(api_results, cfg)
                st.session_state["api_report_html"] = Path(paths["html"]).read_bytes()
                st.session_state["api_report_json"] = Path(paths["json"]).read_bytes()

                elapsed = round(perf_counter() - start_time, 2)
                st.success(f"✅ API scan complete in {elapsed} seconds!")
            except Exception as e:
                st.error(f"API scan failed: {e}")

    if "api_report_html" in st.session_state:
        st.download_button("📑 Download HTML Report", data=st.session_state["api_report_html"],
                           file_name="api_security_report.html", mime="text/html")
    if "api_report_json" in st.session_state:
        st.download_button("📂 Download JSON Report", data=st.session_state["api_report_json"],
                           file_name="api_security_report.json", mime="application/json")

    if "api_results" in st.session_state:
        results = st.session_state["api_results"]
        if isinstance(results, dict):
            result_card_fn("ZAP", results.get("ZAP", []))
            result_card_fn("Fuzzer", results.get("Fuzzer", []))
