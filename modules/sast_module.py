# modules/sast_module.py
import asyncio
import os
import pyfiglet
from pathlib import Path
from time import perf_counter
import streamlit as st
from colorama import Fore, Style
import sys

# Core imports
from Core import dependency_checker, secret_scanner, code_analyzer, code_analyzer_py
from Reports import html_report, json_report

# Windows asyncio fix
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
# ===============================
# Utility Functions
# ===============================

def save_config(config_data, config_path="config.yaml"):
    import yaml
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
        st.success("✅ Config file updated successfully!")
    except Exception as e:
        st.error(f"Failed to save config: {e}")

def load_config(config_path="config.yaml"):
    import yaml
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        st.error(f"Failed to load config: {e}")
        return {}

# ===============================
# Async Scan Logic
# ===============================
async def run_sast_scans(config_path="config.yaml"):
    cfg = load_config(config_path)
    results = {}

    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

    # Fancy header
    figlet_name = cfg.get("tool_info", {}).get("tool_name", "Tool Name")
    terminal_header = pyfiglet.figlet_format(figlet_name, font="doom")
    print(Fore.YELLOW + Style.BRIGHT + terminal_header + Fore.RESET + Style.RESET_ALL)
    print(Fore.GREEN + Style.BRIGHT + "🚀 Starting SAST security scans... please wait...\n", flush=True)

    try:
        if cfg["technology"].upper() == "PYTHON":
            code_analyzer_task = code_analyzer_py.scan(cfg)
        elif cfg["technology"].upper() == "JAVA":
            code_analyzer_task = code_analyzer.scan(cfg)
        else:
            code_analyzer_task = asyncio.sleep(0, result=[])

        dep_task = dependency_checker.scan(cfg)
        secret_task = secret_scanner.scan(cfg)

        scan_results = await asyncio.gather(
            dep_task, 
            secret_task, 
            code_analyzer_task, 
            return_exceptions = True
        )

        results["Dependency Scan"] = (scan_results[0] if not isinstance(scan_results[0], Exception) else [{"error": str(scan_results[0])}])
        results["Secret Scanner"] = (scan_results[1] if not isinstance(scan_results[1], Exception) else [{"error": str(scan_results[1])}])
        results["Code Analyzer"] = (scan_results[2] if not isinstance(scan_results[2], Exception) else [{"error": str(scan_results[2])}])

        code_results = results["Code Analyzer"]
        if isinstance(code_results, dict) and "results" in code_results:
            results["Code Analyzer"] = code_results["results"]
        elif not isinstance(code_results, list):
            results["Code Analyzer"] = [code_results]

        html_report.generate(results, cfg)
        json_report.generate(results, cfg)

    except Exception as e:
        st.error(f"SAST scanning failed: {e}")
        results["Code Analyzer"] = [{"error": str(e)}]

    return results

# ===============================
# UI Logic
# ===============================
TECH_DEPENDENCIES = {
    "Python": ["requirements.txt", "Pipfile", "pyproject.toml"],
    "Java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "NodeJS": ["package.json", "yarn.lock"],
    ".NET": ["packages.config", "*.csproj", "*.vbproj"],
    "Go": ["go.mod", "go.sum"],
    "Ruby": ["Gemfile", "Gemfile.lock"],
}

def sast_page(cfg, config_path, result_card_fn, report_download_button_fn):
    st.header("📊 SAST Dashboard")

    with st.expander("⚙️ Configuration", expanded=False):
        st.subheader("📄 Assessment Project Details")

        project_cfg = cfg.get("Assessment_Project_Details", {})

        folder_path = st.text_input(
            "Application Folder Path:",
            value=cfg.get("target_dirs", ["./"])[0],
            help="Path to application source folder"
        )

        col1, col2 = st.columns([2, 2])
        with col1:
            name = st.text_input("Application Name", value=project_cfg.get("name", ""))
        with col2:
            version = st.text_input("Version", value=project_cfg.get("version", ""))

        col3, col4 = st.columns([2, 2])
        with col3:
            technology = st.selectbox(
                "Application Technology",
                list(TECH_DEPENDENCIES.keys()),
                index=list(TECH_DEPENDENCIES.keys()).index(
                    project_cfg.get("technology", "Python")
                ) if project_cfg.get("technology") in TECH_DEPENDENCIES else 0
            )
        with col4:
            description = st.text_area(
                "Application Description",
                value=project_cfg.get("description", ""),
                height=80,
                placeholder="Briefly describe your project..."
            )

        st.markdown("📌 **Suggested Dependency Files:**")
        st.json(TECH_DEPENDENCIES.get(technology, []))

        if st.button("💾 Save Configuration", key="save_sast_config"):
            cfg["Assessment_Project_Details"] = {
                "name": name,
                "version": version,
                "technology": technology,
                "description": description,
            }
            cfg["technology"] = technology
            cfg["dependency_files"] = {technology.lower(): TECH_DEPENDENCIES[technology]}
            cfg["target_dirs"] = [folder_path]
            save_config(cfg, config_path)

    if "results" not in st.session_state:
        st.session_state.results = None

    if st.button("🚀 Run Security Scans", key="run_sast"):
        start_time = perf_counter()
        with st.spinner("Running SAST scans... please wait ⏳"):
            st.session_state.results = asyncio.run(run_sast_scans(config_path))
        elapsed = round(perf_counter() - start_time, 2)
        st.success(f"✅ SAST scan complete in {elapsed} seconds!")
        print(Fore.YELLOW + Style.BRIGHT + f"\n⏱️ SAST Scan Completed in {elapsed} Seconds.\n", flush=True)
        print(Style.RESET_ALL)

    if st.session_state.results:
        st.subheader("📑 Consolidated Reports")
        report_download_button_fn()

        col1, col2, col3 = st.columns(3)
        with col1:
            result_card_fn("Dependency Scan", st.session_state.results["Dependency Scan"])
        with col2:
            result_card_fn("Secret Scanner", st.session_state.results["Secret Scanner"])
        with col3:
            result_card_fn("Code Analyzer", st.session_state.results["Code Analyzer"])
