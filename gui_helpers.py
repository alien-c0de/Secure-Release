import streamlit as st
import pandas as pd
import altair as alt
from pathlib import Path

# ------------------------------------------------------
# 📊 Shared Visualization + UI Helper Functions
# ------------------------------------------------------

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
    """Display severity chart using Altair (compact, color-coded)."""
    data = pd.DataFrame({
        "Severity": list(severity_counts.keys()),
        "Count": list(severity_counts.values())
    })

    chart = (
        alt.Chart(data)
        .mark_bar()
        .encode(
            x=alt.X("Severity", sort=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]),
            y=alt.Y("Count"),
            color="Severity",
            tooltip=["Severity", "Count"],
        )
        .properties(height=200, width=370)
    )

    st.altair_chart(chart, use_container_width=False)


def result_card(tool, issues):
    """Render one tool's results inside a styled card box with outline + colored header."""
    count = len(issues)

    header_colors = {
        "Dependency Scan": "linear-gradient(90deg, #0ea5e9, #38bdf8)",  # Blue
        "Secret Scanner":  "linear-gradient(90deg, #10b981, #34d399)",  # Green
        "Code Analyzer":   "linear-gradient(90deg, #f59e0b, #fbbf24)",  # Amber
        "ZAP":             "linear-gradient(90deg, #0ea5e9, #fbbf24)",  # Blue-Yellow
        "Fuzzer":          "linear-gradient(90deg, #10b981, #34d399)",  # Green
    }

    header_bg = header_colors.get(tool, "linear-gradient(90deg, #64748b, #475569)")

    st.markdown(
        f"""
        <div style="
            border: 2px solid #e5e7eb;
            border-radius: 10px;
            margin: 15px 0;
            background-color: #ffffff;
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

    # Handle errors or empty issues
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
    """Display styled download buttons for HTML and JSON reports."""
    html_path = Path("Reports/output/security_report.html")
    json_path = Path("Reports/output/security_report.json")

    # Scoped button styling
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

    col1, col2 = st.columns(2)
    with col1:
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

    with col2:
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
        else:
            st.info("ℹ️ No JSON report found yet.")

    st.markdown("</div>", unsafe_allow_html=True)
