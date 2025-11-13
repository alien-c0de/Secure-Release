import streamlit as st
from pathlib import Path
from colorama import Fore, Style
from modules.sast_module import sast_page
from modules.api_module import api_page
from time import perf_counter
from Core import *

from gui_helpers import result_card, report_download_button  # optional if you move helpers

def main():
    st.set_page_config(page_title="Secure Release Dashboard", layout="wide")
    # Global cosmetic styles (title font + layout tweaks)
    st.markdown("""
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
            .stExpander {
                background-color: #ffffff !important;
                border-radius: 10px !important;
                border: 1px solid #e5e7eb !important;
                box-shadow: 0 3px 10px rgba(0,0,0,0.05);
            }
            hr.divider {
                border: none;
                border-top: 1px solid #e5e7eb;
                margin: 0.5rem auto 0.25rem auto;
                width: 80%;
            }
            /* Buttons */
            .stButton>button {
                background: linear-gradient(90deg, #2563eb, #3b82f6) !important;
                color: white !important;
                border: none !important;
                border-radius: 8px !important;
                font-weight: 600 !important;
                transition: transform .1s ease-in-out;
            }
            .stButton>button:hover {
                transform: translateY(-1px);
                filter: brightness(1.05);
            }
            /* Streamlit header spacing fix */
            .block-container {
                padding-top: 1.6rem;
            }
            /* Chart title spacing */
            h2, h3 {
                color: #0f172a !important;
                font-weight: 700 !important;
            }
        </style>""",
        unsafe_allow_html=True,
    )

    # --------------------------
    # App Heading + Tagline
    # --------------------------
    st.markdown('<div class="title-font">🕵️ Secure Release</div>', unsafe_allow_html=True)
    st.markdown('<div class="tagline">From Code to Production - Secure Every Release.</div>', unsafe_allow_html=True)
    st.markdown('<hr class="divider">', unsafe_allow_html=True)

    config_path = Path("config.yaml")
    from modules.sast_module import load_config
    cfg = load_config(config_path)

    menu = {
        "🧠 SAST Scanner": "SAST Scanner",
        "🌐 API Vulnerability": "API Vulnerability Scanner",
        "📜 Contract Scanner": "Contract Scanner"
    }

    choice = st.sidebar.radio("📌 Menu", list(menu.keys()))
    st.sidebar.markdown("---")
    st.sidebar.info("🕵️Secure Release v1.0\nSecure Every Release.")
    choice = menu[choice]
    
    if choice == "SAST Scanner":
        sast_page(cfg, config_path, result_card, report_download_button)
    elif choice == "API Vulnerability Scanner":
        api_page(cfg, result_card)

if __name__ == "__main__":
    main()
