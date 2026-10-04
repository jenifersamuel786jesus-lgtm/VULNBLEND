from __future__ import annotations

import streamlit as st

from screens.views import (
    render_correlation, render_dynamic_analysis, render_experiments, render_history,
    render_new_scan, render_overview, render_prioritization, render_reports,
    render_settings, render_static_analysis, render_targets, render_vulnerabilities,
)
from vulblend.db import init_db
from vulblend.demo_data import seed_demo_data
from vulblend.ui.theme import inject_css, logo

st.set_page_config(page_title="VulnBlend · Hybrid Security Lab", page_icon="⟦•⟧", layout="wide", initial_sidebar_state="expanded")
inject_css()
init_db()
seed_demo_data()

NAV = {
    "Overview": ("command center", render_overview),
    "New Scan": ("execution", render_new_scan),
    "Target Applications": ("scope registry", render_targets),
    "Static Analysis": ("source signals", render_static_analysis),
    "Dynamic Analysis": ("runtime signals", render_dynamic_analysis),
    "Hybrid Correlation": ("evidence braid", render_correlation),
    "Vulnerability Explorer": ("issue registry", render_vulnerabilities),
    "Risk Prioritization": ("remediation order", render_prioritization),
    "Scan History": ("reproducibility", render_history),
    "Experiment Lab": ("evaluation", render_experiments),
    "Reports": ("evidence export", render_reports),
    "Settings": ("control plane", render_settings),
}

with st.sidebar:
    logo()
    st.markdown('<div class="vb-eyebrow">workspace</div>', unsafe_allow_html=True)
    page = st.radio("Navigate", list(NAV.keys()), label_visibility="collapsed")
    st.markdown("<div class='vb-rule'></div>", unsafe_allow_html=True)
    st.markdown('<div class="vb-eyebrow">system status</div>', unsafe_allow_html=True)
    st.success("LOCAL / ISOLATED")
    st.caption("Backend scope enforcement active")
    st.caption("Data source: SQLite")
    st.markdown("<div class='vb-rule'></div>", unsafe_allow_html=True)
    st.caption("VulnBlend v0.1 · research build")

st.markdown(f'<div class="vb-mono">VULNBLEND / {NAV[page][0].upper()} / LOCAL LAB</div>', unsafe_allow_html=True)
NAV[page][1]()
