from __future__ import annotations

import streamlit as st


def inject_css() -> None:
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Inter:wght@400;500;600;700;800&display=swap');
    :root { --navy:#07111f; --panel:#0d1b2e; --panel2:#11243b; --line:#1e3858; --text:#e7eef8; --muted:#91a4bb; --blue:#38bdf8; --violet:#8b5cf6; --cyan:#22d3ee; --amber:#fbbf24; --red:#fb7185; --green:#34d399; }
    .stApp { background: radial-gradient(circle at 90% -10%, rgba(139,92,246,.16), transparent 35%), linear-gradient(135deg,#06101c 0%,#091728 55%,#07111f 100%); color:var(--text); font-family:'Inter',sans-serif; }
    [data-testid='stSidebar'] { background:#081425; border-right:1px solid #18304d; }
    [data-testid='stSidebar'] * { color:var(--text); }
    h1,h2,h3,h4 { letter-spacing:-.03em; }
    h1 { font-size:2.25rem !important; }
    .vb-mark { width:38px; height:38px; display:flex; align-items:center; justify-content:center; border:1px solid rgba(139,92,246,.8); color:#c4b5fd; border-radius:11px; font-weight:800; letter-spacing:-.12em; background:linear-gradient(145deg,#172554,#111827); box-shadow:0 0 26px rgba(139,92,246,.2); }
    .vb-eyebrow { font-family:'IBM Plex Mono',monospace; color:#8aa2bf; text-transform:uppercase; font-size:.68rem; letter-spacing:.16em; }
    .vb-subtitle { color:var(--muted); margin-top:-.4rem; }
    .vb-card { background:linear-gradient(145deg,rgba(17,36,59,.92),rgba(10,26,43,.92)); border:1px solid var(--line); border-radius:14px; padding:18px; box-shadow:0 8px 30px rgba(0,0,0,.16); }
    .vb-kpi { min-height:108px; }
    .vb-kpi-label { color:var(--muted); font-size:.78rem; }
    .vb-kpi-value { font-size:1.85rem; font-weight:700; margin-top:.35rem; }
    .vb-kpi-delta { color:#7dd3fc; font-size:.72rem; margin-top:.2rem; }
    .vb-chip { display:inline-block; padding:.25rem .55rem; border-radius:99px; font-size:.68rem; font-weight:700; margin-right:.25rem; border:1px solid rgba(255,255,255,.1); }
    .vb-critical { color:#fecdd3; background:rgba(190,24,93,.22); border-color:rgba(251,113,133,.35); }
    .vb-high { color:#fed7aa; background:rgba(194,65,12,.22); border-color:rgba(251,146,60,.35); }
    .vb-medium { color:#fde68a; background:rgba(161,98,7,.2); border-color:rgba(251,191,36,.35); }
    .vb-low { color:#bae6fd; background:rgba(3,105,161,.2); border-color:rgba(56,189,248,.35); }
    .vb-demo { border-left:3px solid var(--violet); background:rgba(76,29,149,.17); color:#ddd6fe; padding:10px 14px; border-radius:0 8px 8px 0; font-size:.82rem; }
    .vb-mono { font-family:'IBM Plex Mono',monospace; color:#a5b4fc; font-size:.78rem; }
    .vb-rule { border-top:1px solid var(--line); margin:16px 0; }
    div[data-testid='stMetric'] { background:rgba(13,27,46,.72); border:1px solid var(--line); padding:12px; border-radius:12px; }
    .stButton > button { border-radius:9px; border:1px solid #2a4b70; background:#102744; color:#eaf2ff; }
    .stButton > button:hover { border-color:var(--violet); color:white; }
    .stDownloadButton > button { border-radius:9px; }
    </style>
    """, unsafe_allow_html=True)


def logo() -> None:
    st.markdown('<div style="display:flex;gap:10px;align-items:center;margin:8px 0 26px"><div class="vb-mark">⟦•⟧</div><div><div style="font-weight:800;font-size:1.08rem">VulnBlend</div><div class="vb-eyebrow">hybrid security lab</div></div></div>', unsafe_allow_html=True)


def page_header(eyebrow: str, title: str, subtitle: str) -> None:
    st.markdown(f'<div class="vb-eyebrow">{eyebrow}</div><h1>{title}</h1><div class="vb-subtitle">{subtitle}</div>', unsafe_allow_html=True)


def card_metric(label: str, value: str, delta: str = "") -> None:
    st.markdown(f'<div class="vb-card vb-kpi"><div class="vb-kpi-label">{label}</div><div class="vb-kpi-value">{value}</div><div class="vb-kpi-delta">{delta}</div></div>', unsafe_allow_html=True)


def severity_chip(value: str) -> str:
    css = str(value).lower()
    return f'<span class="vb-chip vb-{css}">{value}</span>'
