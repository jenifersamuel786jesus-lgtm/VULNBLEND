from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

PLOT_BG = "rgba(0,0,0,0)"
GRID = "#1e3858"
TEXT = "#cbd5e1"


def polish(fig):
    fig.update_layout(
        paper_bgcolor=PLOT_BG,
        plot_bgcolor=PLOT_BG,
        font_color=TEXT,
        margin=dict(l=8, r=8, t=48, b=12),
        title=dict(text=""),
        legend=dict(orientation="h", y=1.04, yanchor="bottom", x=0, xanchor="left"),
    )
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=GRID)
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=GRID)
    return fig


def severity_chart(rows):
    df = pd.DataFrame(rows)
    if df.empty: return go.Figure()
    counts = df["severity"].value_counts().rename_axis("severity").reset_index(name="count")
    fig = px.bar(counts, x="severity", y="count", color="severity", color_discrete_map={"Critical":"#fb7185","High":"#fb923c","Medium":"#fbbf24","Low":"#38bdf8"})
    return polish(fig)


def risk_histogram(rows):
    df = pd.DataFrame(rows)
    if df.empty: return go.Figure()
    fig = px.histogram(df, x="score", nbins=8, color="category", color_discrete_sequence=["#8b5cf6", "#38bdf8", "#fbbf24", "#fb7185"])
    return polish(fig)


def method_comparison(rows):
    df = pd.DataFrame(rows)
    if df.empty: return go.Figure()
    melted = df.melt(id_vars=["method"], value_vars=["precision", "recall", "f1"], var_name="metric", value_name="value")
    fig = px.bar(melted, x="method", y="value", color="metric", barmode="group")
    fig.update_yaxes(range=[0, 1])
    return polish(fig)
