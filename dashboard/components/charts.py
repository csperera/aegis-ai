import plotly.express as px
import plotly.graph_objects as go
import pandas as pd


SEVERITY_COLORS = {
    "CRITICAL": "#FF2D2D",
    "HIGH":     "#FF8C00",
    "MEDIUM":   "#FFD700",
    "LOW":      "#4FC3F7",
    "INFO":     "#78909C",
}

FAMILY_COLORS = {
    "DDoS":          "#FF2D2D",
    "BruteForce":    "#FF8C00",
    "WebAttack":     "#FFD700",
    "Botnet":        "#AB47BC",
    "Infiltration":  "#EF5350",
    "Reconnaissance":"#26C6DA",
    "Benign":        "#66BB6A",
    "Other":         "#90A4AE",
}


def severity_donut(events: list[dict]) -> go.Figure:
    if not events:
        return go.Figure()
    df = pd.DataFrame(events)
    counts = df["severity"].value_counts().reset_index()
    counts.columns = ["severity", "count"]
    colors = [SEVERITY_COLORS.get(s, "#90A4AE") for s in counts["severity"]]
    fig = go.Figure(go.Pie(
        labels=counts["severity"], values=counts["count"],
        hole=0.55, marker_colors=colors,
        textinfo="label+percent", hovertemplate="%{label}: %{value}<extra></extra>",
    ))
    fig.update_layout(
        showlegend=True, margin=dict(t=20, b=20, l=20, r=20),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#E0E0E0",
    )
    return fig


def attack_family_bar(events: list[dict]) -> go.Figure:
    if not events:
        return go.Figure()
    df = pd.DataFrame(events)
    counts = df["attack_family"].value_counts().reset_index()
    counts.columns = ["family", "count"]
    colors = [FAMILY_COLORS.get(f, "#90A4AE") for f in counts["family"]]
    fig = go.Figure(go.Bar(
        x=counts["count"], y=counts["family"],
        orientation="h", marker_color=colors,
        hovertemplate="%{y}: %{x}<extra></extra>",
    ))
    fig.update_layout(
        xaxis_title="Events", yaxis_title="",
        margin=dict(t=20, b=20, l=20, r=20),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#E0E0E0",
    )
    return fig


def severity_trend(events: list[dict], window_minutes: int = 10) -> go.Figure:
    if not events:
        return go.Figure()
    df = pd.DataFrame(events)
    df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["ts"])
    df = df.set_index("ts").sort_index()

    # Use wall clock now instead of max event time
    latest = df.index.max()
    earliest = df.index.min()
    if (latest - earliest).total_seconds() > 30:
        df = df[df.index >= latest - pd.Timedelta(minutes=window_minutes)]

    fig = go.Figure()
    for sev, color in SEVERITY_COLORS.items():
        sub = df[df["severity"] == sev]
        if sub.empty:
            continue
        resampled = sub.resample("5s").size().rename("count").reset_index()
        fig.add_trace(go.Scatter(
            x=resampled["ts"], y=resampled["count"],
            name=sev, line=dict(color=color, width=2),
            mode="lines",
        ))
    fig.update_layout(
        xaxis_title="Time", yaxis_title="Events",
        margin=dict(t=20, b=20, l=20, r=20),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#E0E0E0", legend=dict(orientation="h"),
    )
    return fig