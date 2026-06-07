import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import pandas as pd
from datetime import datetime
import time
import threading

from backend.core.event_store import event_store
from dashboard.components.charts import severity_donut, attack_family_bar, severity_trend

st.set_page_config(
    page_title="AegisAI | Overview",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background-color: #0D1117; color: #E0E0E0; }
[data-testid="stHeader"]           { background-color: #0D1117; }
[data-testid="stSidebar"]          { background-color: #161B22; }
[data-testid="stSidebarNav"] a     { font-size: 1.2rem !important; padding: 0.5rem 1rem !important; }
</style>
""", unsafe_allow_html=True)

REFRESH_INTERVAL = 3


def start_pipeline():
    from backend.streaming_simulator import run_pipeline
    thread = threading.Thread(target=run_pipeline, daemon=True)
    thread.start()


if "pipeline_started" not in st.session_state:
    st.session_state.pipeline_started = True
    start_pipeline()


def compute_risk_index(events):
    weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0.1}
    total = sum(weights.get(e.get("severity", "INFO"), 0) for e in events)
    return min(total / max(len(events), 1), 10.0)


placeholder = st.empty()

while True:
    events = event_store.get_recent(500)
    now    = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    with placeholder.container():

        # ── HEADER ────────────────────────────────────────────────────────
        col_title, col_status = st.columns([4, 1])
        with col_title:
            st.markdown("## 🛡️ AegisAI | Real-Time Threat Console")
        with col_status:
            st.markdown(f"🟢 **Live** | `{now}`")

        if not events:
            st.info("⏳ Pipeline starting up, first events arriving soon...")
            time.sleep(REFRESH_INTERVAL)
            continue

        # ── KPIs ──────────────────────────────────────────────────────────
        suspicious = [e for e in events if e.get("is_suspicious")]
        critical   = [e for e in events if e.get("severity") == "CRITICAL"]
        high       = [e for e in events if e.get("severity") == "HIGH"]
        risk_idx   = compute_risk_index(events)

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("📊 Total Events",  len(events))
        k2.metric("⚠️ Suspicious",    len(suspicious))
        k3.metric("🔴 Critical",      len(critical), delta=f"+{len(high)} HIGH")
        k4.metric("🧠 Risk Index",    f"{risk_idx:.1f}/10")

        st.divider()

        # ── CHARTS ────────────────────────────────────────────────────────
        c1, c2 = st.columns([1, 1.5])
        with c1:
            st.subheader("Severity Distribution")
            st.plotly_chart(severity_donut(events), use_container_width=True)
        with c2:
            st.subheader("Attack Families")
            st.plotly_chart(attack_family_bar(events), use_container_width=True)

        st.subheader("Threat Trend (last 10 min)")
        st.plotly_chart(severity_trend(events), use_container_width=True)

        # ── LIVE EVENT FEED ───────────────────────────────────────────────
        st.subheader("📡 Live Event Feed")
        df = pd.DataFrame(events[:50])
        if not df.empty:
            display_cols = ["timestamp", "severity", "attack_family",
                            "src_ip", "dst_ip", "risk_score",
                            "triage_decision", "analyst_summary"]
            display_cols = [c for c in display_cols if c in df.columns]
            st.dataframe(df[display_cols], use_container_width=True, height=350)

    time.sleep(REFRESH_INTERVAL)