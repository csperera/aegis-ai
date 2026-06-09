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
    page_title="AegisAI — Console",
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


# ── HEADER ────────────────────────────────────────────────────────────────────
from datetime import timezone
now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
col_title, col_status = st.columns([4, 1])
with col_title:
    st.markdown("## 🛡️ AegisAI — Real-Time Threat Console")
with col_status:
    st.markdown(f"🟢 **Live** | `{now}`")

# ── FETCH EVENTS ──────────────────────────────────────────────────────────────
events = event_store.get_recent(200)

if not events:
    st.info("⏳ Pipeline starting up, first events arriving soon...")
    time.sleep(REFRESH_INTERVAL)
    st.rerun()

# ── KPIs ──────────────────────────────────────────────────────────────────────
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

# ── CHARTS ────────────────────────────────────────────────────────────────────
c1, c2 = st.columns([1, 1.5])
with c1:
    st.subheader("Severity Distribution")
    st.plotly_chart(severity_donut(events), width='stretch', key="donut")
with c2:
    st.subheader("Attack Families")
    st.plotly_chart(attack_family_bar(events), width='stretch', key="bar")

st.subheader("Threat Trend (last 10 min)")
st.plotly_chart(severity_trend(events), width='stretch', key="trend")

# ── LIVE EVENT FEED ───────────────────────────────────────────────────────────
st.subheader("📡 Live Event Feed")
df = pd.DataFrame(events[:50])
if not df.empty:
    display_cols = ["timestamp", "severity", "attack_family",
                    "src_ip", "dst_ip", "risk_score",
                    "triage_decision", "analyst_summary"]
    display_cols = [c for c in display_cols if c in df.columns]
    st.dataframe(
    df[display_cols].style.format({"risk_score": "{:.4f}"}),
    use_container_width=True,
    height=350
    )

st.divider()

# ── EVENT DETAIL ──────────────────────────────────────────────────────────────
st.subheader("🔍 Event Detail")
if events:
    event_labels = [
        f"[{events[i].get('severity','?')}] "
        f"{events[i]['event_id'][:16]}... — "
        f"{events[i].get('attack_family','?')}"
        for i in range(min(20, len(events)))
    ]

    selected_idx = st.selectbox(
        "Select event",
        range(len(event_labels)),
        format_func=lambda i: event_labels[i],
        key="event_detail_select",
    )

    evt = events[selected_idx]

    d1, d2, d3 = st.columns(3)
    d1.markdown(f"**Severity:** `{evt.get('severity')}`")
    d1.markdown(f"**Decision:** `{evt.get('triage_decision')}`")
    d1.markdown(f"**Risk Score:** `{evt.get('risk_score', 0):.3f}`")
    d2.markdown(f"**Source:** `{evt.get('src_ip')}:{evt.get('src_port')}`")
    d2.markdown(f"**Dest:** `{evt.get('dst_ip')}:{evt.get('dst_port')}`")
    d2.markdown(f"**Protocol:** `{evt.get('protocol')}`")
    d3.markdown(f"**Attack Family:** `{evt.get('attack_family')}`")
    d3.markdown(f"**Confidence:** `{evt.get('confidence', 0):.2f}`")
    d3.markdown(f"**Model:** `{evt.get('model_version')}`")

    st.markdown("**📝 Explanation**")
    st.info(evt.get("llm_explanation") or evt.get("attack_hypothesis") or "N/A")

    st.markdown("**✅ Recommended Action**")
    st.success(evt.get("recommended_action") or "N/A")

    st.markdown("**🔎 Reasoning Trace**")
    trace = [t for t in (evt.get("reasoning_trace", []) or []) if t and t != "N/A"]
    if trace:
        for t in trace:
            st.markdown(f"- {t}")
    else:
        st.markdown("- No reasoning trace available")

# ── AUTO REFRESH ──────────────────────────────────────────────────────────────
time.sleep(REFRESH_INTERVAL)
st.rerun()