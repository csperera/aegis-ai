import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st
import pandas as pd
import json
from datetime import datetime
import time

from backend.core.event_store import event_store

st.set_page_config(
    page_title="AegisAI | Event Explorer",
    page_icon="🔍",
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

REFRESH_INTERVAL = 5

# ── HEADER ────────────────────────────────────────────────────────────────────
from datetime import timezone
now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
col_title, col_status = st.columns([4, 1])
with col_title:
    st.markdown("## 🔍 AegisAI | Event Explorer")
with col_status:
    st.markdown(f"🟢 **Live** | `{now}`")

# ── FETCH EVENTS ──────────────────────────────────────────────────────────────
events = event_store.get_recent(200)

if not events:
    st.info("⏳ Waiting for events from the pipeline...")
    time.sleep(REFRESH_INTERVAL)
    st.rerun()

# ── FILTERS ───────────────────────────────────────────────────────────────────
st.subheader("Filters")
f1, f2 = st.columns(2)
with f1:
    sev_filter = st.selectbox("Severity",
                              ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                              key="sev_filter")
with f2:
    fam_filter = st.selectbox("Attack Family",
                              ["ALL", "DDoS", "Reconnaissance", "BruteForce",
                               "Botnet", "Infiltration", "WebAttack", "Benign", "Other"],
                              key="fam_filter")

# Apply filters
filtered = events
if sev_filter != "ALL":
    filtered = [e for e in filtered if e.get("severity") == sev_filter]
if fam_filter != "ALL":
    filtered = [e for e in filtered if e.get("attack_family") == fam_filter]

st.caption(f"Showing {len(filtered)} of {len(events)} events")
st.divider()

# ── EVENT TABLE ───────────────────────────────────────────────────────────────
st.subheader("📋 Event Table")
if filtered:
    df = pd.DataFrame(filtered[:100])
    display_cols = ["timestamp", "severity", "attack_family",
                    "src_ip", "dst_ip", "risk_score",
                    "triage_decision", "analyst_summary"]
    display_cols = [c for c in display_cols if c in df.columns]
    st.dataframe(
    df[display_cols].style.format({"risk_score": "{:.4f}"}),
    width='stretch',
    height=350
    )
else:
    st.warning("No events match the selected filters.")

st.divider()

# ── EVENT DETAIL ──────────────────────────────────────────────────────────────
st.subheader("🔍 Event Detail")
source = filtered if filtered else events
if source:
    event_labels = [
        f"[{source[i].get('severity','?')}] "
        f"{source[i]['event_id'][:16]}... — "
        f"{source[i].get('attack_family','?')}"
        for i in range(min(20, len(source)))
    ]

    selected_idx = st.selectbox(
        "Select event",
        range(len(event_labels)),
        format_func=lambda i: event_labels[i],
        key="event_detail_select",
    )

    evt = source[selected_idx]

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

    # ── EXPORT TO THREATОРACLE ────────────────────────────────────────────────
    st.divider()
    st.markdown("**🔗 Escalate to ThreatOracle AI**")

    export_payload = {
        "event_id":        evt.get("event_id"),
        "timestamp":       evt.get("timestamp"),
        "src_ip":          evt.get("src_ip"),
        "dst_ip":          evt.get("dst_ip"),
        "src_port":        evt.get("src_port"),
        "dst_port":        evt.get("dst_port"),
        "protocol":        evt.get("protocol"),
        "attack_family":   evt.get("attack_family"),
        "severity":        evt.get("severity"),
        "risk_score":      evt.get("risk_score"),
        "triage_decision": evt.get("triage_decision"),
        "analyst_summary": evt.get("analyst_summary"),
        "recommended_action": evt.get("recommended_action"),
    }

    export_json = json.dumps(export_payload, indent=2)

    st.code(export_json, language="json")

    st.markdown(
        "📋 Copy the JSON above and paste it into "
        "[ThreatOracle AI](https://github.com/csperera/threat-oracle) "
        "for ATT&CK diagnosis and D3FEND remediation."
    )

# ── AUTO REFRESH ──────────────────────────────────────────────────────────────
time.sleep(REFRESH_INTERVAL)
st.rerun()