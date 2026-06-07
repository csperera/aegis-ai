import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st

st.set_page_config(
    page_title="AegisAI | Architecture & ML",
    page_icon="🧠",
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

st.markdown("## 🧠 AegisAI | Architecture & ML Model Details")
st.divider()

# ── SYSTEM ARCHITECTURE ───────────────────────────────────────────────────────
st.subheader("🏗️ System Architecture")
st.markdown("""
AegisAI is an end-to-end autonomous SOC augmentation pipeline. Each network event
flows through four specialized agents before reaching the real-time dashboard.
""")

arch_path = Path(__file__).parent.parent.parent / "dashboard" / "architecture.png"
if arch_path.exists():
    st.image(str(arch_path), use_container_width=True)
else:
    st.warning("Architecture diagram not found. Place `architecture.png` in the `dashboard/` folder.")

st.divider()

# ── ML MODEL ─────────────────────────────────────────────────────────────────
st.subheader("🤖 ML Model Details")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Dataset",        "CICIDS2017")
m2.metric("Total Rows",  "2.83M")
m3.metric("Features",       "30")
m4.metric("Model",          "XGBoost")

p1, p2, p3, p4 = st.columns(4)
p1.metric("AUC",            "0.9992")
p2.metric("Attack Recall",  "99%")
p3.metric("Attack Precision","95%")
p4.metric("Accuracy",       "99%")


st.markdown("""
#### Train / Test Split
The dataset was divided using a **stratified 80/20 train/test split** (`random_state=42`),
preserving the natural class imbalance ratio across both sets. The model was trained on
**2.26M flows** and evaluated on a completely held-out **565K flow test set** — never seen
during training. Stratification ensures the 4:1 benign-to-attack ratio is consistent
across both splits, preventing leakage and producing reliable generalization metrics.

#### Dataset
The model was trained on the **CICIDS2017 benchmark dataset** produced by the Canadian
Institute for Cybersecurity. It contains 2.83 million labeled network flow records captured
across a full week of simulated enterprise traffic, covering benign activity and seven attack
families: DDoS, Reconnaissance, BruteForce, Botnet, Infiltration, and Web Attacks.

#### Feature Engineering
30 numeric flow-level features were selected by variance ranking from the raw dataset,
including flow duration, inter-arrival times, packet length statistics, flag counts, and
byte transfer volumes. Features were standardized using a fitted `StandardScaler` saved
alongside the model for consistent inference.

#### Why XGBoost
XGBoost was selected for its strong performance on tabular network flow data, native
handling of class imbalance via `scale_pos_weight`, fast inference suitable for
real-time scoring, and interpretability through feature importance. The class imbalance
ratio in CICIDS2017 is approximately 4:1 benign to attack, handled with
`scale_pos_weight = 4.08`.

#### Limitations
- The model is trained on simulated lab traffic, not live enterprise data
- Real-world deployment would require retraining on environment-specific baselines
- WebAttack labels were excluded due to encoding issues in the source dataset
""")

st.divider()

# ── AGENTIC WORKFLOW ──────────────────────────────────────────────────────────
st.subheader("⚙️ Agentic Workflow")

col_a, col_b = st.columns(2)

with col_a:
    st.markdown("""
**Prediction Agent**
- Loads the trained XGBoost model and fitted scaler
- Extracts the 30-feature vector from each ThreatEvent
- Outputs `risk_score` (0–1 probability) and `is_suspicious` flag
- Threshold: 0.5 (tunable)

**Triage Agent**
- Applies a rule engine using real CICIDS2017 feature names
- Rules fired: high flow rate, sensitive port targeting, one-way traffic,
  packet length anomaly, long idle periods, short flow duration, large backward payload
- Maps risk score + attack family → severity (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- Outputs triage decision: ESCALATE / MONITOR / IGNORE
""")

with col_b:
    st.markdown("""
**Explanation Agent**
- Template-based reasoning engine with attack-family-specific narratives
- Produces 4-sentence plain-English explanation per event
- Generates 5-step SOC analyst action plan
- Outputs 4-point reasoning trace with specific technical indicators
- Zero API cost — fully deterministic, never rate-limited

**Event Store**
- Thread-safe in-memory ring buffer (2,000 event capacity)
- Shared between the pipeline thread and the Streamlit dashboard
- Dashboard polls every 3 seconds for fresh events
""")

st.divider()

# ── WHY THIS MATTERS ──────────────────────────────────────────────────────────
st.subheader("💡 Why This Matters")

st.markdown("""
#### Modern SOC Pain Points
Security Operations Centers are overwhelmed. The average SOC analyst reviews hundreds
of alerts per shift, with false positive rates exceeding 50% in many environments.
Alert fatigue leads to missed detections, slow response times, and analyst burnout.

#### How AegisAI Addresses Them
AegisAI operates as an autonomous first-responder layer that sits between raw network
telemetry and human analysts. It filters noise, prioritizes threats by severity, and
delivers analyst-grade reasoning with every alert — so humans focus only on what matters.

| Pain Point | AegisAI Response |
|---|---|
| Alert volume | ML scoring filters benign traffic at 99% accuracy |
| Alert context | Explanation Agent generates full reasoning per event |
| Prioritization | Triage Agent assigns severity and escalation decision |
| Response guidance | Recommended actions delivered with every alert |
| Real-time visibility | Streaming dashboard with live KPIs and trend analysis |

#### Where This Fits in the Security Stack
AegisAI operates at the **detection and triage layer** — sitting above raw SIEM ingestion
and below human incident response. It is designed to augment, not replace, SOC analysts
by handling the mechanical work of scoring, classifying, and explaining alerts at machine speed.
""")