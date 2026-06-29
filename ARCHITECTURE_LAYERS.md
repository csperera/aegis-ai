# AegisAI — System Architecture

**AegisAI** is an AI-native Security Operations Center (SOC) augmentation platform that ingests real network flow telemetry, scores each event for malicious behavior, and enriches alerts with severity, triage decisions, and analyst-grade explanations. Built on the CICIDS2017 benchmark dataset (2.83M labeled flows), it runs a five-stage multi-agent pipeline from raw data ingestion through human-in-the-loop review. Each stage is loosely coupled: agents communicate via structured `ThreatEvent` objects that serialize to JSON for downstream consumption. The system is designed as **Component 1 of an AI SOC Pipeline** — it outputs structured intelligence that any downstream layer (including ThreatOracle) can ingest without tight coupling to the dashboard or model internals.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    AEGISAI — AUTONOMOUS SOC AUGMENTATION PIPELINE                            │
│                              Component 1 of AI SOC Pipeline  │  Loosely Coupled Architecture                 │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  STAGE 1 — DATA INGESTION                                                                                │
  │  ┌─────────────────────┐    ┌──────────────────────────────┐    ┌─────────────────────────────────────┐  │
  │  │  CICIDS2017 Dataset │───►│  Feature Extraction &        │───►│  Temporal Validation &              │  │
  │  │  2.83M network flow │    │  Preprocessing               │    │  Train / Test Split                 │  │
  │  │  events (UNB)       │    │  • 30 features (variance)    │    │  • Stratified 80/20 split           │  │
  │  └─────────────────────┘    │  • StandardScaler normalize  │    │  • Parquet → streaming simulator    │  │
  │                             │  • Attack family mapping     │    └─────────────────────────────────────┘  │
  │                             └──────────────────────────────┘                                             │
  └───────────────────────────────────────────────┬──────────────────────────────────────────────────────────┘
                                                  │  ThreatEvent (raw features + metadata)
                                                  ▼
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  STAGE 2 — PREDICTION AGENT                                                                              │
  │  ┌────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
  │  │  XGBoost Core Model  │  AUC: 0.9992 on imbalanced temporal data  │  scale_pos_weight class balance │  │
  │  └────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
  │  Outputs ──►  attack classification  │  risk_score (confidence 0–1)  │  is_suspicious flag               │
  └───────────────────────────────────────────────┬──────────────────────────────────────────────────────────┘
                                                  │  ThreatEvent + prediction fields
                                                  ▼
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  STAGE 3 — TRIAGE AGENT                                                                                  │
  │  ┌──────────────────────────────┐    ┌──────────────────────────────┐    ┌────────────────────────────┐  │
  │  │  Receives prediction output  │───►│  Severity Scoring &          │───►│  Route Decision            │  │
  │  │  (risk_score, attack_family) │    │  Priority Ranking            │    │  Dashboard  │  Escalation  │  │
  │  └──────────────────────────────┘    │  CRITICAL → HIGH → MEDIUM    │    └────────────────────────────┘  │
  │                                      │  → LOW → INFO                │                                    │
  │                                      └──────────────────────────────┘                                    │
  └───────────────────────────────────────────────┬──────────────────────────────────────────────────────────┘
                                                  │  ThreatEvent + severity + triage_decision
                                                  ▼
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  STAGE 4 — EXPLANATION AGENT                                                                             │
  │  ┌──────────────────────────────┐    ┌──────────────────────────────┐    ┌────────────────────────────┐  │
  │  │  SHAP Explainability Layer   │───►│  Human-Readable Reasoning    │───►│  Enriched ThreatEvent      │  │
  │  │  Feature importance ranking  │    │  per classification          │    │  analyst_summary           │  │
  │  └──────────────────────────────┘    │  Plain-English narrative     │    │  reasoning_trace           │  │
  │                                      │  Recommended SOC action plan │    │  recommended_action        │  │
  │                                      └──────────────────────────────┘    └────────────────────────────┘  │
  └───────────────────────────────────────────────┬──────────────────────────────────────────────────────────┘
                                                  │  Fully enriched ThreatEvent
                                                  ▼
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  STAGE 5 — DASHBOARD & HUMAN-IN-THE-LOOP                                                                 │
  │  ┌────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
  │  │  Streamlit SOC Console  │  Real-Time Threat Feed  │  Event Explorer  │  Drill-Down Detail View     │  │
  │  └────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
  │  ┌──────────────────────────────┐    ┌──────────────────────────────┐    ┌────────────────────────────┐  │
  │  │  Analyst Accept / Override   │───►│  Correction Logging          │───►│  Continuous Improvement    │  │
  │  │  (human feedback loop)       │    │  (feedback → retraining)     │    │  (model & rule refinement) │  │
  │  └──────────────────────────────┘    └──────────────────────────────┘    └────────────────────────────┘  │
  └───────────────────────────────────────────────┬──────────────────────────────────────────────────────────┘
                                                  │
                                                  ▼
  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  JSON OUTPUT INTERFACE  —  Structured ThreatEvent consumed by downstream intelligence systems            │
  │  ┌────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
  │  │  {                                                                                                 │  │
  │  │    "event_id": "...",  "timestamp": "...",  "src_ip": "...",  "dst_ip": "...",                     │  │
  │  │    "risk_score": 0.97,  "severity": "CRITICAL",  "triage_decision": "ESCALATE",                    │  │
  │  │    "attack_family": "DDoS",  "attack_hypothesis": "...",  "confidence": 0.97,                      │  │
  │  │    "analyst_summary": "...",  "recommended_action": "...",  "reasoning_trace": [...],              │  │
  │  │    "mitre_techniques": ["T1498", "T1046"]                                                          │  │
  │  │  }                                                                                                 │  │
  │  └────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
  │                                                                                                          │
  │  MITRE ATT&CK Technique Mappings                                                                         │
  │  ┌──────────────┬─────────────────────────────────────────────────────────────────────────────────────┐  │
  │  │  T1110       │  Brute Force — credential / authentication attacks (FTP-Patator, SSH-Patator)       │  │
  │  │  T1046       │  Network Service Discovery — port scanning and reconnaissance (PortScan)            │  │
  │  │  T1498       │  Network Denial of Service — volumetric and application-layer floods (DDoS family)  │  │
  │  │  T1071       │  Application Layer Protocol — C2 and exfil over standard protocols (Botnet, Web)    │  │
  │  └──────────────┴─────────────────────────────────────────────────────────────────────────────────────┘  │
  │                                                                                                          │
  │  ▼  Downstream Consumers: ThreatOracle AI  │  SIEM Integrations  │  SOAR Playbooks  │  Custom APIs       │
  └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  Note: "Component 1 of AI SOC Pipeline — outputs structured JSON to any downstream intelligence layer"
```

---

## Legend

| Symbol | Meaning |
|--------|---------|
| `┌─┐│└┘` | Box borders — denote a component, stage, or subsystem boundary |
| `─►` | Data flow / pipeline handoff between stages |
| `│` / `▼` | Vertical flow — event passes from one stage to the next |
| `ThreatEvent` | Core dataclass (`backend/core/schema.py`) carrying fields through all agents |
| `CRITICAL → INFO` | Severity ladder used by the Triage Agent for priority ranking |
| `ESCALATE / MONITOR / IGNORE` | Triage routing decisions sent to dashboard or external systems |
| `JSON OUTPUT INTERFACE` | `ThreatEvent.to_dict()` — structured output for loosely coupled downstream consumers |
| `MITRE ATT&CK` | Standardized adversary technique IDs mapped from attack family classifications |
