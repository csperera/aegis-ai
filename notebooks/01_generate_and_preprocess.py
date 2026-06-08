"""
Generates synthetic CICIDS2017-style data, preprocesses it, and saves
the clean parquet + scaler. No real dataset needed.
Run: python notebooks/01_generate_and_preprocess.py
"""
import pandas as pd
import numpy as np
import pickle
from pathlib import Path
from sklearn.preprocessing import StandardScaler

np.random.seed(42)
OUT_PATH = Path("data/processed/cicids_clean.parquet")
SCALER_PATH = Path("models/scaler.pkl")
OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
Path("models").mkdir(exist_ok=True)

N = 50_000  # total events

FAMILIES = {
    "Benign":        0.60,
    "DDoS":          0.12,
    "BruteForce":    0.08,
    "WebAttack":     0.07,
    "Botnet":        0.06,
    "Reconnaissance":0.04,
    "Infiltration":  0.03,
}

def make_events(family, n):
    is_attack = family != "Benign"
    base_flow = 5000 if family == "DDoS" else 200
    base_pkt   = 800  if family == "DDoS" else 50

    rows = {
        "Flow Duration":          np.random.exponential(1e6 if is_attack else 5e6, n),
        "Flow Pkts/s":            np.random.exponential(base_flow, n),
        "Flow Bytes/s":           np.random.exponential(base_flow * 500, n),
        "Fwd Pkts/s":             np.random.exponential(base_pkt, n),
        "Bwd Pkts/s":             np.random.exponential(10 if is_attack else base_pkt * 0.8, n),
        "Fwd Pkt Len Mean":       np.random.normal(60 if is_attack else 500, 30, n).clip(20),
        "Bwd Pkt Len Mean":       np.random.normal(40 if is_attack else 400, 20, n).clip(0),
        "Fwd IAT Mean":           np.random.exponential(500 if is_attack else 5000, n),
        "Bwd IAT Mean":           np.random.exponential(600 if is_attack else 6000, n),
        "Active Mean":            np.random.exponential(1000, n),
        "Idle Mean":              np.random.exponential(2000 if is_attack else 10000, n),
        "SYN Flag Cnt":           np.random.poisson(5 if family in ("DDoS","BruteForce") else 1, n),
        "RST Flag Cnt":           np.random.poisson(3 if is_attack else 0.2, n),
        "PSH Flag Cnt":           np.random.poisson(2, n),
        "ACK Flag Cnt":           np.random.poisson(10, n),
        "URG Flag Cnt":           np.random.poisson(0.1, n),
        "Pkt Len Mean":           np.random.normal(80 if is_attack else 450, 50, n).clip(20),
        "Pkt Len Std":            np.random.exponential(100, n),
        "Pkt Len Var":            np.random.exponential(5000, n),
        "Tot Fwd Pkts":           np.random.poisson(50 if is_attack else 20, n),
        "Tot Bwd Pkts":           np.random.poisson(5  if is_attack else 18, n),
        "TotLen Fwd Pkts":        np.random.exponential(3000 if is_attack else 8000, n),
        "TotLen Bwd Pkts":        np.random.exponential(500 if is_attack else 7000, n),
        "Flow IAT Mean":          np.random.exponential(400 if is_attack else 4000, n),
        "Flow IAT Std":           np.random.exponential(300 if is_attack else 3000, n),
        "Flow IAT Max":           np.random.exponential(2000 if is_attack else 20000, n),
        "Flow IAT Min":           np.random.exponential(100 if is_attack else 500, n),
        "Init Fwd Win Byts":      np.random.choice([0, 8192, 65535], n,
                                      p=[0.6,0.3,0.1] if is_attack else [0.1,0.3,0.6]),
        "Init Bwd Win Byts":      np.random.choice([0, 8192, 65535], n,
                                      p=[0.7,0.2,0.1] if is_attack else [0.1,0.3,0.6]),
        "Subflow Fwd Pkts":       np.random.poisson(25 if is_attack else 10, n),
        # metadata
        "Source IP":       [f"10.0.{np.random.randint(0,255)}.{np.random.randint(1,254)}" for _ in range(n)],
        "Destination IP":  [f"192.168.{np.random.randint(0,10)}.{np.random.randint(1,50)}" for _ in range(n)],
        "Source Port":     np.random.randint(1024, 65535, n),
        "Destination Port":np.random.choice(
                               [80,443,22,3389,8080,445,3306],n,
                               p=[0.3,0.3,0.15,0.1,0.05,0.05,0.05] if family=="BruteForce"
                               else [0.35,0.35,0.1,0.05,0.1,0.025,0.025]),
        "Protocol":        np.random.choice([6, 17], n, p=[0.8, 0.2]),
        "Label":           [family] * n,
        "attack_family":   [family] * n,
        "is_attack":       [int(is_attack)] * n,
    }

    df = pd.DataFrame(rows)

    # Add realistic noise to numeric features to prevent perfect class
    # separation — ensures XGBoost outputs probability distributions
    # rather than binary 0/1 scores
    META_COLS = {"Source IP", "Destination IP", "Source Port",
                 "Destination Port", "Protocol", "Label",
                 "attack_family", "is_attack"}
    numeric_cols = [c for c in df.columns
                    if c not in META_COLS and df[c].dtype in [np.float64, np.int64]]
    for col in numeric_cols:
        std = df[col].std()
        if std > 0:
            df[col] = df[col] + np.random.normal(0, std * 0.25, n)
            df[col] = df[col].clip(lower=0)  # prevent negative values

    return df


# --- Build dataset ---
dfs = []
for family, frac in FAMILIES.items():
    n = int(N * frac)
    print(f"  Generating {n:,} {family} events...")
    dfs.append(make_events(family, n))

df = pd.concat(dfs, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
print(f"Total rows: {len(df):,}")

# --- Feature selection ---
META = {"Label","attack_family","is_attack","Source IP","Destination IP",
        "Source Port","Destination Port","Protocol"}
feature_cols = [c for c in df.select_dtypes(include=[np.number]).columns if c not in META]

df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0)

# Top 30 by variance
top_features = df[feature_cols].var().sort_values(ascending=False).head(30).index.tolist()
print(f"Selected features: {top_features}")

# --- Scale ---
scaler = StandardScaler()
df[top_features] = scaler.fit_transform(df[top_features])
with open(SCALER_PATH, "wb") as f:
    pickle.dump((scaler, top_features), f)
print(f"Scaler saved → {SCALER_PATH}")

# --- Save parquet ---
keep = top_features + list(META)
df[keep].to_parquet(OUT_PATH, index=False)
print(f"Dataset saved → {OUT_PATH}")
print("\nAttack family distribution:")
print(df["attack_family"].value_counts())