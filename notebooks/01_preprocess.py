"""
One-time preprocessing of CICIDS2017 CSVs → clean parquet.
Drop all CSVs into data/raw/ then run: python notebooks/01_preprocess.py
"""
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import StandardScaler
import pickle, warnings
warnings.filterwarnings("ignore")

RAW_DIR = Path("data/raw")
OUT_PATH = Path("data/processed/cicids_clean.parquet")
SCALER_PATH = Path("models/scaler.pkl")
OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
Path("models").mkdir(exist_ok=True)

# --- 1. Load all files (any extension) ---
dfs = []
for f in RAW_DIR.glob("*"):
    if f.is_file():
        print(f"Loading {f.name}...")
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)

df = pd.concat(dfs, ignore_index=True)
print(f"Total rows: {len(df):,}")

# --- 2. Normalize label column ---
label_col = [c for c in df.columns if "label" in c.lower()][0]
df.rename(columns={label_col: "Label"}, inplace=True)
df["Label"] = df["Label"].str.strip()

ATTACK_FAMILY_MAP = {
    "BENIGN": "Benign",
    "DDoS": "DDoS",
    "DoS GoldenEye": "DDoS",
    "DoS Hulk": "DDoS",
    "DoS Slowhttptest": "DDoS",
    "DoS slowloris": "DDoS",
    "Heartbleed": "DDoS",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack \x96 Brute Force": "WebAttack",
    "Web Attack \x96 XSS": "WebAttack",
    "Web Attack \x96 Sql Injection": "WebAttack",
    "Bot": "Botnet",
    "Infiltration": "Infiltration",
    "PortScan": "Reconnaissance",
}
df["attack_family"] = df["Label"].map(
    lambda x: next((v for k, v in ATTACK_FAMILY_MAP.items() if k.lower() in x.lower()), "Other")
)
df["is_attack"] = (df["Label"].str.upper() != "BENIGN").astype(int)

# --- 3. Select numeric features ---
exclude = {"Label", "attack_family", "is_attack", "Flow ID", "Source IP",
           "Destination IP", "Timestamp", "Source Port", "Destination Port", "Protocol"}
feature_cols = [c for c in df.select_dtypes(include=[np.number]).columns if c not in exclude]

# Drop inf / NaN
df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)
df.dropna(subset=feature_cols, inplace=True)

# Keep top 30 features by variance
variances = df[feature_cols].var().sort_values(ascending=False)
top_features = variances.head(30).index.tolist()
print(f"Selected {len(top_features)} features")

# --- 4. Scale features ---
scaler = StandardScaler()
df[top_features] = scaler.fit_transform(df[top_features])
with open(SCALER_PATH, "wb") as f:
    pickle.dump((scaler, top_features), f)
print(f"Scaler saved → {SCALER_PATH}")

# --- 5. Reconstruct metadata cols ---
for col, default in [("Source IP", "0.0.0.0"), ("Destination IP", "0.0.0.0"),
                     ("Source Port", 0), ("Destination Port", 0), ("Protocol", 0)]:
    if col not in df.columns:
        df[col] = default

# --- 6. Save parquet ---
keep_cols = top_features + ["Label", "attack_family", "is_attack",
                             "Source IP", "Destination IP",
                             "Source Port", "Destination Port", "Protocol"]
keep_cols = [c for c in keep_cols if c in df.columns]
df[keep_cols].to_parquet(OUT_PATH, index=False)
print(f"Clean dataset saved → {OUT_PATH}  ({len(df):,} rows)")
print("\nAttack family distribution:")
print(df["attack_family"].value_counts())