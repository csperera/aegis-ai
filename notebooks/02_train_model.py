"""
Train XGBoost on preprocessed data.
Run: python notebooks/02_train_model.py
"""
import pandas as pd
import numpy as np
import pickle, json
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import xgboost as xgb

import os
DATA_PATH = Path(os.getenv("PROCESSED_DATA_PATH", "data/processed/cicids_clean.parquet"))
SCALER_PATH = Path("models/scaler.pkl")
MODEL_PATH = Path("models/xgb_model.json")

df = pd.read_parquet(DATA_PATH)

with open(SCALER_PATH, "rb") as f:
    scaler, feature_cols = pickle.load(f)

X = df[feature_cols].values
y = df["is_attack"].values

# Stratified split preserving attack ratio
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

scale_pos_weight = (y == 0).sum() / (y == 1).sum()
print(f"scale_pos_weight = {scale_pos_weight:.2f}")

model = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=scale_pos_weight,
    eval_metric="auc",
    random_state=42,
    n_jobs=-1,
)
model.fit(X_train, y_train,
          eval_set=[(X_test, y_test)],
          verbose=50)

y_pred_proba = model.predict_proba(X_test)[:, 1]
y_pred = (y_pred_proba > 0.5).astype(int)
auc = roc_auc_score(y_test, y_pred_proba)
print(f"\nAUC: {auc:.4f}")
print(classification_report(y_test, y_pred))

model.save_model(str(MODEL_PATH))
print(f"Model saved → {MODEL_PATH}")

# Save feature names alongside model
with open("models/feature_names.json", "w") as f:
    json.dump(feature_cols, f)
print("Feature names saved → models/feature_names.json")