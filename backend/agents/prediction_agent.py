import numpy as np
import xgboost as xgb
import pickle, json
from pathlib import Path
from backend.core.schema import ThreatEvent

MODEL_PATH = Path("models/xgb_model.json")
SCALER_PATH = Path("models/scaler.pkl")
FEATURES_PATH = Path("models/feature_names.json")
THRESHOLD = 0.5
MODEL_VERSION = "xgb_v1.0"


class PredictionAgent:
    def __init__(self):
        self.model = xgb.XGBClassifier()
        self.model.load_model(str(MODEL_PATH))
        with open(SCALER_PATH, "rb") as f:
            self.scaler, _ = pickle.load(f)
        with open(FEATURES_PATH) as f:
            self.feature_names: list[str] = json.load(f)

    def run(self, event: ThreatEvent) -> ThreatEvent:
        # Build feature vector in correct order
        vector = np.array([
            event.features.get(feat, 0.0) for feat in self.feature_names
        ]).reshape(1, -1)

        prob = float(self.model.predict_proba(vector)[0][1])

        event.risk_score = round(prob, 4)
        event.is_suspicious = prob > THRESHOLD
        event.model_version = MODEL_VERSION
        return event