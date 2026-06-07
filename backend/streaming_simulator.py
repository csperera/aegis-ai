import os, time, json, random
from pathlib import Path
from dotenv import load_dotenv
import pandas as pd

load_dotenv()

from backend.core.schema import ThreatEvent
from backend.core.event_store import event_store
from backend.agents.prediction_agent import PredictionAgent
from backend.agents.triage_agent import TriageAgent
from backend.agents.explanation_agent import ExplanationAgent

DATA_PATH     = Path(os.getenv("PROCESSED_DATA_PATH", "data/processed/cicids_clean.parquet"))
STREAM_RATE   = int(os.getenv("STREAM_RATE", 5))
FEATURES_PATH = Path("models/feature_names.json")


def load_feature_names():
    with open(FEATURES_PATH) as f:
        return json.load(f)


def row_to_event(row: pd.Series, feature_cols: list) -> ThreatEvent:
    features = {col: float(row.get(col, 0.0)) for col in feature_cols}
    return ThreatEvent(
        src_ip        = str(row.get("Source IP",        f"10.0.{random.randint(0,255)}.{random.randint(1,254)}")),
        dst_ip        = str(row.get("Destination IP",   f"192.168.{random.randint(0,10)}.{random.randint(1,50)}")),
        src_port      = int(row.get("Source Port",      random.randint(1024, 65535))),
        dst_port      = int(row.get("Destination Port", random.choice([80, 443, 22, 3389, 8080]))),
        protocol      = str(row.get("Protocol",         "TCP")),
        features      = features,
        label         = str(row.get("Label",            "BENIGN")),
        attack_family = str(row.get("attack_family",    "Benign")),
    )


def run_pipeline():
    print("🚀 AegisAI pipeline starting...")
    feature_cols = load_feature_names()
    df           = pd.read_parquet(DATA_PATH)
    processed    = 0
    delay        = 1.0 / STREAM_RATE

    pred_agent   = PredictionAgent()
    triage_agent = TriageAgent()
    expl_agent   = ExplanationAgent()

    while True:  # loop forever for continuous streaming
        df_shuffled = df.sample(frac=1, random_state=processed).reset_index(drop=True)

        for _, row in df_shuffled.iterrows():
            event = row_to_event(row, feature_cols)
            event = pred_agent.run(event)
            event = triage_agent.run(event)
            event = expl_agent.run(event)  # always run — zero API cost

            event_store.add(event)
            processed += 1

            if processed % 100 == 0:
                print(f"  [{processed}] Severity={event.severity} | Family={event.attack_family} | Score={event.risk_score:.3f}")

            time.sleep(delay)


if __name__ == "__main__":
    run_pipeline()