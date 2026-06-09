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

# Memory budget for Render 512MB Starter tier
DEMO_SAMPLE_SIZE = 5000


def load_feature_names():
    with open(FEATURES_PATH) as f:
        return json.load(f)


def row_to_event(row, feature_cols: list) -> ThreatEvent:
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

    print(f"  Loading dataset and sampling {DEMO_SAMPLE_SIZE} rows...")
    df = pd.read_parquet(DATA_PATH).sample(
        n=DEMO_SAMPLE_SIZE, random_state=42
    ).reset_index(drop=True)
    print(f"  Dataset ready: {len(df):,} rows")

    processed    = 0
    delay        = 1.0 / STREAM_RATE

    pred_agent   = PredictionAgent()
    triage_agent = TriageAgent()
    expl_agent   = ExplanationAgent()

    while True:
        # Interleave attack and benign for realistic ~30% attack rate
        df_attack   = df[df["is_attack"] == 1].sample(frac=1, random_state=processed)
        df_benign   = df[df["is_attack"] == 0].sample(frac=1, random_state=processed)

        attack_list = df_attack.to_dict("records")
        benign_list = df_benign.to_dict("records")

        interleaved = []
        a, b = 0, 0
        for i in range(len(df)):
            if i % 3 == 0 and a < len(attack_list):
                interleaved.append(attack_list[a]); a += 1
            elif b < len(benign_list):
                interleaved.append(benign_list[b]); b += 1

        df_shuffled = pd.DataFrame(interleaved)

        for _, row in df_shuffled.iterrows():
            event = row_to_event(row, feature_cols)
            event = pred_agent.run(event)
            event = triage_agent.run(event)
            event = expl_agent.run(event)

            event_store.add(event)
            processed += 1

            if processed % 100 == 0:
                print(f"  [{processed}] Severity={event.severity} | Family={event.attack_family} | Score={event.risk_score:.3f}")

            time.sleep(delay)


if __name__ == "__main__":
    run_pipeline()