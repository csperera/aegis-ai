import os, time, json, random, gc
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


def event_generator(df: pd.DataFrame, feature_cols: list):
    """
    Generator that yields one event at a time in an infinite loop.
    Interleaves attack and benign at ~30% attack rate.
    Zero memory accumulation — no pre-built lists.
    """
    attack_idx = df[df["is_attack"] == 1].index.tolist()
    benign_idx = df[df["is_attack"] == 0].index.tolist()

    while True:
        random.shuffle(attack_idx)
        random.shuffle(benign_idx)

        a, b = 0, 0
        i = 0

        while a < len(attack_idx) or b < len(benign_idx):
            if i % 3 == 0 and a < len(attack_idx):
                yield df.loc[attack_idx[a]]
                a += 1
            elif b < len(benign_idx):
                yield df.loc[benign_idx[b]]
                b += 1
            else:
                break
            i += 1


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

    for row in event_generator(df, feature_cols):
        event = row_to_event(row, feature_cols)
        event = pred_agent.run(event)
        event = triage_agent.run(event)
        event = expl_agent.run(event)

        event_store.add(event)
        processed += 1

        if processed % 100 == 0:
            print(f"  [{processed}] Severity={event.severity} | Family={event.attack_family} | Score={event.risk_score:.3f}")
            gc.collect()

        time.sleep(delay)


if __name__ == "__main__":
    run_pipeline()