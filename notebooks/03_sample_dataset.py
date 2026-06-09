"""
Creates a 10% stratified sample of the real CICIDS2017 parquet.
Produces a smaller file that fits in 512MB RAM on Render Starter tier.
Run: python notebooks/03_sample_dataset.py
"""
import pandas as pd
from pathlib import Path

IN_PATH  = Path("data/processed/cicids_clean.parquet")
OUT_PATH = Path("data/processed/cicids_sample.parquet")

print("Loading full dataset...")
df = pd.read_parquet(IN_PATH)
print(f"Full dataset: {len(df):,} rows")

# Stratified 10% sample preserving attack family distribution
sample = df.groupby("attack_family", group_keys=False).apply(
    lambda x: x.sample(frac=0.10, random_state=42)
).reset_index(drop=True)

print(f"Sample dataset: {len(sample):,} rows")
print("\nAttack family distribution:")
print(sample["attack_family"].value_counts())

sample.to_parquet(OUT_PATH, index=False)
print(f"\nSaved → {OUT_PATH}")

import os
size_mb = os.path.getsize(OUT_PATH) / 1024 / 1024
print(f"File size: {size_mb:.1f} MB")