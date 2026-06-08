#!/bin/bash
echo "Generating synthetic dataset..."
python notebooks/01_generate_and_preprocess.py

echo "Training model on fresh data..."
python notebooks/02_train_model.py

echo "Build complete."