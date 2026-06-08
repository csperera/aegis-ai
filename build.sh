#!/bin/bash
echo "Generating synthetic dataset..."
python notebooks/01_generate_and_preprocess.py

echo "Build complete — model files pre-trained, synthetic data generated."