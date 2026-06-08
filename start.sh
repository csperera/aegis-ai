#!/bin/bash
echo "Training model on disk data..."
python notebooks/02_train_model.py
echo "Training complete. Starting Streamlit..."
streamlit run dashboard/1_Console.py --server.port $PORT --server.address 0.0.0.0