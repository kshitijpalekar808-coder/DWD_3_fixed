#!/bin/bash
echo "============================================"
echo "  DataWatchDawgs v2 - Starting..."
echo "============================================"
pip install -r requirements.txt --quiet
echo "Starting server..."
python app.py
