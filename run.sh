#!/bin/bash
set -e

echo "[*] Setting up Python Virtual Environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Upgrading pip and installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Launching NetScanTools PRO Suite..."
python main.py