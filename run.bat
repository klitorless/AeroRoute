@echo off
echo [*] Setting up Python Virtual Environment...
python -m venv venv
call venv\Scripts\activate

echo [*] Upgrading pip and installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo [*] Launching NetScanTools PRO Suite...
python main.py
pause