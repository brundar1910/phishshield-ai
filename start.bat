@echo off
cd /d "%~dp0"
set PYTHONPATH=%CD%
start "" "http://localhost:8000/Dashboard.html"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
pause
