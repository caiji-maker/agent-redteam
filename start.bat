@echo off
cd /d "%~dp0"
echo Starting AgentRedTeam on http://127.0.0.1:8000
echo Press Ctrl+C to stop
echo.
.venv\Scripts\python -m uvicorn web.server:app --host 127.0.0.1 --port 8000
pause
