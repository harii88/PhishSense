@echo off
rem Double-click to start PhishSense. Runs from this folder using its .venv.
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
    echo The Python environment is missing. Follow README.md section 2 to create .venv first.
    pause
    exit /b 1
)
start "" ".venv\Scripts\pythonw.exe" -m phishsense
