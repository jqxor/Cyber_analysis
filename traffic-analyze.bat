@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m traffic_analysis.cli %*
) else if exist "uv.exe" (
    uv run traffic-analyze %*
) else if defined UV (
    uv run traffic-analyze %*
) else (
    python -m traffic_analysis.cli %*
)
endlocal
