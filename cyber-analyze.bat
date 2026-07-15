@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m cyber_analysis.cli %*
) else if exist "uv.exe" (
    uv run cyber-analyze %*
) else if defined UV (
    uv run cyber-analyze %*
) else (
    python -m cyber_analysis.cli %*
)
endlocal
