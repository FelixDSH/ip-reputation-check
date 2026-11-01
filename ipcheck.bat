@echo off
rem ipcheck wrapper: use packed exe if present, else fall back to python script
setlocal
set "DIR=%~dp0"
if exist "%DIR%dist\ipcheck.exe" (
  "%DIR%dist\ipcheck.exe" %*
) else (
  python "%DIR%scripts\ipcheck.py" %*
)
