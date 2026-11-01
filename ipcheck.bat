@echo off
rem Windows 便捷入口：优先用打包好的 exe，否则回退到 python 脚本
setlocal
set "DIR=%~dp0"
if exist "%DIR%dist\ipcheck.exe" (
  "%DIR%dist\ipcheck.exe" %*
) else (
  python "%DIR%scripts\ipcheck.py" %*
)
