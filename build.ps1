# 打包 Windows 免安装 exe（用户无需装 Python）
# 用法：右键“用 PowerShell 运行”，或在 PowerShell 里：  ./build.ps1
param([switch]$Clean)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "[1/2] 安装/更新 PyInstaller ..."
python -m pip install --upgrade --quiet pyinstaller

if ($Clean) {
    Write-Host "清理旧构建 ..."
    Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue
}

Write-Host "[2/2] 构建单文件 exe ..."
python -m PyInstaller --onefile --name ipcheck --distpath dist --workpath build --specpath build --noupx scripts/ipcheck.py

Write-Host ""
Write-Host "完成 -> dist/ipcheck.exe"
Write-Host "用法:  .\dist\ipcheck.exe 8.8.8.8     或   .\dist\ipcheck.exe 8.8.8.8 --brief"
