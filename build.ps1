# build.ps1 - build the ReverseSuite desktop app (Python sidecar + Tauri bundle)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "run from the project root with a prepared .venv" }

Write-Host "== 0/3 syncing dist/index.html from the API UI =="
& $python "build\sync_dist.py"
if ($LASTEXITCODE -ne 0) { throw "dist sync failed" }

Write-Host "== 1/3 building Python sidecar =="
& $python -m PyInstaller --onefile --name reversesuite-backend `
    --distpath "src-tauri\binaries\tmp" --workpath "build\pyi" --specpath "build" `
    --noconfirm --paths src --hidden-import capstone --collect-submodules reversesuite `
    "build\backend_entry.py"
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

$target = "src-tauri\binaries\reversesuite-backend-x86_64-pc-windows-msvc.exe"
Move-Item -Force "src-tauri\binaries\tmp\reversesuite-backend.exe" $target
Remove-Item -Recurse -Force "src-tauri\binaries\tmp" -ErrorAction SilentlyContinue
Write-Host "sidecar -> $target"

Write-Host "== 2/3 installing frontend tooling =="
npm install --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw "npm install failed" }

Write-Host "== 3/3 building Tauri bundle =="
npx tauri build
if ($LASTEXITCODE -ne 0) { throw "tauri build failed" }

Write-Host "done. installer under src-tauri\target\release\bundle\msi"