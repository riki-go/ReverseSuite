param([string]$OutDir = (Join-Path $PSScriptRoot 'out'))
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$bat = Join-Path $PSScriptRoot 'build.bat'
cmd /c "`"$bat`" 2>&1"
if ($LASTEXITCODE -ne 0) { throw "build.bat failed: $LASTEXITCODE" }
$a = Join-Path $OutDir 'a.exe'; $c = Join-Path $OutDir 'c.exe'
Copy-Item $a $c -Force
$bytes = [IO.File]::ReadAllBytes($c)
$bytes[0x3C] = 0; $bytes[0x3D] = 0; $bytes[0x3E] = 0; $bytes[0x3F] = 0
[IO.File]::WriteAllBytes($c, $bytes)
$manifest = Get-ChildItem $OutDir -File | ForEach-Object { [pscustomobject]@{ file = $_.Name; bytes = $_.Length; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash } }
$manifest | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $OutDir 'manifest.json') -Encoding UTF8
$manifest | Format-Table -AutoSize