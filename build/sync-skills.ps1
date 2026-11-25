<#
.SYNOPSIS
    Mirror the project skills into the directories an agent scans.

.DESCRIPTION
    OpenClaw does not follow Windows junctions for skills, so each skill has to exist
    as a real directory under <workspace>\.agents\skills and %USERPROFILE%\.agents\skills.
    This script copies skills/<name>/ into both, removes stale files and verifies that
    every SKILL.md hash matches the project copy.

.PARAMETER Check
    Do not copy; only report whether the two agent copies are in sync.

.PARAMETER Skills
    Skill names to sync. Default: every folder under skills/ that contains SKILL.md.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File build/sync-skills.ps1
    powershell -ExecutionPolicy Bypass -File build/sync-skills.ps1 -Check
#>
param(
    [switch]$Check,
    [string[]]$Skills
)

$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot          # ...\projects\reversesuite
$workspace = Split-Path -Parent (Split-Path -Parent $project)
$sourceRoot = Join-Path $project "skills"

$targets = @(
    (Join-Path $workspace ".agents\skills"),
    (Join-Path $env:USERPROFILE ".agents\skills")
)

if (-not $Skills) {
    $Skills = Get-ChildItem $sourceRoot -Directory |
        Where-Object { Test-Path (Join-Path $_.FullName "SKILL.md") } |
        ForEach-Object { $_.Name }
}

function Get-TreeHash([string]$root) {
    $map = @{}
    Get-ChildItem $root -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($root.Length).TrimStart("\")
        $map[$rel] = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    }
    return $map
}

$failed = 0
foreach ($name in $Skills) {
    $src = Join-Path $sourceRoot $name
    if (-not (Test-Path (Join-Path $src "SKILL.md"))) {
        Write-Output ("SKIP  " + $name + " (no SKILL.md in project)")
        continue
    }
    $srcMap = Get-TreeHash $src
    foreach ($root in $targets) {
        $dst = Join-Path $root $name
        if ($Check) {
            if (-not (Test-Path $dst)) { Write-Output ("DRIFT " + $dst + " (missing)"); $failed++; continue }
            $dstMap = Get-TreeHash $dst
            $missing = $srcMap.Keys | Where-Object { -not $dstMap.ContainsKey($_) }
            $different = $srcMap.Keys | Where-Object { $dstMap.ContainsKey($_) -and $dstMap[$_] -ne $srcMap[$_] }
            $extra = $dstMap.Keys | Where-Object { -not $srcMap.ContainsKey($_) }
            if ($missing -or $different -or $extra) {
                Write-Output ("DRIFT " + $dst + " missing=" + @($missing).Count + " changed=" + @($different).Count + " extra=" + @($extra).Count)
                $failed++
            } else {
                Write-Output ("OK    " + $dst)
            }
            continue
        }
        New-Item -ItemType Directory -Force -Path $root | Out-Null
        if (Test-Path $dst) {
            $item = Get-Item $dst -Force
            if ($item.LinkType) { cmd /c rmdir "$dst" | Out-Null } else { Remove-Item $dst -Recurse -Force }
        }
        Copy-Item $src $dst -Recurse -Force
        $dstMap = Get-TreeHash $dst
        $mismatch = $srcMap.Keys | Where-Object { -not $dstMap.ContainsKey($_) -or $dstMap[$_] -ne $srcMap[$_] }
        if ($mismatch) {
            Write-Output ("FAIL  " + $dst + " (" + @($mismatch).Count + " files differ)")
            $failed++
        } else {
            Write-Output ("SYNC  " + $dst + " (" + $srcMap.Count + " files)")
        }
    }
}

if ($failed -gt 0) { Write-Output ("done with " + $failed + " problem(s)"); exit 1 }
Write-Output "all skills in sync"
