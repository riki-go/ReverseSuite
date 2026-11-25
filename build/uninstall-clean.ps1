<#
.SYNOPSIS
    Uninstall ReverseSuite and optionally remove the user data it leaves behind.

.DESCRIPTION
    The MSI removes program files, registry keys and shortcuts but keeps user data
    (logs, session token, WebView2 cache) by design. This script runs the MSI
    uninstall first, then deletes those folders unless -KeepUserData is given.

.PARAMETER KeepUserData
    Leave %LOCALAPPDATA%\ReverseSuite and %LOCALAPPDATA%\com.reversesuite.desktop
    in place (same behaviour as a plain MSI uninstall).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File uninstall-clean.ps1
    powershell -ExecutionPolicy Bypass -File uninstall-clean.ps1 -KeepUserData
#>
param(
    [switch]$KeepUserData
)

$ErrorActionPreference = "Stop"
$uninstallRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)

$productCode = $null
foreach ($root in $uninstallRoots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root | ForEach-Object {
        $entry = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($entry.DisplayName -like "*ReverseSuite*") {
            $script:productCode = $_.PSChildName
        }
    }
}

if (-not $productCode) {
    Write-Output "ReverseSuite is not installed (no uninstall entry found)."
} else {
    Write-Output ("Uninstalling " + $productCode + " ...")
    $proc = Start-Process msiexec.exe -ArgumentList @("/x", $productCode, "/qn", "/norestart") -Wait -PassThru
    Write-Output ("msiexec exit code: " + $proc.ExitCode)
}

$targets = @(
    (Join-Path $env:LOCALAPPDATA "ReverseSuite"),
    (Join-Path $env:LOCALAPPDATA "com.reversesuite.desktop")
)

if ($KeepUserData) {
    Write-Output "User data kept:"
    $targets | ForEach-Object { if (Test-Path $_) { Write-Output ("  " + $_) } }
} else {
    foreach ($path in $targets) {
        if (Test-Path $path) {
            $size = (Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
            Remove-Item $path -Recurse -Force
            Write-Output ("removed " + $path + " (" + [math]::Round($size / 1MB, 2) + " MB)")
        } else {
            Write-Output ("absent  " + $path)
        }
    }
}

$programFiles = "C:\Program Files\ReverseSuite"
if (Test-Path $programFiles) { Write-Output ("still present: " + $programFiles) } else { Write-Output "program files removed" }
