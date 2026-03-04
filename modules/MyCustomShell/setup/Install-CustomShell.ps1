#initial setup script 

<#
.SYNOPSIS
Installs MyCustomShell module system-wide.

.DESCRIPTION
Copies MyCustomShell module to Program Files module directory.
Works for PS 5.1 and PS 7.
Optionally adds auto-import to current user profile.
#>

param(
    [string]$SourcePath = ".\MyCustomShell",
    [switch]$AddToProfile
)

# ===============================
# Ensure Running As Admin
# ===============================

$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    return
}

# ===============================
# Validate Source
# ===============================

if (-not (Test-Path $SourcePath)) {
    Write-Host "Source path not found: $SourcePath" -ForegroundColor Red
    return
}

$destination = "C:\Program Files\WindowsPowerShell\Modules\MyCustomShell"

Write-Host "`nInstalling MyCustomShell..." -ForegroundColor Cyan

# ===============================
# Remove Existing Version
# ===============================

if (Test-Path $destination) {
    Write-Host "Existing version found. Removing..." -ForegroundColor Yellow
    Remove-Item $destination -Recurse -Force
}

# ===============================
# Copy Module
# ===============================

Copy-Item $SourcePath $destination -Recurse -Force

Write-Host "Module installed to $destination" -ForegroundColor Green

# ===============================
# Optional: Add Auto Import
# ===============================

if ($AddToProfile) {

    $profilePath = $PROFILE.CurrentUserAllHosts

    if (-not (Test-Path $profilePath)) {
        New-Item -ItemType File -Path $profilePath -Force | Out-Null
    }

    $importLine = "Import-Module MyCustomShell -ErrorAction SilentlyContinue"

    if (-not (Select-String -Path $profilePath -Pattern "MyCustomShell" -Quiet)) {
        Add-Content -Path $profilePath -Value "`n$importLine"
        Write-Host "Profile updated to auto-import module." -ForegroundColor Green
    }
    else {
        Write-Host "Profile already contains import line." -ForegroundColor Yellow
    }
}

Write-Host "`nInstallation complete." -ForegroundColor Cyan