<#
.SYNOPSIS
Installs and initializes MyCustomShell.

.DESCRIPTION
Installs the MyCustomShell module system-wide, initializes the environment,
and configures the correct user profile even when running as Administrator.

Works in PowerShell 5.1 and PowerShell 7.

.EXAMPLE
.\Install-MyCustomShell.ps1

.EXAMPLE
.\Install-MyCustomShell.ps1 -AddToProfile
#>

param(
    [string]$SourcePath = "$PSScriptRoot\..\MyCustomShell",
    [switch]$AddToProfile
)

# -------------------------------------------------
# Ensure script is running as Administrator
# -------------------------------------------------

$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    return
}

# -------------------------------------------------
# Detect actual logged-in user (not admin account)
# -------------------------------------------------

$loggedUser = (Get-Process explorer -IncludeUserName |
               Select-Object -First 1 -ExpandProperty UserName).Split('\')[1]

$userProfile = "C:\Users\$loggedUser"
$userDocs    = Join-Path $userProfile "Documents"

Write-Host "Target user: $loggedUser" -ForegroundColor DarkCyan

# -------------------------------------------------
# Validate module source
# -------------------------------------------------

if (-not (Test-Path $SourcePath)) {
    Write-Host "Source path not found: $SourcePath" -ForegroundColor Red
    return
}

# -------------------------------------------------
# Determine system module path automatically
# -------------------------------------------------

$moduleRoot = ($env:PSModulePath -split ';') |
    Where-Object { $_ -like "*Program Files*" } |
    Select-Object -First 1

$destination = Join-Path $moduleRoot "MyCustomShell"

Write-Host "`nInstalling MyCustomShell..." -ForegroundColor Cyan

# -------------------------------------------------
# Remove existing installation
# -------------------------------------------------

if (Test-Path $destination) {
    Write-Host "Existing version found. Removing..." -ForegroundColor Yellow
    Remove-Item $destination -Recurse -Force
}

# -------------------------------------------------
# Copy module
# -------------------------------------------------

Copy-Item $SourcePath $destination -Recurse -Force

Write-Host "Module installed to $destination" -ForegroundColor Green

# -------------------------------------------------
# Import module
# -------------------------------------------------

Import-Module MyCustomShell -Force

# -------------------------------------------------
# Initialize environment
# -------------------------------------------------

Write-Host "`nRunning environment initialization..." -ForegroundColor Cyan

try {
    Initialize-MyCustomShell
}
catch {
    Write-Host "Initialization skipped or failed." -ForegroundColor Yellow
}

# -------------------------------------------------
# Configure user profiles
# -------------------------------------------------

if ($AddToProfile) {

    $ps5Profile = Join-Path $userDocs "WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
    $ps7Profile = Join-Path $userDocs "PowerShell\Microsoft.PowerShell_profile.ps1"

    $profiles = @($ps5Profile,$ps7Profile)

    foreach ($profilePath in $profiles) {

        $dir = Split-Path $profilePath

        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        if (-not (Test-Path $profilePath)) {
            New-Item -ItemType File -Path $profilePath -Force | Out-Null
        }

        $importLine = "Import-Module MyCustomShell -ErrorAction SilentlyContinue"

        if (-not (Select-String -Path $profilePath -Pattern "MyCustomShell" -Quiet)) {
            Add-Content -Path $profilePath -Value "`n$importLine"
            Write-Host "Profile updated: $profilePath" -ForegroundColor Green
        }
        else {
            Write-Host "Profile already configured: $profilePath" -ForegroundColor DarkYellow
        }
    }
}

Write-Host "`nMyCustomShell installation complete." -ForegroundColor Cyan