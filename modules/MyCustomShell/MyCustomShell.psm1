<#
.SYNOPSIS
MyCustomShell interactive PowerShell environment.

.DESCRIPTION
MyCustomShell provides a customized interactive PowerShell environment
with Linux-style commands, Active Directory shortcuts, and enhanced
navigation tools.

The module includes utilities such as:

    df
    du
    sudo
    Refresh-ADData
    Start-StayAwake

.COMMANDS
df
du
sudo
Refresh-ADData
Start-StayAwake
Menu

.VARIABLES
$WinServers
$LinuxServers
$Users
$Scripts
$Modules
$UserScripts
$CPUScripts
$UserModules
$CPUModules

.NOTES
Author: Darrell Nielsen
Version: 1.0
#>

Write-Host "`n"
Write-Host "Type 'Menu' to list all pre-defined Commands and Variables" -ForegroundColor DarkGray
Write-Host "`n"


$ps5Root = Join-Path $env:USERPROFILE "Documents\WindowsPowerShell"
$ps7Root = Join-Path $env:USERPROFILE "Documents\PowerShell"

if (-not (Test-Path $ps7Root)) {
    New-Item -ItemType Directory -Path $ps7Root | Out-Null
}

$itemsToLink = @(
    "Scripts"
    "Modules"
    "Microsoft.PowerShell_profile.ps1"
)

$script:UserPSRoot = if (Test-Path "$HOME\Documents\PowerShell") {
    "$HOME\Documents\PowerShell"
}
else {
    "$HOME\Documents\WindowsPowerShell"
}

# --------------------------------------
# Define user paths
# --------------------------------------

$script:UserScripts = Join-Path $script:UserPSRoot "Scripts"
$script:UserModules = Join-Path $script:UserPSRoot "Modules"

# --------------------------------------
# Define system paths
# --------------------------------------

$script:CPUScripts = "C:\Program Files\WindowsPowerShell\Scripts"
$script:CPUModules = "C:\Program Files\WindowsPowerShell\Modules"

# --------------------------------------
# Combined path collections
# --------------------------------------

$script:Scripts = @(
    $script:UserScripts
    $script:CPUScripts
)

$script:Modules = @(
    $script:UserModules
    $script:CPUModules
)

# Optional environment variable
$env:PSScriptPath = $script:UserScripts

# --------------------------------------
# Ensure directories exist
# --------------------------------------

foreach ($path in @(
    $script:UserScripts
    $script:UserModules
)) {
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

# --------------------------------------
# Load public functions
# --------------------------------------

Get-ChildItem "$PSScriptRoot\Public\*.ps1" -Recurse | ForEach-Object {
    . $_
}

# --------------------------------------
# Initialize exported variables
# --------------------------------------

$script:WinServers   = @()
$script:WinComputers = @()
$script:LinuxServers = @()
$script:Users        = @()

# --------------------------------------
# Navigation drives
# --------------------------------------

if (-not (Get-PSDrive scripts -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name scripts -PSProvider FileSystem -Root $script:UserScripts -Scope Global | Out-Null
}

if (-not (Get-PSDrive modules -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name modules -PSProvider FileSystem -Root $script:UserModules -Scope Global | Out-Null
}

# --------------------------------------
# Background AD Runspace
# --------------------------------------

$script:ADPowerShell  = $null
$script:ADAsyncResult = $null

function Start-ADBackgroundLoad {

    if (-not (Get-Module -ListAvailable ActiveDirectory)) { return }
    if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) { return }

    $script:ADPowerShell = [PowerShell]::Create()

    $script:ADPowerShell.AddScript({

        Import-Module ActiveDirectory

        [PSCustomObject]@{

            WinServers = Get-ADComputer -Filter {
                OperatingSystem -like "*windows server*" -and Enabled -eq "True"
            } | Select-Object -ExpandProperty Name

            WinComputers = Get-ADComputer -Filter {
                OperatingSystem -like "*Windows 11*" -and Enabled -eq $true
            } -Properties OperatingSystem |
            Select-Object Name,OperatingSystem,
                @{Name="OU";Expression={$_.DistinguishedName -replace '^CN=[^,]+,'}} |
            Sort-Object OU

            LinuxServers = Get-ADComputer -Filter {
                OperatingSystem -like "*Linux*" -and Enabled -eq "True"
            } | Select-Object -ExpandProperty Name

            Users = Get-ADUser -Filter * |
                Select-Object Name,SamAccountName,Enabled,DistinguishedName
        }

    })

    $script:ADAsyncResult = $script:ADPowerShell.BeginInvoke()
}

function Complete-ADBackgroundLoad {

    if (-not $script:ADAsyncResult) { return }
    if (-not $script:ADAsyncResult.IsCompleted) { return }

    $result = $script:ADPowerShell.EndInvoke($script:ADAsyncResult)

    $script:WinServers   = $result.WinServers
    $script:WinComputers = $result.WinComputers
    $script:LinuxServers = $result.LinuxServers
    $script:Users        = $result.Users

    $script:ADPowerShell.Dispose()
    $script:ADPowerShell  = $null
    $script:ADAsyncResult = $null
}

# --------------------------------------
# Start background load
# --------------------------------------

Start-ADBackgroundLoad

Register-EngineEvent PowerShell.OnIdle -Action {
    Complete-ADBackgroundLoad
} | Out-Null

# --------------------------------------
# Export module members
# --------------------------------------

Export-ModuleMember -Function * `
    -Variable WinServers, WinComputers, LinuxServers, Users, Scripts, Modules, UserScripts, CPUScripts, UserModules, CPUModules