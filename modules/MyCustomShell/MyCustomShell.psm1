<#
.SYNOPSIS
MyCustomShell interactive PowerShell environment.

.DESCRIPTION
MyCustomShell provides a customized interactive PowerShell environment
with Linux-style commands, Active Directory shortcuts, and enhanced
navigation tools.

The module includes utilities such as:

    df                Linux-style disk free viewer
    du                Linux-style disk usage viewer
    sudo              Launch elevated PowerShell
    Refresh-ADData    Refresh Active Directory cached data
    Start-StayAwake   Prevent workstation idle lock

The module also preloads environment variables and background tasks
for Active Directory queries.

.COMMANDS
df
du
sudo
Refresh-ADData
Start-StayAwake
Menu

.VARIABLES
$WinServers     Cached Windows server list from Active Directory
$LinuxServers   Cached Linux server list from Active Directory
$Users          Cached user objects from Active Directory
$Modules        Available PowerShell module paths
$Scripts        Custom script directories

.EXAMPLE
Import-Module MyCustomShell

Loads the MyCustomShell environment and initializes background AD data.

.EXAMPLE
Menu

Displays available commands and environment variables.

.NOTES
Author: Darrell Nielsen
Version: 1.0
#>

Write-Host "`n"
Write-Host "Type 'Menu' to list all pre-defined Commands and Variables" -ForegroundColor DarkGray
Write-Host "`n"

$script:UserPSRoot = if (Test-Path "$HOME\Documents\PowerShell") {
    "$HOME\Documents\PowerShell"
}
else {
    "$HOME\Documents\WindowsPowerShell"
}

#Script directory environment variable
$env:PSScriptPath = Join-Path $script:UserPSRoot "Scripts"

# Module/script locations
$script:Scripts = @(
    $env:PSScriptPath,
    "C:\Program Files\WindowsPowerShell\Scripts"
)


$script:Modules = @(
    (Join-Path $script:UserPSRoot "Modules"),
    "C:\Program Files\WindowsPowerShell\Modules"
)

# Ensure directories exist
foreach ($path in @($Modules[0], $Scripts[0])) {
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

# Load all public functions
Get-ChildItem "$PSScriptRoot\Public\*.ps1" -Recurse | ForEach-Object {
    . $_
}
# Initialize Exported Variables
$script:WinServers   = @()
$script:WinComputers = @()
$script:LinuxServers = @()
$script:Users        = @()
<#
$script:Scripts = @("$env:USERPROFILE\Documents\WindowsPowerShell\Scripts", "c:\program files\windowspowershell\scripts")
#$script:Modules = @("$env:USERPROFILE\Documents\WindowsPowerShell\Modules", "c:\Program Files\WindowsPowerShell\Modules")

# Quick Navigation Drives
# Ensure default directories exist
foreach ($path in @($Modules[0], $Scripts[0])) {
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
} #>
# Create quick navigation drives
if (-not (Get-PSDrive modules -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name modules -PSProvider FileSystem -Root $Modules[0] -Scope Global | Out-Null
}
if (-not (Get-PSDrive scripts -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name scripts -PSProvider FileSystem -Root $Scripts[0] -Scope Global | Out-Null
}

# Background AD Runspace
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
                OperatingSystem -like "*Windows 11*" -and Enabled -eq $true} `
                -Properties OperatingSystem | 
                Select-object Name,OperatingSystem, @{Name="OU";Expression={$_.DistinguishedName -replace '^CN=[^,]+,'}} | Sort-Object OU

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
    $script:winComputers = $result.WinComputers
    $script:LinuxServers = $result.LinuxServers
    $script:Users        = $result.Users

    $script:ADPowerShell.Dispose()
    $script:ADPowerShell  = $null
    $script:ADAsyncResult = $null
}

# Start background load immediately
Start-ADBackgroundLoad

# Export Public Members
Register-EngineEvent PowerShell.OnIdle -Action {
    Complete-ADBackgroundLoad
} | Out-Null

Export-ModuleMember -Function * `
                    -Variable WinServers, WinComputers, LinuxServers, Users, Scripts, Modules