# ===============================
# MyCustomShell Module
# ===============================
Write-Host "Type 'Menu' to list all pre-defined Commands and Variables" -ForegroundColor DarkGray
# Load all public functions
$publicPath = Join-Path $PSScriptRoot "Public"

Get-ChildItem $publicPath -Filter *.ps1 | ForEach-Object {
    . $_.FullName
}

# ===============================
# Initialize Exported Variables
# ===============================

$script:WinServers   = @()
$script:LinuxServers = @()
$script:Users        = @()

$script:Scripts = Join-Path $env:USERPROFILE "Documents\PowerShell\Scripts"
$script:Modules = $env:PSModulePath

# ===============================
# Background AD Runspace
# ===============================

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
    $script:LinuxServers = $result.LinuxServers
    $script:Users        = $result.Users

    $script:ADPowerShell.Dispose()
    $script:ADPowerShell  = $null
    $script:ADAsyncResult = $null
}



# Start background load immediately
Start-ADBackgroundLoad

# ===============================
# Export Public Members
# ===============================




Register-EngineEvent PowerShell.OnIdle -Action {
    Complete-ADBackgroundLoad
} | Out-Null

Export-ModuleMember -Function * `
                    -Variable WinServers, LinuxServers, Users, Scripts, Modules


