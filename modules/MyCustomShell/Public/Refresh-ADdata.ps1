function Refresh-ADData {

<#
.SYNOPSIS
Refreshes AD data 

.DESCRIPTION
Queries Active Directory and updates exported module variables.
Safe for non-domain machines. The $Winservers, $LinuxServers, and $Users variables will be updated if successful.
#>

    # Check AD module availability
    if (-not (Get-Module -ListAvailable ActiveDirectory)) {
        Write-Warning "ActiveDirectory module not available."
        return
    }
    # Check if domain joined
    if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        Write-Warning "Machine is not domain joined."
        return
    }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        Write-Host "Refreshing Active Directory data..." -ForegroundColor Cyan

        $script:WinServers = Get-ADComputer -Filter {
            OperatingSystem -like "*windows server*" -and Enabled -eq "True"
        } | Select-Object -ExpandProperty Name

        $script:LinuxServers = Get-ADComputer -Filter {
            OperatingSystem -like "*Linux*" -and Enabled -eq "True"
        } | Select-Object -ExpandProperty Name

        $script:Users = Get-ADUser -Filter * |
            Select-Object Name,SamAccountName,Enabled,DistinguishedName

        Write-Host "AD data refreshed successfully." -ForegroundColor Green
        Write-Host "WinServers: $($WinServers.Count)" -ForegroundColor DarkCyan
        Write-Host "LinuxServers: $($LinuxServers.Count)" -ForegroundColor DarkCyan
        Write-Host "Users: $($Users.Count)" -ForegroundColor DarkCyan
    }
    catch {
        Write-Host "Failed to refresh Active Directory data: " -ForegroundColor Red 
    }
}