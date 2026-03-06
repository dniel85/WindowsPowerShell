<#
.SYNOPSIS
Retrieves Windows Firewall profile status from remote servers.

.DESCRIPTION
This script queries one or more remote Windows servers and returns the enabled
status of the Domain, Private, and Public Windows Firewall profiles.

If the variable $winservers is not already defined, the script reads the list
of target servers from:

C:\STiG_Findings\ops\ExceptADM.txt

The script then uses Invoke-Command to remotely execute Get-NetFirewallProfile
on each server and returns a formatted table showing the firewall profile
status for each system.

.PARAMETER winservers
Optional array of computer names to query. If not provided, the script loads
server names from C:\STiG_Findings\ops\ExceptADM.txt.

.EXAMPLE
.\Get-FirewallProfileStatus.ps1

Runs the script and loads server names from:
C:\STiG_Findings\ops\ExceptADM.txt

.EXAMPLE
$winservers = "Server01","Server02"
.\Get-FirewallProfileStatus.ps1
Queries only the specified servers.

.INPUTS
System.String

.OUTPUTS
System.Management.Automation.PSCustomObject

Output properties:
ComputerName
Domain
Private
Public

.NOTES
Author: Darrell Nielsen
Created: 2026-03-06
Version: 1.0

TAGS:
Firewall
security
compliance
settings
domain

Requirements:
- PowerShell Remoting enabled on target systems
- User must have permission to run Invoke-Command remotely
- Get-NetFirewallProfile available on remote hosts

#>
if($winservers -eq $null) {$winservers = @(Get-Content 'C:\STiG_Findings\ops\ExceptADM.txt')

    }
Invoke-Command -ComputerName $winservers -ScriptBlock {
    $profiles = Get-NetFirewallProfile | Select-Object Name,Enabled
    $map = @{}
    foreach ($item in $profiles){
        $map[$item.name] = $item.enabled
    }
    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Domain       = $map['Domain']
        Private      = $map['Private']
        Public       = $map['Public']
    }
} | Format-Table ComputerName, Domain,Private,Public -AutoSize