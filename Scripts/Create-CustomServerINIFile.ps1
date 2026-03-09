<#
.SYNOPSIS
Generates a categorized server inventory from Active Directory and exports it to an INI file.

.DESCRIPTION
This script queries Active Directory for all enabled Windows Server computer objects
and automatically categorizes them based on naming conventions found in the server name.

The script parses the hostname to determine the server role (such as Domain Controller,
File Server, SQL, etc.) using a predefined role mapping table.

Servers are grouped by role and exported into an INI formatted file located at:

    $env:USERPROFILE\Documents\WindowsPowerShell\Files\Servers.ini

Each section of the INI file represents a detected role and contains the servers
belonging to that category.

If the INI file already exists it will be deleted and regenerated.

.PARAMETER None
This script does not accept parameters.

.EXAMPLE
.\Generate-ServerInventory.ps1

Queries Active Directory for Windows Servers and generates a categorized
Servers.ini file in the user’s PowerShell files directory.

.EXAMPLE
powershell.exe -ExecutionPolicy Bypass -File .\Generate-ServerInventory.ps1

Runs the script from another process and creates the categorized server list.

.OUTPUTS
INI File

Creates:
$env:USERPROFILE\Documents\WindowsPowerShell\Files\Servers.ini

Example output structure:

[DomainController]
server=corp-dc01
server=corp-dc02

[FileShare]
server=corp-fs01

[Databases]
server=corp-sql01

.NOTES
Author: Darrell Nielsen

Purpose:
Automatically build categorized server lists for administrative tools,
PowerShell modules, or management scripts.

Requirements:
- ActiveDirectory PowerShell module
- Domain connectivity
- Permission to query computer objects in Active Directory

File Location:
$env:USERPROFILE\Documents\WindowsPowerShell\Files\Servers.ini

Tags:
ActiveDirectory
ServerInventory
Automation
PowerShell
Infrastructure
ServerRoles
INI
EnterpriseAdministration

.LINK
Get-ADComputer
https://learn.microsoft.com/powershell/module/activedirectory/get-adcomputer

#>
[cmdletbinding()]
    param()
if($WinServers -eq $null){New-Variable -name WinServers -value  @(get-adcomputer -Filter {operatingsystem -like "*windows server*" -and Enabled -eq "True"}).name -Scope global
    }

$roleNameMap = @{
    "dc"  = "DomainController"
    "wec" = "WindowsEventCollector"
    "fs"  = "FileShare"
    "sql" = "Databases"
    "lr"  = "LogRhythm"
    "vdi" = "Citrix"
    "sen" = "Sentris"
    "iat" = "Nessus"
    "ps1" = "print"
    "wsus"= "UpdateServer"
    "dhcp" = "DHCP"
    "sep" =  "Symantic"
    "fp" =   "ForcePoint"
    }

$iniFile = "$env:userprofile\documents\windowspowershell\files\Servers.ini"
if(test-path $inifile) {remove-item $inifile}

$RoleGroups = @{}

foreach($server in $WinServers){
    $parts = $server -split "-"
    
    $middleParts = $parts[1..($parts.Count -2)]

    $rolekey = $null
    foreach ($part in $middleParts){

        $cleanPart = ($part -replace "\d","").ToLower()
        if($cleanPart){
            $roleKey = $cleanPart
            break
        }
    }

    if(-not $rolekey){
        $rolekey=($parts[1] -replace "\d","").ToLower()
    }

    
    if($roleNameMap.ContainsKey($rolekey)){
        $roleName = $roleNameMap[$rolekey]
    } 
    else {
        $roleName = (Get-Culture).TextInfo.ToTitleCase($rolekey)
    }
    if (-not $RoleGroups.ContainsKey($rolename)){
        $RoleGroups[$roleName] = @()
    }
    $rolegroups[$roleName] += $server
}

Add-Content -Path $iniFile -Value "; Servers categorized by auto-detected role"
Add-Content -Path $iniFile -Value "; Generated on $(get-date)"
add-content -Path $iniFile -Value ""

foreach($role in $RoleGroups.Keys){
    Add-Content -Path $iniFile -Value "[$role]"
    foreach($srv in $RoleGroups[$role]){
        Add-Content -Path $iniFile -Value "server=$srv"
    }
    Add-Content -Path $iniFile -Value ""

}
Write-Output "INI file created: $iniFile"
