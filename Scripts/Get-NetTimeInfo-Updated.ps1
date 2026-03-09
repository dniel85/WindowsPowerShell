<#
.SYNOPSIS
    Retrieves time synchronization information from a list of remote Windows servers.

.DESCRIPTION
    This script reads a list of server names from a text file and queries each server
    for time synchronization status using the w32tm command.

    For each server, the script retrieves:
    - Hostname
    - Time zone
    - Last successful sync time
    - NTP server source
    - Current time

    The script uses PowerShell remoting (Invoke-Command) to execute the w32tm query on each server.

    Results are displayed in a formatted table.

.PARAMETER Winservers
    A text file containing a list of server names to query, one per line.(DEFAULT)

.EXAMPLE
    .\Get-NetTimeInfo-Updated.ps1

    Reads servers from:
    C:\STiG_Findings\ops\ExceptADM.txt

    Queries time synchronization status on each system and displays results in a table.

.NOTES
    Author: Darrell Nielsen
    Created: 2026-03-09
    Version: 1.0

TAGS:
    Time
    tools
    synchronization
    w32tm
    NTP
    timezones
    net time
#>
[cmdletbinding()]
    param()
$winservers = @(Get-Content 'C:\STiG_Findings\ops\ExceptADM.txt')
$results = @()

foreach($server in $winservers){
    try{
        $output = invoke-command -ComputerName $server -ScriptBlock{

            $timezone = Get-WmiObject -Namespace "root\cimv2" -Class win32_timezone | select caption -ExpandProperty caption
            $HostName = $env:computername
            $w32tmoutput = w32tm /query /status
            $exactTime = get-date -Format "HH:mm:ss:ms"

            $lastSyncTime = $null
            $timeSource = $null

            foreach($line in $w32tmoutput){
                if($line -match "Last Successful Sync Time\s*:\s*(.+)"){
                    $lastSyncTime = $Matches[1].Trim()
                }
                elseif ($line -match "Source\s*:\s*(.+)") {
                    $timeSource =$Matches[1].Trim() 
                }
            }

            return  [pscustomobject]@{
                Hostname = $HostName
                TimeZone = $timezone
                LastSyncTime = $lastSyncTime
                NTPServer = $timeSource
                CurrentTime = $exactTime
        } | Select-Object hostname, timezone, lastsynctime, ntpserver, CurrentTime
    }

    $results += $output
    }
    catch{
        $results += [pscustomobject]@{
            Hostname = $HostName
            TimeZone = "ERROR" 
            LastSyncTime = "ERROR"
            NTPServer = "ERROR"
            CurrentTime = "ERROR"
        } | Select-Object hostname, timezone, lastsynctime, ntpserver, CurrentTime
    }
}
$results | Format-Table -AutoSize 
