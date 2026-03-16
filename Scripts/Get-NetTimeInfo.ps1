#requires -version 5.1
<#
.SYNOPSIS
  Short summary of script
.DESCRIPTION
  Detailed description of what the script does
.PARAMETER ComputerName
  Target computer name.
.PARAMETER Force
  Forces the action.
.INPUTS
  None.
.OUTPUTS
  Log file or console output.
.NOTES
  Version:        1.0
  Author:         Darrell Nielsen
  Creation Date:  2026-03-13
  Purpose/Change: Initial script development

  Tags:
    tag1, tag2

.EXAMPLE
  .\script.ps1 -ComputerName SERVER01
#>



[CmdletBinding(SupportsShouldProcess)]
param(
)

Import-Module activedirectory, MyCustomShell, pslogging -WarningAction Ignore

Set-StrictMode -Version Latest
$ErrorActionPreference = 'stop'
$WarningPreference = 'Ignore'

$ScriptVersion = '1.0'

#Switch below is for testing within ISE and VS Code Clean this space up when moving to production
switch ($Host.Name) {
    'ConsoleHost' {
        $ScriptName = Split-Path -Leaf $PSCommandPath
        $ScriptPath = $PSCommandPath
        $ScriptRoot = Split-Path -Parent $PSCommandPath
    }
    'Visual Studio Code Host' {
        $ScriptName = 'TempScript.ps1'
        $ScriptPath = Join-Path $env:TEMP $ScriptName
        $ScriptRoot = $env:TEMP
    }
    'Windows PowerShell ISE Host' {
        $ScriptName = 'TempScript.ps1'
        $ScriptPath = Join-Path $env:TEMP $ScriptName
        $ScriptRoot = $env:TEMP
    }
    default {
        $ScriptName = 'TempScript.ps1'
        $ScriptPath = Join-Path $env:TEMP $ScriptName
        $ScriptRoot = $env:TEMP
    }
}

$RunAsAdmin    = $true
$RequiresPowerShell7 = $false
$EnableTranscript = $false
$ExitCode = 1

if ($RequiresPowerShell7 -and $PSVersionTable.PSVersion.Major -lt 7) {
    Write-Log "This script must be run in PowerShell 7." -Level ERROR
    exit 1
}

if ($RunAsAdmin) {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "This script must be run as Administrator." -Level ERROR
        exit 1
    }
}



if ($EnableTranscript) {
    $TranscriptPath = Join-Path $env:TEMP ("$((Get-Date).ToString('yyyyMMdd-HHmmss'))-$ScriptName.log")
    Start-Transcript -Path $TranscriptPath -Force | Out-Null
}

Write-Log -Message "Starting $ScriptName $ScriptVersion" -Level INFO
Write-Log -Message "User: $env:USERNAME" -Level DEBUG
Write-Log -Message "Computer: $env:COMPUTERNAME" -Level DEBUG
Write-Log -Message "PowerShell Version: $($PSVersionTable.PSVersion)" -Level DEBUG

try {
    Write-Log "Start of main Logic"
    $results=@()
    $count=5
    foreach($server in $winservers[0]){
        
        Write-Log -message "processing $count of $($WinServers.Length):: $server"

        try{
            $output = invoke-command -ComputerName $server -ScriptBlock{

                $timezone = Get-WmiObject -Namespace "root\cimv2" -Class win32_timezone | select caption -ExpandProperty caption
                $HostName = $env:computername
                $w32tmoutput = w32tm /query /status
                #$exactTime = get-date -Format "HH:mm:ss:ms"

                $lastSyncTime = $null
                $timeSource = $null
                Write-Log -Message "formatting $server into parsable content"
                foreach($line in $w32tmoutput){
                    if($line -match "Last Successful Sync Time\s*:\s*(.+)"){
                        $lastSyncTime = $Matches[1].Trim()
                    }
                    elseif ($line -match "Source\s*:\s*(.+)") {
                        $timeSource =$Matches[1].Trim() 
                    }
                }
                #Write-Log "returning $server to parsable PScustomobject"
                return  [pscustomobject]@{
                    Hostname = $HostName
                    TimeZone = $timezone
                    LastSyncTime = $lastSyncTime
                    NTPServer = $timeSource
                    #CurrentTime = $exactTime
                } | Select-Object hostname, timezone, lastsynctime, ntpserver #, CurrentTime
            }
        #Write-Log "adding $results to output"
        $results += $output
        }
        catch{
            Write-Log -Message "An error occoured at $_ " -Level ERROR
            $results += [pscustomobject]@{
                Hostname = $HostName
                TimeZone = "ERROR" 
                LastSyncTime = "ERROR"
                NTPServer = "ERROR"
                #CurrentTime = "ERROR"
            } | Select-Object hostname, timezone, lastsynctime, ntpserver #, CurrentTime
        }
        $count++
    }
    $results | Format-Table -AutoSize 
}
catch {
    $ExitCode = 1
    Write-Log -Message "an error occoured:: $_.Exception.Message " -Level ERROR
}
finally {
    if ($EnableTranscript) {
        Stop-Transcript | Out-Null
    }
}

Write-Log -Message "Ending $ScriptName with exit code $ExitCode" -Level INFO

exit $ExitCode