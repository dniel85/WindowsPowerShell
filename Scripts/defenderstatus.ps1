<#
.SYNOPSIS
Scans remote servers to collect Microsoft Defender Antivirus status information.

.DESCRIPTION
This script reads a list of server names from a text file and queries each server
for Microsoft Defender Antivirus status using the MSFT_MpComputerStatus CIM class.

For each server the script retrieves:

- Antivirus signature version
- Antivirus enabled status
- Last signature update time
- Last completed quick scan
- Signature age

The script uses PowerShell remoting (Invoke-Command) to execute the Defender
status query on each server.

Progress is displayed during execution using Write-Progress so the operator
can monitor scan progress.

Results are displayed in a formatted table and exported to a timestamped CSV file
in the user's Documents directory.

.PARAMETER None
This script does not accept parameters.

.EXAMPLE
.\Get-DefenderServerStatus.ps1

Reads servers from:
C:\STiG_Findings\ops\OPSRV.txt

Queries Defender status on each system and exports results to:

$env:USERPROFILE\Documents\defenderStatus_<timestamp>.csv

.EXAMPLE
powershell.exe -ExecutionPolicy Bypass -File .\Get-DefenderServerStatus.ps1

Runs the script from another process or scheduled task.

.INPUTS
System.String

Server names are read from a text file containing one server name per line.

.OUTPUTS
PSCustomObject

The script outputs objects with the following properties:

ComputerName
Version
Enabled
LastUpdated
LastCompletedScan
SignatureAge

It also exports the data to a CSV file.

.NOTES
Author: Darrell Nielsen

Purpose:
Audit Microsoft Defender Antivirus status across multiple servers.

Requirements:
- ActiveDirectory PowerShell module
- PowerShell Remoting enabled on target servers
- Administrator privileges on remote systems
- Access to query Defender CIM classes

Input File:
C:\STiG_Findings\ops\OPSRV.txt

Output File:
$env:USERPROFILE\Documents\defenderStatus_<timestamp>.csv

Tags:
Defender
MicrosoftDefender
Security
STIG
Compliance
ServerAudit
PowerShell
EndpointSecurity
WindowsSecurity

#>

Import-Module ActiveDirectory

$servers = @(Get-Content 'C:\STiG_Findings\ops\OPSRV.txt')
$totalServers = $servers.Count
$currentProgress = 0
$results = @() 

foreach ($server in $servers){

    $currentprogress++
    $progressMessage = "Scanning server: $server"

    Write-Progress -Activity "Scanning Servers Defender Status" -Status $progressMessage -PercentComplete (($currentProgress / $totalServers) * 100)

    #$serverData =Get-CimInstance  -ComputerName $server -ClassName MSFT_MpComputerStatus -Namespace root/microsoft/windows/defender -ErrorAction SilentlyContinue
        $serverData = invoke-command -ComputerName $server -ScriptBlock { Get-CimInstance -ClassName MSFT_MpComputerStatus -Namespace root/microsoft/windows/defender -ErrorAction SilentlyContinue } -ErrorAction SilentlyContinue

    $Tabledata = [pscustomobject]@{
        ComputerName = $server
        Version = if($serverdata.AntivirusSignatureVersion){$serverdata.AntivirusSignatureVersion}else{"UNK"}
        Enabled = if($serverdata.antivirusEnabled){$serverdata.antivirusEnabled}else{"UNK"} 
        LastUpdated = if($serverdata.AntivirusSignatureLastUpdated){$serverdata.AntivirusSignatureLastUpdated}else{"UNK"}
        LastCompletedScan = if($serverdata.QuickScanEndTime){$serverdata.QuickScanEndTime}else{"UNK"}
        SignatureAge = if($serverData.NISSignatureAge){$serverdata.nissignatureage}else{"UNK"}
        }

        $results += $Tabledata

        }

        Write-Progress -Activity "Defender Scan" -Completed
        $FormattedTime = (get-date).ToString("dd-MMM_HHmm")
        $results |format-table -AutoSize
        $results | export-csv -Path $env:userprofile\documents\defenderStatus_$formattedtime.csv -NoTypeInformation -Force
        Write-Host "` CSV resuls path:: $env:userprofile\documents\defenderStatus_$formattedtime.csv" -ForegroundColor Yellow