<#
.SYNOPSIS
    Retrieves Defender status for domain

.DESCRIPTION
    Use this to run against a domain connected network. Will iterate through the domain and retrieve the status of all domain connected workstations and servers.

.PARAMETER ParameterName
    Parameter description

.EXAMPLE
    .\Get-DomainDefenderStatus.ps1

.NOTES
    Author: Darrell Nielsen
    Created: 2026-03-06
    Version: 1.0

TAGS
    Defender
    status
    IA
    Security
    scan
    mpsignature
#>
Import-Module ActiveDirectory

$servers = @(Get-Content 'C:\STiG_Findings\ops\ExceptADM.txt')
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
        $results |ft -AutoSize
        $results | export-csv -Path $env:userprofile\documents\defenderStatus_$formattedtime.csv -NoTypeInformation -Force
        Write-Host "` CSV resuls path:: $env:userprofile\documents\defenderStatus_$formattedtime.csv" -ForegroundColor Yellow


