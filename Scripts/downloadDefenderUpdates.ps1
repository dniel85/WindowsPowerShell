<#
.SYNOPSIS 
    Downloads the latest Microsoft Defender Antivirus updates and packages them into an ISO file.

.DESCRIPTION
    This script retrieves the latest Microsoft Defender Antivirus signature updates for both x64 and x86 architectures.
    It downloads the updates from the official Microsoft links, saves them to a specified directory, and then creates an ISO file containing the updates.

    The script checks for the existence of the target directories and creates them if they do not exist. 
    After downloading the updates, it generates an ISO file named with the current date and moves it to a transfer location.

    Finally, it cleans up the temporary files used for creating the ISO.

.PARAMETER None
    This script does not accept any parameters.
    

.EXAMPLE
    .\downloadDefenderUpdates.ps1

    Downloads the latest Defender updates, creates an ISO file, and saves it to the transfer directory.

.NOTES
    Author: Darrell Nielsen
    Created: 2026-03-09
    Version: 1.0

TAGS:
    Defender
    MicrosoftDefender
    Antivirus
    Updates
    ISO
    Automation
#>

Import-Module Write-Log
try{
$mpam64 = "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64"
$mpam86 = "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86"
Write-Log -var $mpam64
write-log -var $mpam86
$nis64 = "https://go.microsoft.com/fwlink/?LinkID=187316&arch=x64&nri=true"
$nis86 = "https://go.microsoft.com/fwlink/?LinkID=187316&arch=x86&nri=true"
Write-Log -var $nis64
Write-Log -var $nis86

$x64_path = "C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x64\"
$x86_path = "C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x86\"
$transfer_Path = "N:\Transfer\For Darrell"

if(!(test-Path -PathType Container $x64_path -OutVariable TF)){New-Item -ItemType Directory -Path $x64_path}
Write-Log -Message "Testing boolian $TF"
if(!(test-Path -PathType Container $x86_path -OutVariable TF)){New-Item -ItemType Directory -Path $x86_path}
Write-Log -Message "Testing boolian $TF"
if(!(test-Path -PathType Container $transfer_path)){New-Item -ItemType Directory -Path $transfer_path}

Invoke-WebRequest $mpam64 -OutFile "C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x64\mpam-fe.exe"
Write-Log -Message "Invokeing WebRequest on $mpam64 outfile = C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x64\mpam-fe.exe"
Invoke-WebRequest $mpam86 -OutFile "C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x86\mpam-fe.exe"

Invoke-WebRequest $nis64 -OutFile "C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x64\nis_full.exe" 
Invoke-WebRequest $nis86 -OutFile "C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x86\nis_full.exe"

gci 'N:\Transfer\For Darrell' | where {$_.name -like "*defenderUpdates.iso"} | Remove-Item

$date = (get-date).ToString("MM-dd-yy")

New-IsoFile -Source C:\Users\darrell.nielsen\Desktop\DefenderUpdates -Path "N:\Transfer\For Darrell\$date-defenderUpdates.iso"

start-sleep -Seconds 20 

Remove-Item -Path "C:\users\darrell.nielsen\Desktop\DefenderUpdates" -Recurse
}
catch{Write-Log -Message "An error occored:: $_" -Level ERROR}