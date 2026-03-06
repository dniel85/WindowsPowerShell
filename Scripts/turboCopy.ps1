<#
.SYNOPSIS
 TurboCopy - Robocopy wrapper with multi-threading, MIR, and byte-based progress bar

.DESCRIPTION
 Copies files from a single source to multiple destinations in parallel using Robocopy.
 Shows a single progress bar based on total bytes copied across all destinations.
 Supports multi-threading, MIR, logging, and exit code warnings.

.EXAMPLE
 Basic copy with progress
 .\turboCopy.ps1 -Source "C:\Temp Folder" -Destination "D:\Backup Folder"

.EXAMPLE
 Mirror with 16 threads and logging
 .\turboCopy.ps1 -Source "C:\Temp Folder" -Destination "D:\Backup Folder" -Mirror -Threads 16 -LogToFile

.EXAMPLE
 Multi-destination functionality copied in parallel
 .\turboCopy.ps1 -Source "C:\Temp Folder" -Destinations "D:\Backup1","E:\Backup2","F:\Backup3" -Mirror -Threads 16 -LogToFile

 .NOTES
Author: Darrell Nielsen
Created: 2026-03-06
Version: 1.0

Tags:
copy
robo
robocopy
turbo

.FUNCTIONALITY
   Copy files really fast.... 
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$Source,

    [Parameter(Mandatory=$true)]
    [string[]]$Destinations,  # Array of destinations

    [int]$Threads = 8,
    [switch]$Mirror,
    [switch]$LogToFile,
    [string]$LogFile = "$env:TEMP\turboCopy_log.txt"
)

# ---------------- Validate Source ----------------
if (-not (Test-Path $Source)) { Write-Error "Source path does not exist: $Source"; exit }
$Source = $Source.TrimEnd('\')

# ---------------- Create Destinations ----------------
foreach ($Dest in $Destinations) {
    $DestTrim = $Dest.TrimEnd('\')
    if (-not (Test-Path $DestTrim)) { New-Item -ItemType Directory -Path $DestTrim | Out-Null }
}

# ---------------- Calculate Total Bytes ----------------
Write-Host "Calculating total bytes to copy..."
$allFiles = Get-ChildItem -Path $Source -Recurse -File
$totalBytes = ($allFiles | Measure-Object -Property Length -Sum).Sum
if ($totalBytes -eq 0) { Write-Host "No files found in source."; exit }

$totalBytesAll = $totalBytes * $Destinations.Count

# ---------------- Function to Start Robocopy ----------------
function Start-RoboCopyJob {
    param ($Source, $Destination, $Threads, $Mirror, $LogToFile, $LogFile)

    $DestTrim = $Destination.TrimEnd('\')
    $robocopyOptions = @('/E', "/MT:$Threads", '/R:3', '/W:5')
    if ($Mirror) { $robocopyOptions += '/MIR' }
    if ($LogToFile) { $robocopyOptions += "/LOG:`"$LogFile`"" }

    $sourceArg = '"' + $Source + '"'
    $destArg   = '"' + $DestTrim + '"'
    $rcArgs    = $sourceArg + ' ' + $destArg + ' ' + ($robocopyOptions -join ' ')

    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = "robocopy.exe"
    $processInfo.Arguments = $rcArgs
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo
    $process.Start() | Out-Null
    return $process
}

# ---------------- Start Timer ----------------
$startTime = Get-Date

# ---------------- Start All Jobs ----------------
$jobs = @()
$jobStartTimes = @{}
foreach ($Dest in $Destinations) {
    $proc = Start-RoboCopyJob -Source $Source -Destination $Dest -Threads $Threads -Mirror:$Mirror -LogToFile:$LogToFile -LogFile $LogFile
    $jobs += $proc
    $jobStartTimes[$Dest] = Get-Date
}

Write-Host "Copying in parallel to multiple destinations..."

# ---------------- Combined Progress Loop ----------------
while ($jobs | Where-Object { -not $_.HasExited }) {
    Start-Sleep -Seconds 2

    $copiedBytes = 0
    foreach ($Dest in $Destinations) {
        $DestTrim = $Dest.TrimEnd('\')
        $copiedBytes += (Get-ChildItem -Path $DestTrim -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    }

    $percent = [math]::Min(100, [int](($copiedBytes / $totalBytesAll) * 100))
    Write-Progress -Activity "Copying to all destinations" -Status "$([math]::Round($copiedBytes/1MB,2)) MB of $([math]::Round($totalBytesAll/1MB,2)) MB copied" -PercentComplete $percent
}

# ---------------- Wait for Jobs and Check Exit Codes ----------------
Write-Host "`nPer-destination summary:"
foreach ($i in 0..($Destinations.Count-1)) {
    $process = $jobs[$i]
    $DestTrim = $Destinations[$i].TrimEnd('\')
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    $endTime = Get-Date
    $durationMinutes = ($endTime - $jobStartTimes[$Destinations[$i]]).TotalMinutes
    $bytesCopied = (Get-ChildItem -Path $DestTrim -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    $GBCopied = [math]::Round($bytesCopied / 1GB, 2)

    if ($exitCode -le 7) { 
        Write-Host "$DestTrim : $GBCopied GB copied in $([math]::Round($durationMinutes,2)) minutes." 
    } else { 
        Write-Warning "$DestTrim : $GBCopied GB copied in $([math]::Round($durationMinutes,2)) minutes. Exit code: $exitCode"
    }
}

# ---------------- End Timer ----------------
$totalDuration = ($endTime - $startTime).TotalMinutes
$totalGBAll = [math]::Round($totalBytesAll / 1GB, 2)

Write-Host "`n-------------------------------------------"
Write-Host "All copies completed."
Write-Host "$totalGBAll GB copied across $($Destinations.Count) destinations in $([math]::Round($totalDuration,2)) minutes."
Write-Host "-------------------------------------------"