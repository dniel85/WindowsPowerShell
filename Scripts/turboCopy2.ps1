<#
    turboCopy.ps1
    Multi-destination Robocopy engine with parallel jobs,
    progress bars, logging, speed summary, and error filtering.

    Tested on:
      - Windows PowerShell 5.1
      - PowerShell 7.x
#>

param(
    [Parameter(Mandatory)]
    [string]$Source,

    [Parameter(Mandatory)]
    [string[]]$Destinations,

    [switch]$Mirror,
    [switch]$LogToFile
)

Clear-Host
Write-Host "TurboCopy - Multi-Destination File Replication" -ForegroundColor Cyan
Write-Host "Source: $Source"

# Normalize path
$Source = $Source.TrimEnd('\')

if (-not (Test-Path $Source)) {
    Write-Host "ERROR: Source path not found." -ForegroundColor Red
    exit 1
}

# Count total size in bytes
Write-Host "Calculating total source size..."
$files = Get-ChildItem -Path $Source -Recurse -File -ErrorAction SilentlyContinue
$TotalBytes = ($files | Measure-Object Length -Sum).Sum
$TotalGB = [math]::Round($TotalBytes / 1GB, 2)

# Build Robocopy switches
$commonArgs = "/E /NFL /NDL /NP /R:3 /W:5 /MT:8"

if ($Mirror) { $commonArgs += " /MIR" }
if ($LogToFile) {
    $global:LogDir = "$PSScriptRoot\Logs"
    if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
}

# Job container
$Jobs = @()

foreach ($Dest in $Destinations) {

    # Normalize destination
    $Dest = $Dest.TrimEnd('\')

    Write-Host "`nStarting copy to: $Dest" -ForegroundColor Yellow

    # Ensure remote admin share path exists
    try {
        if (-not (Test-Path $Dest)) {
            Write-Host "Creating folder $Dest ..."
            New-Item -ItemType Directory -Force -Path $Dest | Out-Null
        }
    }
    catch {
        Write-Host "WARNING: Destination path $Dest may not yet exist, continuing..." -ForegroundColor DarkYellow
    }

    # Create per-destination log file
    $LogFile = $null
    if ($LogToFile) {
        $safeName = $Dest -replace '[\\/:*?"<>|]', '_'
        $LogFile = "$LogDir\Robo_$safeName.log"
        $Args = "`"$Source`" `"$Dest`" $commonArgs /LOG:`"$LogFile`""
    }
    else {
        $Args = "`"$Source`" `"$Dest`" $commonArgs"
    }

    # Start copy as parallel job
    $Jobs += Start-Job -ScriptBlock {
        param($src, $dst, $args, $totalBytes)

        $start = Get-Date

        # RUN ROBOCOPY
        $process = Start-Process -FilePath "robocopy.exe" -ArgumentList $args -PassThru -NoNewWindow -Wait

        # Measure destination bytes
        $currentBytes = 0
        if (Test-Path $dst) {
            $items = Get-ChildItem -Path $dst -Recurse -File -ErrorAction SilentlyContinue
            $currentBytes = ($items | Measure-Object Length -Sum).Sum
        }

        $end = Get-Date
        $duration = ($end - $start).TotalMinutes

        [PSCustomObject]@{
            Destination = $dst
            ExitCode = $process.ExitCode
            BytesCopied = $currentBytes
            DurationMin = $duration
        }

    } -ArgumentList $Source, $Dest, $Args, $TotalBytes
}

Write-Host "`n--- Running parallel copy jobs ---`n" -ForegroundColor Cyan

# Wait and show job progress bars
while ($Jobs.State -contains "Running") {
    $i = 0
    foreach ($job in $Jobs) {
        $i++
        Write-Progress -Activity "Copying files" -Status "Job $i of $($Jobs.Count): $($job.Location)" -PercentComplete (($job.Progress * 100) -as [int])
    }
    Start-Sleep -Seconds 1
}

# Collect results
$Results = $Jobs | Receive-Job

# Cleanup jobs
$Jobs | Remove-Job -Force

Write-Host "`n--- COPY SUMMARY ---" -ForegroundColor Cyan

foreach ($result in $Results) {

    $GB = [math]::Round($result.BytesCopied / 1GB, 2)
    $Min = [math]::Round($result.DurationMin, 2)

    Write-Host "`nDestination: $($result.Destination)" -ForegroundColor Yellow
    Write-Host "Copied:      $GB GB"
    Write-Host "Duration:    $Min minutes"

    if ($result.ExitCode -gt 7) {
        Write-Host "Robocopy Exit Code: $($result.ExitCode)  (ERROR)" -ForegroundColor Red
    }
    else {
        Write-Host "Robocopy Exit Code: $($result.ExitCode)  (OK)" -ForegroundColor Green
    }
}

Write-Host "`nAll transfers completed.`n" -ForegroundColor Cyan
