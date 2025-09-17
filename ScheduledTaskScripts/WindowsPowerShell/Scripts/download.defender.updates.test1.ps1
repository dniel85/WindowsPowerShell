try {
    # Ensure the script is running as a file
    if (-not $PSCommandPath) {
        throw "This script must be run from a .ps1 file, not interactively."
    }

    # Get script name and paths
    $ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
    $logPath = "C:\ScheduledTasks\logs\$ScriptName"
    $logName = "$ScriptName.log"
    $fullLogPath = Join-Path $logPath $logName
    $date = Get-Date -Format "dd-MM-yy_HHmm"

    # Create log directories if they don't exist
    if (-not (Test-Path $logPath)) {
        New-Item -Path $logPath -ItemType Directory -Force | Out-Null
    }
    $archivePath = Join-Path $logPath "archived_logs"
    if (-not (Test-Path $archivePath)) {
        New-Item -Path $archivePath -ItemType Directory -Force | Out-Null
    }

    # Rotate log if it exceeds 10 MB
    if (Test-Path $fullLogPath -and (Get-Item $fullLogPath).Length -gt 10MB) {
        $archivedLogName = "$date.$logName"
        $archivedLogFullPath = Join-Path $archivePath $archivedLogName
        Move-Item -Path $fullLogPath -Destination $archivedLogFullPath -Force
    }

} catch {
    Write-Host "Error: $($_.Exception.Message)"
    exit 1
}

# Start transcript
Start-Transcript -Path $fullLogPath -Append