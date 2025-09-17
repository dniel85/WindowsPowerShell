
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
    if ((Test-Path $fullLogPath) -and ((Get-Item $fullLogPath).Length -gt 10MB)) {
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
# URLs for Microsoft Defender updates
$mpam = @{
    x64 = "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64"
    x86 = "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86"
}

$nis = @{
    x64 = "https://go.microsoft.com/fwlink/?LinkID=187316&arch=x64&nri=true"
    x86 = "https://go.microsoft.com/fwlink/?LinkID=187316&arch=x86&nri=true"
}

# Local paths
$basePath = "C:\ScheduledTasks\files\DefenderUpdates\wd_dfs"
$x64Path = Join-Path $basePath "x64"
$x86Path = Join-Path $basePath "x86"
$transferPath = "N:\Transfer\For Darrell"
$transferDestination = Join-Path "N:\Transfer" "__WD_defs"

# Ensure directories exist
$x64Path, $x86Path, $transferPath, $transferDestination | ForEach-Object {
    if (-not (Test-Path -Path $_ -PathType Container)) {
        New-Item -Path $_ -ItemType Directory -Force | Out-Null
    }
}

# Download files
Invoke-WebRequest $mpam.x64 -OutFile (Join-Path $x64Path "mpam-fe.exe")
Invoke-WebRequest $mpam.x86 -OutFile (Join-Path $x86Path "mpam-fe.exe")

Invoke-WebRequest $nis.x64 -OutFile (Join-Path $x64Path "nis_full.exe")
Invoke-WebRequest $nis.x86 -OutFile (Join-Path $x86Path "nis_full.exe")

# Copy all downloaded files to transfer folder
Copy-Item -Path (Join-Path $basePath "*") -Recurse -Destination $transferDestination -Force

Stop-Transcript