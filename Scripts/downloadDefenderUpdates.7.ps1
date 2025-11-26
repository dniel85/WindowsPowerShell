

if($PSVersionTable.PSVersion.Major -lt 7){
    Write-Host "PowerShell version 7 must be used to run this Script" -ForegroundColor Red
    exit 1 
    }

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

# Start transcript logging
Start-Transcript -Path $fullLogPath -Append

Write-Host "Starting Defender update script..." -ForegroundColor Cyan

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


# Build download list for parallel execution
$downloads = @(
    @{ Url = $mpam.x64; Path = Join-Path $x64Path "mpam-fe.exe" }
    @{ Url = $mpam.x86; Path = Join-Path $x86Path "mpam-fe.exe" }
    @{ Url = $nis.x64;  Path = Join-Path $x64Path "nis_full.exe" }
    @{ Url = $nis.x86;  Path = Join-Path $x86Path "nis_full.exe" }
)

Write-Host "Downloading Defender updates in parallel..." -ForegroundColor Cyan

$results = $downloads | ForEach-Object -Parallel {
    try {
        Write-Host "Downloading $($_.Url)..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $_.Url -OutFile $_.Path -UseBasicParsing -ErrorAction Stop
        return [PSCustomObject]@{
            Url = $_.Url
            Path = $_.Path
            Status = "Success"
        }
    }
    catch {
        return [PSCustomObject]@{
            Url = $_.Url
            Path = $_.Path
            Status = "Failed: $($_.Exception.Message)"
        }
    }
} -ThrottleLimit 4

# Show results
$results | ForEach-Object {
    Write-Host "[$($_.Status)] $($_.Url) -> $($_.Path)" -ForegroundColor Yellow
}

# Copy downloaded files to transfer destination
Write-Host "Copying updated definitions to transfer folder..." -ForegroundColor Cyan
Copy-Item -Path (Join-Path $basePath "*") -Recurse -Destination $transferDestination -Force

Write-Host "✅ Defender updates complete." -ForegroundColor Cyan
Write-Host "✅ Files copied to $transferDestination" -ForegroundColor Cyan

Stop-Transcript