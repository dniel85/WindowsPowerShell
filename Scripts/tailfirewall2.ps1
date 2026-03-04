param(
    [string[]]$SourceIPs = @(),  # Leave empty to show all traffic
    [string]$LogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
)

# -----------------------------
# Save current firewall logging settings
# -----------------------------
$profiles = @("Domain", "Private", "Public")
$originalSettings = @{}

foreach ($p in $profiles) {
    $fw = Get-NetFirewallProfile -Profile $p
    $originalSettings[$p] = [PSCustomObject]@{
        LogAllowed = $fw.LogAllowed
        LogBlocked = $fw.LogBlocked
        LogFileName = $fw.LogFileName
        LogMaxSizeKilobytes = $fw.LogMaxSizeKilobytes
    }
}

# -----------------------------
# Enable firewall logging if not enabled
# -----------------------------
$loggingEnabled = $false
foreach ($p in $profiles) {
    $fw = Get-NetFirewallProfile -Profile $p
    if ($fw.LogAllowed -or $fw.LogBlocked) { $loggingEnabled = $true }
}

if (-not $loggingEnabled) {
    Write-Host "Firewall logging is OFF. Enabling now..." -ForegroundColor Yellow
    foreach ($p in $profiles) {
        Set-NetFirewallProfile -Profile $p `
            -LogAllowed True `
            -LogBlocked True `
            -LogFileName $LogPath `
            -LogMaxSizeKilobytes 32768
    }
}

# -----------------------------
# Handle Ctrl+C to restore firewall logging
# -----------------------------
$onExit = {
    Write-Host "`nRestoring original firewall logging settings..." -ForegroundColor Cyan
    foreach ($p in $profiles) {
        $s = $originalSettings[$p]
        Set-NetFirewallProfile -Profile $p `
            -LogAllowed $s.LogAllowed `
            -LogBlocked $s.LogBlocked `
            -LogFileName $s.LogFileName `
            -LogMaxSizeKilobytes $s.LogMaxSizeKilobytes
    }
    [console]::CursorVisible = $true
    Write-Host "Done." -ForegroundColor Green
}

# Register Ctrl+C handler
$null = Register-EngineEvent PowerShell.Exiting -Action $onExit

# -----------------------------
# Read header
# -----------------------------
$headerLine = Select-String -Path $LogPath -Pattern "#Fields:" -SimpleMatch | Select-Object -First 1
if ($headerLine) {
    $fieldNames = $headerLine.Line -replace "#Fields:\s*", "" -split "\s+"
} else {
    $fieldNames = "date","time","action","protocol","src-ip","dst-ip","src-port","dst-port"
}

# -----------------------------
# Console setup
# -----------------------------
[console]::CursorVisible = $false
$startRow = 0
$maxRows = [console]::WindowHeight - 2
$logBuffer = @()

# Print header
[console]::SetCursorPosition(0, $startRow)
Write-Host ($fieldNames -join "`t") -ForegroundColor Cyan

# -----------------------------
# Tail log file
# -----------------------------
try {
    Get-Content -Path $LogPath -Wait -Tail 10 | ForEach-Object {
        if ($_ -match "^#") { return }

        $data = $_ -split "\s+"
        if ($data.Count -ne $fieldNames.Count) { return }

        $entry = [PSCustomObject]@{}
        for ($i=0; $i -lt $fieldNames.Count; $i++) {
            $entry | Add-Member -MemberType NoteProperty -Name $fieldNames[$i] -Value $data[$i]
        }

        # Filter by Source IPs if provided
        if ($SourceIPs.Count -gt 0 -and ($SourceIPs -notcontains $entry.'src-ip')) { return }

        # Determine color
        $color = switch ($entry.action) {
            "ALLOW" { "Green" }
            "ALLOW-ASSOC" { "Green" }
            "BLOCK" { "Red" }
            "DROP" { "Red" }
            default { "Gray" }
        }

        # Add to circular buffer
        $logBuffer += @{ Line = ($data -join "`t"); Color = $color }
        if ($logBuffer.Count -gt $maxRows) {
            $logBuffer = $logBuffer[-$maxRows..-1]
        }

        # Render buffer below header
        for ($i=0; $i -lt $logBuffer.Count; $i++) {
            $targetRow = $startRow + 1 + $i
            [console]::SetCursorPosition(0, $targetRow)
            $line = $logBuffer[$i].Line
            Write-Host ($line.PadRight([console]::WindowWidth)) -ForegroundColor $logBuffer[$i].Color -NoNewline
        }
    }
} finally {
    & $onExit
}
