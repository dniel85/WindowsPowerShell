<#
.SYNOPSIS
Displays a real-time view of Windows Firewall traffic from the firewall log.

.DESCRIPTION
This script reads and tails the Windows Firewall log file (pfirewall.log) and
displays traffic events in real time inside the PowerShell console.

The console window is maximized and formatted to show a continuously updating
table of firewall events. Traffic entries are color-coded based on action:

    Green  = Allowed traffic
    Red    = Blocked/Dropped traffic
    Gray   = Other actions

If firewall logging is disabled, the script temporarily enables logging for
Domain, Private, and Public firewall profiles. When the script exits (including
when Ctrl+C is pressed), the original firewall logging settings are restored.

The script reads the header fields directly from the firewall log to determine
which columns to display and maintains a circular buffer to render a scrolling
view of the most recent events.

.PARAMETER SourceIPs
Optional list of source IP addresses to filter. Only traffic originating from
these IPs will be displayed.

If left empty, all firewall traffic entries will be shown.

.PARAMETER LogPath
Path to the Windows Firewall log file.

Default:
C:\Windows\System32\LogFiles\Firewall\pfirewall.log

.EXAMPLE
.\Watch-FirewallTraffic.ps1

Displays all firewall traffic in real time.

.EXAMPLE
.\Watch-FirewallTraffic.ps1 -SourceIPs 10.10.10.15

Shows only firewall traffic originating from 10.10.10.15.

.EXAMPLE
.\Watch-FirewallTraffic.ps1 -SourceIPs 10.10.10.15,192.168.1.20

Filters traffic for multiple source IP addresses.

.EXAMPLE
.\Watch-FirewallTraffic.ps1 -LogPath "D:\Logs\Firewall\pfirewall.log"

Reads firewall traffic from a custom log location.

.INPUTS
System.String[]

.OUTPUTS
None

The script writes formatted output directly to the console.
.ROLE
Administrator

.NOTES
Author: Darrell Nielsen
Created: 2026-03-06
Version: 1.0

Tags:
firewall
logs
troubleshoot

Requirements:
- Must be run with sufficient privileges to modify firewall logging settings.
- Windows Firewall logging must be available on the system.
- PowerShell 5.1 or later recommended.

Behavior:
- Maximizes the PowerShell console window.
- Temporarily enables firewall logging if disabled.
- Restores original firewall settings on script exit.
- Uses a circular buffer to render a scrolling live view of traffic.

#>
param(
    [string[]]$SourceIPs = @(),  # Leave empty to show all traffic
    [string]$LogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
)

# Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit 1
}


cls

# Maximize the console window
$hwnd = (Get-Process -Id $PID).MainWindowHandle
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@
# 3 = Maximized
[Win32]::ShowWindow($hwnd, 3)

# Optional: Adjust buffer size to match window
$host.UI.RawUI.BufferSize = $host.UI.RawUI.WindowSize



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
