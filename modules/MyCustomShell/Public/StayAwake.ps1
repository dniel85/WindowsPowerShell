function Stay-Awake {
<#
.SYNOPSIS
Prevents CPU lock

.DESCRIPTION
Sends a virtual key every minute to prevent workstation idle timeout.
Locks the workstation automatically when the timer expires.

.PARAMETER Hours
Number of hours to stay awake. Default is 2.

.EXAMPLE
Stay-Awake
Stay-Awake -Hours 4
#>

[CmdletBinding()]
param(
    [int]$Hours = 2
)
$minutes = $Hours * 60
$myShell = New-Object -ComObject "Wscript.shell"
Clear-Host
$oldPos = $host.UI.RawUI.CursorPosition
for ($i = 0; $i -lt $minutes; $i++) {
    $timeConvert = [timespan]::FromMinutes($i)
    Write-Host -NoNewline " <ESC> or [ctrl]+C" -ForegroundColor Red
    Write-Host -NoNewline " to quit! Elapsed time: " -ForegroundColor Cyan
    Write-Host ("{0:hh\:mm}" -f $timeConvert) -ForegroundColor Green -NoNewline
    Write-Host -NoNewline " Workstation will automatically lock after $Hours hour(s)." -ForegroundColor Cyan

    $host.UI.RawUI.CursorPosition = $oldPos
    $myShell.SendKeys("{F16}")

    for ($sleep = 1; $sleep -le 60; $sleep++) {

        if ($host.UI.RawUI.KeyAvailable -and ($host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho").VirtualKeyCode -eq 27)) {
            Write-Host
            Write-Host "Exit!" -ForegroundColor Red
            return
        }
        foreach ($spin in "|","/","-","\") {
            $host.UI.RawUI.CursorPosition = $oldPos
            Write-Host $spin -NoNewline -ForegroundColor White
            Start-Sleep -Milliseconds 115
        }
    }
}
rundll32.exe user32.dll,LockWorkStation
exit 0
}