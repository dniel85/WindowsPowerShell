[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [int][ValidateRange(1,8)] $hours
)

$minutes = $hours * 60
$myShell = New-Object -ComObject "Wscript.Shell"
Clear-Host

for ($i = 0; $i -lt $minutes; $i++) {
    $timeConvert = [TimeSpan]::FromMinutes($i)
    $oldPos = $host.UI.RawUI.CursorPosition

    Write-Verbose $timeConvert
    Write-Host -NoNewline " <ESC> or [Ctrl]+C" -ForegroundColor Red
    Write-Host -NoNewline " to quit! Elapsed time: " -ForegroundColor Cyan
    Write-Host ("{0:hh\:mm}" -f $timeConvert) -ForegroundColor Green -NoNewline
    Write-Host -NoNewline (" Workstation will automatically lock after {0} hour(s)." -f $hours) -ForegroundColor Cyan

    $myShell.SendKeys("{F16}")
    Write-Verbose "Sending keys F16"

    for ($sleep = 1; $sleep -le 60; $sleep++) {
        if ($host.UI.RawUI.KeyAvailable -and ($host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho").VirtualKeyCode -eq 27)) {
            Write-Host "`nExit!" -ForegroundColor Red
            exit
        }

        foreach ($c in '|/-\') {
            $host.UI.RawUI.CursorPosition = $oldPos
            Write-Host $c -NoNewline -ForegroundColor White
            Start-Sleep -Milliseconds 250
        }
    }
}

Write-Host "`nLocking workstation..." -ForegroundColor Yellow
rundll32.exe user32.dll,LockWorkStation
