[cmdletbinding()]
param(
    [parameter(mandatory = $true)]
    [int]$hours
    )
$hours = ($hours * 60)
$myShell = New-Object -ComObject "wscript.shell"
clear
$oldPos = $host.UI.RawUI.CursorPosition

for ($i = 0; $i -lt $hours; $i++){
    $timeConvert = [timespan]::FromMinutes($i)
    Write-Host -NoNewline " <ESC> or [ctrl]+C" -ForegroundColor Red
    Write-Host -NoNewline " to quit! Elapsed time: " -ForegroundColor Cyan
    Write-Host ("{0:hh\:mm}" -f $timeConvert) -ForegroundColor Green -NoNewline
    Write-Host -NoNewline " workstation will automatically lock after"($hours/60)"hour(s)." -ForegroundColor Cyan
    $host.ui.rawui.CursorPosition = $oldPos
    $myshell.sendkeys("{F16}")

    for ($sleep = 1; $sleep -le 60; $sleep++){
        if($host.ui.RawUI.KeyAvailable -and ($host.ui.RawUI.ReadKey("IncludeKeyUp,NoEcho").virtualKeyCode -eq 27)){
        Write-Host
        Write-Host "Exit!" -ForegroundColor Red
        exit
        }
    for($count = 1; $count -le 2; $count++){
        $host.UI.RawUI.CursorPosition = $oldPos
        Write-Host "|" -NoNewline -ForegroundColor White
        Start-Sleep -Milliseconds 115
        $host.UI.RawUI.CursorPosition = $oldPos
        Write-Host "/" -NoNewline -ForegroundColor White
        Start-Sleep -Milliseconds 115
        $host.UI.RawUI.CursorPosition = $oldPos
        Write-Host "-" -NoNewline -ForegroundColor White
        Start-Sleep -Milliseconds 115
        $host.UI.RawUI.CursorPosition = $oldPos
        Write-Host "\" -NoNewline -ForegroundColor White
        Start-Sleep -Milliseconds 115
        }
    }
}
rundll32.exe user32.dll,LockWorkStation