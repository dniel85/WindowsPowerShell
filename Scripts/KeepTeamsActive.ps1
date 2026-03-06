<#
.SYNOPSIS
    Keep Teams Active

.DESCRIPTION
    Script sligtly moves cursor to keep teams status "Green"
    press Ctrl+C to stop the script

.EXAMPLE
    .\KeepTeamsActive.ps1

.NOTES
    Author: Darrell Nielsen
    Created: 2026-03-06
    Version: 1.0

TAGS:
    Teams
    active
#>
[cmdletbinding()]
param(   
)
Add-Type -AssemblyName System.Windows.Forms
$interval = 60
$moveDistance = 1
Write-Host "Keeping Teams active. Press Ctrl+C to stop." -ForegroundColor DarkYellow

while ($true) {
    $cursor = [System.Windows.Forms.Cursor]::Position
    write-verbose "moving cursor slightly"
    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(($cursor.X + $moveDistance), $cursor.Y)
    Start-Sleep -Milliseconds 500
    write-verbose "moving cursor back"
    [System.Windows.Forms.Cursor]::Position = $cursor
    Start-Sleep -Seconds $interval
}