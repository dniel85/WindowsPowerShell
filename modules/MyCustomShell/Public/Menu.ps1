function Menu {
<#
.SYNOPSIS
Displays commands, variables, and environment info for MyCustomShell.
#>
Set-Alias -Name Menu -Value Man -Force
    $module = $MyInvocation.MyCommand.Module

    if (-not $module) {
        Write-Host "Module context not found." -ForegroundColor Red
        return
    }

    # ===============================
    # Domain Detection
    # ===============================
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        $domainName = if ($cs.PartOfDomain) { $cs.Domain } else { "Not Domain Joined" }
    }
    catch {
        $domainName = "Unknown"
    }

    Write-Host ""
    Write-Host "$($module.Name) Environment" -ForegroundColor Cyan
    Write-Host "Domain : $domainName" -ForegroundColor DarkYellow
    Write-Host ""

    # ===============================
    # Commands Section
    # ===============================
    Write-Host "Commands" -ForegroundColor Cyan
    ""

    $cmdWidth  = 22
    $synWidth  = 32
    $consoleWidth = $Host.UI.RawUI.WindowSize.Width
    $descWidth = $consoleWidth - ($cmdWidth + $synWidth + 4)

    "{0,-$cmdWidth} {1,-$synWidth} {2}" -f "Command","Synopsis","Description"
    "{0,-$cmdWidth} {1,-$synWidth} {2}" -f "-------","--------","-----------"

    $commands = $module.ExportedCommands.Values |
                Where-Object { $_.Name -notin @('prompt','Menu','Complete-ADBackgroundLoad','Start-ADBackgroundLoad','Stay-Awake') } |
                Sort-Object Name

    function Wrap-Text($text,$width) {
        $words = $text -split "\s+"
        $line  = ""
        $out   = @()

        foreach ($w in $words) {
            if (($line.Length + $w.Length + 1) -gt $width) {
                $out += $line.Trim()
                $line = "$w "
            }
            else {
                $line += "$w "
            }
        }

        if ($line.Trim()) { $out += $line.Trim() }

        return $out
    }

    foreach ($cmd in $commands) {

        $help = Get-Help $cmd.Name -ErrorAction SilentlyContinue

        $synopsis = if ($help.Synopsis) { $help.Synopsis.Trim() } else { "" }

        $description = if ($help.Description) {
            ($help.Description.Text -join " ").Trim()
        } else { "" }

        $wrapped = Wrap-Text $description $descWidth
        $first = $true

        foreach ($line in $wrapped) {

            if ($first) {
                Write-Host ("{0,-$cmdWidth} {1,-$synWidth} {2}" -f $cmd.Name,$synopsis,$line) -ForegroundColor Green
                $first = $false
            }
            else {
                Write-Host ("{0,-$cmdWidth} {1,-$synWidth} {2}" -f "","",$line) -ForegroundColor Green
            }
        }

        Write-Host ""
    }

    # ===============================
    # Variables Section
    # ===============================
    Write-Host ""
    Write-Host "Preloaded Variables" -ForegroundColor Cyan
    ""

    "{0,-20} {1}" -f "Variable","Info"
    "{0,-20} {1}" -f "--------","----"

    $vars = $module.ExportedVariables.Keys | Sort-Object

    foreach ($name in $vars) {

        $value = Get-Variable -Name $name -ValueOnly -ErrorAction SilentlyContinue

        switch ($name) {

            "WinServers" {
                if ($WinServers.Count -eq 0) {
                    Write-Host ("{0,-20} {1}" -f "`$$name","Not Loaded") -ForegroundColor Red
                }
                else {
                    Write-Host ("{0,-20} {1}" -f "`$$name","$($WinServers.Count) Servers") -ForegroundColor DarkCyan
                }
            }

            "WinComputers" {
                if ($Wincomputers.Count -eq 0) {
                    Write-Host ("{0,-20} {1}" -f "`$$name","Not Loaded") -ForegroundColor Red
                }
                else {
                    Write-Host ("{0,-20} {1}" -f "`$$name","$($WinComputers.Count) Computers") -ForegroundColor DarkCyan
                }
            }

            "LinuxServers" {
                if ($LinuxServers.Count -eq 0) {
                    Write-Host ("{0,-20} {1}" -f "`$$name","Not Loaded") -ForegroundColor Red
                }
                else {
                    Write-Host ("{0,-20} {1}" -f "`$$name","$($LinuxServers.Count) Servers") -ForegroundColor DarkCyan
                }
            }

            "Users" {
                if ($Users.Count -eq 0) {
                    Write-Host ("{0,-20} {1}" -f "`$$name","Not Loaded") -ForegroundColor Red
                }
                else {
                    Write-Host ("{0,-20} {1}" -f "`$$name","$($Users.Count) Users") -ForegroundColor DarkCyan
                }
            }

            "Modules" {

                $paths = $Modules -split ';'
                $default = $paths[0] -replace [regex]::Escape($env:USERPROFILE),"~"
                $count = $paths.Count

                Write-Host ("{0,-20} {1} ($count total)" -f "`$$name",$default) -ForegroundColor DarkCyan
            }

            "Scripts" {

                $default = $Scripts[0] -replace [regex]::Escape($env:USERPROFILE),"~"
                $count = $Scripts.Count
                Write-Host ("{0,-20} {1} ($count total)" -f "`$$name",$default) -ForegroundColor DarkCyan
            }

            default {
                Write-Host ("{0,-20} {1}" -f "`$$name","") -ForegroundColor DarkCyan
            }
        }
    }

    Write-Host ""


}