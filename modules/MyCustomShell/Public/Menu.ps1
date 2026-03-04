Complete-ADBackgroundLoad

function Menu {
<#
.SYNOPSIS
Displays commands, variables, and environment info for MyCustomShell.
#>
    # Detect module automatically
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
    Write-Host "Commands:" -ForegroundColor Cyan
    ""

    "{0,-25} {1}" -f "Command","Synopsis"
    "{0,-25} {1}" -f "-------","--------"

    $commands = $module.ExportedCommands.Values |
                Where-Object { $_.Name -notin @('prompt','Menu','Complete-ADBackgroundLoad','Start-ADBackgroundLoad') } |
                Sort-Object Name

    foreach ($cmd in $commands) {

        $help = Get-Help $cmd.Name -ErrorAction SilentlyContinue
        $synopsis = if ($help.Synopsis) { $help.Synopsis.Trim() } else { "No help available" }

        Write-Host ("{0,-25} {1}" -f $cmd.Name, $synopsis) -ForegroundColor Green
    }

    # ===============================
    # Variables Section
    # ===============================
    Write-Host ""
    Write-Host "Preloaded Variables:" -ForegroundColor Cyan
    ""

    "{0,-20} {1}" -f "Variable","Info"
    "{0,-20} {1}" -f "--------","----"

    $vars = $module.ExportedVariables.Keys | Sort-Object

    foreach ($name in $vars) {

        $value = Get-Variable -Name $name -ValueOnly -ErrorAction SilentlyContinue

        switch ($name) {

            "WinServers" {
                if ($WinServers.Count -eq 0) {
                    Write-Host ("{0,-20} {1}" -f "`$$name", "Not Loaded") -ForegroundColor Red
                }
                else {
                    Write-Host ("{0,-20} {1}" -f "`$$name", "$($WinServers.Count) Servers") -ForegroundColor DarkCyan
                }
            }

            "LinuxServers" {
                if ($LinuxServers.Count -eq 0) {
                    Write-Host ("{0,-20} {1}" -f "`$$name", "Not Loaded") -ForegroundColor Red
                }
                else {
                    Write-Host ("{0,-20} {1}" -f "`$$name", "$($LinuxServers.Count) Servers") -ForegroundColor DarkCyan
                }
            }

            "Users" {
                if ($Users.Count -eq 0) {
                    Write-Host ("{0,-20} {1}" -f "`$$name", "Not Loaded") -ForegroundColor Red
                }
                else {
                    Write-Host ("{0,-20} {1}" -f "`$$name", "$($Users.Count) Users") -ForegroundColor DarkCyan
                }
            }

            "Modules" {
                $count = ($Modules -split ';').Count
                Write-Host ("{0,-20} {1}" -f "`$$name", "$count Module Paths") -ForegroundColor DarkCyan
            }

            "Scripts" {
                $home = $env:USERPROFILE
                $shortPath = $Scripts -replace [regex]::Escape($home), "~"
                Write-Host ("{0,-20} {1}" -f "`$$name", $shortPath) -ForegroundColor DarkCyan
            }

            default {
                Write-Host ("{0,-20} {1}" -f "`$$name", "") -ForegroundColor DarkCyan
            }
        }
    }

    Write-Host ""
}