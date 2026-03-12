function Search-Scripts {
<#
.SYNOPSIS
Searches PowerShell scripts.

.DESCRIPTION
The Search-Scripts function searches one or more directories recursively for
PowerShell scripts (*.ps1) containing a specified tag or keyword.

The function scans each script file for the provided tag and returns the
script name, description from comment-based help, and full path.

.PARAMETER Tag
Specifies the tag or keyword to search for inside PowerShell scripts.

.PARAMETER Path
Specifies one or more directory paths to search.

If not provided, the function defaults to:
- Logged-on user's Documents\WindowsPowerShell
- Logged-on user's Documents\PowerShell
- C:\Program Files\WindowsPowerShell
- C:\Program Files\PowerShell

.EXAMPLE
Search-Scripts edge

Searches the default script locations for the word "edge".

.EXAMPLE
Search-Scripts -Tag logging -Path C:\Scripts

Searches C:\Scripts recursively for scripts containing "logging".

.EXAMPLE
Search-Scripts defender | Select-Object -ExpandProperty FullPath

Returns only the full paths of matching scripts.

.OUTPUTS
PSCustomObject
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Tag,

        [string[]]$Path
    )

    if (-not $Path) {
        $loggedOnUser = ((Get-CimInstance Win32_ComputerSystem).UserName -split '\\')[-1]

        $Path = @(
            "C:\Users\$loggedOnUser\Documents\WindowsPowerShell",
            "C:\Users\$loggedOnUser\Documents\PowerShell",
            "C:\Program Files\WindowsPowerShell",
            "C:\Program Files\PowerShell"
        )
    }

    $validPaths = $Path | Where-Object { Test-Path $_ } | Select-Object -Unique

    if (-not $validPaths) {
        Write-Warning "No valid search paths found."
        return
    }

    $scripts = Get-ChildItem -Path $validPaths -Recurse -File -Filter *.ps1 -ErrorAction SilentlyContinue |
        Where-Object {
            Select-String -Path $_.FullName -Pattern $Tag -Quiet
        }

    if (-not $scripts) {
        Write-Host "No scripts found that match the tag: $Tag" -ForegroundColor DarkYellow
        return
    }

    foreach ($script in $scripts) {
        try {
            $help = Get-Help -Name $script.FullName -ErrorAction Stop
            $description = $help.Synopsis
        }
        catch {
            $description = "No help description available"
        }

        [PSCustomObject]@{
            Script      = $script.Name
            Description = $description
            FullPath    = $script.FullName
        }
    }
}