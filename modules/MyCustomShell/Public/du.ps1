function du {
<#
.SYNOPSIS
Linux-style disk usage viewer (fast).

.DESCRIPTION
Shows the size of each immediate child directory under -Path (like "du --max-depth=1"),
sorted by size descending. Handles access denied and shows it in yellow.

.EXAMPLE
du
du C:\Temp
#>
    [CmdletBinding()]
    param(
        [string]$Path = ".",
        [int]$Decimals = 2,
        [switch]$ShowLessThan # if set: show "<0.01" instead of "0.00" for tiny folders
    )

    $root = (Resolve-Path -LiteralPath $Path).Path

    # Use a List to avoid slow += array growth
    $results = [System.Collections.Generic.List[object]]::new()

    $dirs = Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue

    foreach ($d in $dirs) {
        $currentDir = $d.FullName
        $sumBytes = 0L
        $denied = $false

        try {
            # Fast enumeration of file paths (not FileInfo objects)
            foreach ($file in [System.IO.Directory]::EnumerateFiles($currentDir, '*', [System.IO.SearchOption]::AllDirectories)) {
                try {
                    # Get length; individual files can fail (locked, perms)
                    $sumBytes += (Get-Item -LiteralPath $file -Force -ErrorAction Stop).Length
                }
                catch [System.UnauthorizedAccessException] {
                    # If we hit access denied anywhere, mark the directory as denied
                    $denied = $true
                    break
                }
                catch {
                    # Skip weird one-off errors (broken links, transient issues)
                    continue
                }
            }
        }
        catch [System.UnauthorizedAccessException] {
            $denied = $true
        }
        catch {
            # Treat unexpected enumeration failures as denied for clarity
            $denied = $true
        }

        if ($denied) {
            $results.Add([pscustomobject]@{
                Directory      = $currentDir
                Bytes          = $null
                DisplaySizeGB  = "Insufficient Permissions"
                IsAccessDenied = $true
            })
        }
        else {
            $gbRaw = $sumBytes / 1GB
            $gbRounded = [math]::Round($gbRaw, $Decimals)

            $display =
                if ($ShowLessThan -and $sumBytes -gt 0 -and $gbRounded -eq 0) {
                    "<{0:N$Decimals}" -f (1 / [math]::Pow(10, $Decimals))  # e.g. <0.01
                }
                else {
                    "{0:N$Decimals}" -f $gbRounded
                }

            $results.Add([pscustomobject]@{
                Directory      = $currentDir
                Bytes          = $sumBytes
                DisplaySizeGB  = $display
                IsAccessDenied = $false
            })
        }
    }

    # Sort by bytes, keep denied at bottom
    $results = $results | Sort-Object @{
        Expression = { if ($_.IsAccessDenied) { -1 } else { $_.Bytes } }
        Descending = $true
    }

    # Header
    "{0,-70} {1,12}" -f "Directory","SizeGB"
    "{0,-70} {1,12}" -f "---------","------"

    foreach ($r in $results) {
        if ($r.IsAccessDenied) {
            Write-Host ("{0,-70} {1,12}" -f $r.Directory, $r.DisplaySizeGB) -ForegroundColor Yellow
        }
        else {
            # Color tiers (optional but useful)
            $color =
                if ($r.Bytes -ge 50GB) { "Red" }
                elseif ($r.Bytes -ge 10GB) { "Magenta" }
                elseif ($r.Bytes -ge 1GB)  { "Cyan" }
                else { $null }

            if ($color) {
                Write-Host ("{0,-70} {1,12}" -f $r.Directory, $r.DisplaySizeGB) -ForegroundColor $color
            } else {
                Write-Host ("{0,-70} {1,12}" -f $r.Directory, $r.DisplaySizeGB)
            }
        }
    }
}