function du {
<#
.SYNOPSIS
Linux-style disk usage viewer.

.DESCRIPTION
Calculates directory sizes recursively and displays them sorted.

.EXAMPLE
du C:\Temp
#>
    param([string]$Path = ".")
    $results = @()
    Get-ChildItem -Directory -Force $Path -ErrorAction SilentlyContinue |
    ForEach-Object {
        $currentDir = $_.FullName
        try {
            $size = Get-ChildItem -Recurse -Force $currentDir -ErrorAction Stop |
                    Where-Object { -not $_.PSIsContainer } |
                    Measure-Object Length -Sum |
                    Select-Object -ExpandProperty Sum
            $results += [pscustomobject]@{
                Directory = $currentDir
                SizeGB    = [math]::Round($size / 1GB, 2)
                IsAccessDenied = $false
            }
        }
        catch [System.UnauthorizedAccessException] {
            $results += [pscustomobject]@{
                Directory = $currentDir
                SizeGB    = "     Insufficent Permissions"
                IsAccessDenied = $true
            }
        }
    }
    $results = $results | Sort-Object {
        if ($_.'SizeGB' -is [double]) { $_.'SizeGB' } else { -1 }
    } -Descending
    # Custom table output
    "{0,-70} {1,10}" -f "Directory","SizeGB"
    "{0,-70} {1,10}" -f "---------","------"
    foreach ($r in $results) {
        if ($r.IsAccessDenied) {
            Write-Host ("{0,-70} {1,10}" -f $r.Directory, $r.SizeGB) -ForegroundColor Yellow
        }
        else {
            Write-Host ("{0,-70} {1,10}" -f $r.Directory, $r.SizeGB)
        }
    }
}