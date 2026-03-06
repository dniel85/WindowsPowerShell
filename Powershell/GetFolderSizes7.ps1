<#
.SYNOPSIS
    Displays the largest directories under a specified path using parallel processing (PowerShell 7+ only).

.DESCRIPTION
    Recursively scans subdirectories in parallel, calculates total sizes,
    and outputs the top N directories in human-readable format.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [int]$Top = 10,

    [int]$Depth = -1  # -1 = full recursion
)

# --- REQUIRE POWERSHELL 7+ ---
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "❌ This script must be run in PowerShell 7 or higher. Current version: $($PSVersionTable.PSVersion)"
}

if (-not (Test-Path $Path)) {
    throw "❌ The path '$Path' does not exist."
}

Write-Host "`n🚀 Scanning directories under: $Path (parallel mode)...`n" -ForegroundColor Cyan

# Collect all directories
if ($Depth -ge 0) {
    $directories = Get-ChildItem -Path $Path -Directory -Recurse -Depth $Depth -ErrorAction SilentlyContinue
} else {
    $directories = Get-ChildItem -Path $Path -Directory -Recurse -ErrorAction SilentlyContinue
}

# Process directories in parallel
$results = $directories | ForEach-Object -Parallel {
    $folder = $_.FullName
    $size = (Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue |
             Measure-Object -Property Length -Sum).Sum

    [PSCustomObject]@{
        Directory = $folder
        SizeBytes = [int64]$size
        SizeHR = if ($size -ge 1GB) {
            "{0:N2} GB" -f ($size / 1GB)
        } elseif ($size -ge 1MB) {
            "{0:N2} MB" -f ($size / 1MB)
        } elseif ($size -ge 1KB) {
            "{0:N2} KB" -f ($size / 1KB)
        } else {
            "$size B"
        }
    }
} -ThrottleLimit 8

# Sort and show top results
$largest = $results | Sort-Object SizeBytes -Descending | Select-Object -First $Top

Write-Host "`n🏆 Top $Top Largest Directories:`n" -ForegroundColor Yellow
$largest | Format-Table Directory, SizeHR -AutoSize
