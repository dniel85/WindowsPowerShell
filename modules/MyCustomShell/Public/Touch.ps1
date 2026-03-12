 function touch {
<#
.SYNOPSIS
    Creates a file like linux

.DESCRIPTION
    Creates a file 

.PARAMETER Path
    Mandatory:: Sepcifies the path and extension of the file 

.EXAMPLE
    touch -Path .\example.txt

.NOTES
    Author: Darrell Nielsen
    Created: 2026-03-12
    Version: 1.0

TAGS:
    create file
#>
        [cmdletbinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path
            )

    if (Test-Path $Path) {
        # Update timestamp
        (Get-Item $Path).LastWriteTime = Get-Date
    }
    else {
        # Create file
        New-Item -ItemType File -Path $Path | Out-Null
    }
}