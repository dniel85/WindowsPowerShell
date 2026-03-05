function search-scripts {
<#
.SYNOPSIS
Searches PowerShell scripts.

.DESCRIPTION
The Search-Scripts function searches a directory recursively for PowerShell
scripts (*.ps1) containing a specified tag or keyword.

The function scans each script file for the provided tag and returns the
script name along with the description extracted from the script's
comment-based help block.

.PARAMETER Tag
Specifies the tag or keyword to search for inside PowerShell scripts.

This parameter is mandatory.

.PARAMETER Path
Specifies the directory path to search for scripts.

If not provided, the default location is:
$env:USERPROFILE\Documents\WindowsPowerShell

.EXAMPLE
Search-Scripts edge

Searches the default PowerShell script directory for scripts containing
the word "edge" and displays the script name and description.

.EXAMPLE
Search-Scripts -Tag logging -Path C:\Scripts

Searches the C:\Scripts directory recursively for PowerShell scripts
containing the word "logging".

.OUTPUTS
PSCustomObject

Returns objects containing:
Script       - The script filename
Description  - The description extracted from the script help block

.NOTES
Author: Darrell Nielsen

This function is intended to help organize and search large PowerShell
script libraries using tags or keywords embedded in scripts.

#>
    [cmdletbinding()]
    param(
    [Parameter(Mandatory=$true,position=0)]
    [string]$tag,
    $path = "$env:userprofile\documents\windowspowershell"
    )

    $script = Get-ChildItem $path -Recurse -Filter *.ps1 | Where-Object {
        Select-String -Path $_.FullName -Pattern $tag -Quiet
    }
    if($script -eq $null){
        Write-Host "No scripts found that match the tag: $tag" -ForegroundColor Yellow
        }

    $script | ForEach-Object {
        $help = Get-Help $_.FullName
        [PSCustomObject]@{
            Script      = $_.Name
            Description = $help.Description.Text -join " "
            FullPath    = $_.FullName
        }
    }
}