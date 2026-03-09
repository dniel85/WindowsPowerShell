<#
.SYNOPSIS
Scans Word (.docx) documents for potential SSN personally identifiable information (PII).

.DESCRIPTION
Scan-SSNPII recursively scans a directory (including UNC paths) for Microsoft Word
documents (*.docx) and searches the document contents for patterns that resemble
Social Security Numbers (SSN).

The function extracts the internal XML structure of each .docx file and scans
the document.xml content using regular expressions.

When matches are found, the function returns information about the file including:

- File path
- File owner
- Last access time

This function is useful for identifying potential PII exposure within document
repositories, network shares, or compliance audit environments.

.PARAMETER uncPath
Specifies the directory or UNC path to scan for .docx files.

The function will recursively search the specified location for Word documents
and analyze their contents for SSN patterns.

.EXAMPLE
Scan-SSNPII -uncPath "N:\Automation\TestDocx"

Scans the specified directory for Word documents containing SSN patterns.

.EXAMPLE
Scan-SSNPII -uncPath "\\fileserver\shared\documents"

Scans a network share for Word documents containing possible SSN PII.

.EXAMPLE
Scan-SSNPII -uncPath "C:\Users\Public\Documents"

Scans a local directory for Word documents containing SSN data.

.INPUTS
System.String

Accepts a directory path or UNC path.

.OUTPUTS
PSCustomObject

Returns objects containing:

FilePath
Owner
LastAccessTime

.NOTES
Author: Darrell Nielsen

Purpose:
Identify potential Social Security Number (SSN) exposure in Word documents
during security audits, compliance checks, or data classification efforts.

Method:
The function extracts .docx files (which are ZIP archives) and scans the
document.xml file using regular expressions to identify SSN patterns.

Patterns Detected:
- ###-##-####
- SSN ###-##-####
- SSN #########

Requirements:
- Read access to the target directory
- .NET System.IO.Compression support (built into PowerShell)

Tags:
PII
SSN
SecurityAudit
DataLossPrevention
Compliance
PowerShell
InformationSecurity
FileScanning
Audit

.LINK
about_Regular_Expressions
https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_regular_expressions

.LINK
System.IO.Compression.ZipFile
https://learn.microsoft.com/dotnet/api/system.io.compression.zipfile

#>
function Search-SSNPII{
    [CmdletBinding()]
    param (
        [Parameter()]
        [TypeName]
        $uncPath
    )
    #$uncPath = "N:\Automation\TestDocx" 
    function Search-PIIInDocx {
        param (
            [string]$docxFilePath,
            [array]$patterns
        )
        $foundPII = @{}
        try {
            $tempDir = Join-Path -Path $env:TEMP -ChildPath ([System.IO.Path]::GetRandomFileName())
            New-Item -ItemType Directory -Path $tempDir | Out-Null
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($docxFilePath, $tempDir)
            $documentXmlPath = Join-Path $tempDir "word\document.xml"
            if (Test-Path $documentXmlPath) {
                $documentXml = Get-Content -Path $documentXmlPath -Raw
                foreach ($pattern in $patterns) {
                    $RegMatches = [regex]::RegMatches($documentXml, $pattern)
                    if ($RegMatches.Count -gt 0) {
                        $foundPII[$pattern] = $RegMatches.Count
                    }
                }
            }
            Remove-Item -Path $tempDir -Recurse -Force
        } catch {
            Write-Error "Error processing $docxFilePath $_"
        }
        return $foundPII
    }
    function Search-Directory {
        param (
            [string]$directory,
            [array]$patterns
        )
        Get-ChildItem -Path $directory -Filter *.docx -Recurse | ForEach-Object {
            $filePath = $_.FullName
            $result = Search-PIIInDocx -docxFilePath $filePath -patterns $patterns
            if ($result.Count -gt 0) {
                [PSCustomObject]@{
                    FilePath = $filePath
                    PII = $result
                }
            }
        }
    }
    $patterns = @(
        "\b\d{3}-\d{2}-\d{4}\b","SSN \d{3}-\d{2}-\d{4}\b","SSN \d{9}"     #<---- SSN REGEX pattern
        )
    $results = Search-Directory -directory $uncPath -patterns $patterns
    Write-Host "`n Files below contain SSN PII" -ForegroundColor Yellow -BackgroundColor Black
    foreach ($result in $results) {
        $docOwner = Get-Acl -Path $results.FilePath | Select-Object -ExpandProperty Owner
        $lastAccesstime = Get-Item -Path $results.FilePath | Select-Object -ExpandProperty lastAccessTime 
    }
    $path = @($results.FilePath)
    $Owner = @($docOwner)
    $tableRows = @()

    for ($i = 0; $i -lt $path.Count; $i++){
        $row = @{
            "FilePath" = $Path[$i]
            "Owner" = $Owner[$i]
            "lastAccessTime" = $lastAccesstime[$i]
        }
        $tableRows += New-Object PSObject -Property $row
    }
    return $tableRows | Format-Table
}