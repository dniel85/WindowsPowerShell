
function Scan-SSNPII{
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
    function Scan-Directory {
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
    $results = Scan-Directory -directory $uncPath -patterns $patterns
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