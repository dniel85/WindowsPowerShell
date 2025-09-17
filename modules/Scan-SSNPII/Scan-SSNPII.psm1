<#
.Synopsis
   Scan for PII on fileshares
.DESCRIPTION
   Scanns for PII SSN inside .docx word documents.

.EXAMPLE
   Perform a scan of Microsoft word files containg SSN PII
   PS C:\> Scan-SSNPII -uncPath <string> 
.EXAMPLE
   Perform a can of Microsoft word files containing SSN PII and output results to CSV
   PS C:\> Scan-SSNPII -uncPath <string> -ExportResultsToCSV
.INPUTS
   None
.OUTPUTS
   None
.NOTES
   
    Author: Darrell Nielsen, Landon Sims 
    Version: 1.0 
    Last Updated 6/13/2024

.FUNCTIONALITY
   This cmdlet is for IA administrators to determine if there are word documents on a fileshare that contain PII data.  It provies an output of 
   creation Date, last access date, file path of the document and the owner of the document. 
#>


$ErrorActionPreference:Continue
function Scan-SSNPII{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$uncPath,
        [parameter()]
        [switch]$ExportResultsToCSV
    )

    <#
    $iniPath = "$PSScriptRoot\pii_script.ini"
    write-verbose "$iniPath"
    $patterns = @(Get-Content $iniPath)
#>
if(test-path "$PSScriptRoot\pii_script.ini"){ 
    $IniFilePath = "$PSScriptRoot\pii_script.ini"
    }
    else { $IniFilePath = "C:\Users\darrell.nielsen\Documents\WindowsPowerShell\modules\Scan-SSNPII\pii_script.ini"}
    # Read and parse patterns from the INI file

    $iniContent = Get-Content -Path $iniFilePath -Raw
    $iniConfig = @{}
    $section = ""

    $iniContent -split '\r?\n' | ForEach-Object {
        if ($_ -match '^\[(.*?)\]$') {
            $section = $matches[1]
            $iniConfig[$section] = @{}
        } elseif ($_ -match '^(.*?)\s*=\s*(.*?)$') {
            $key = $matches[1]
            $value = $matches[2]
            $iniConfig[$section][$key] = $value
        }
    }


    $iniContent = Get-IniContent -filePath $IniFilePath

    # Step 2: Define regex patterns from the INI file
    $regexPatterns = $iniContent['SSNs'] 

   $global:wordResults = Scan-Directory -directory $uncPath -patterns $patterns
    $global:csvResults = Search-PIInCSV -directory $uncPath -patterns $patterns

    $excelFiles = Get-ChildItem -Path $excelDirectory -Filter *.xlsx -Recurse

    $scanResults = @()
    
    foreach ($file in $excelFiles) {
        $scanResults += Scan-ExcelForSSN -excelFilePath $file.FullName -patterns $regexPatterns | select -Unique
    }
    
    #$global:XLSXResults = search-PIInXLSX -directory $uncPath -patterns $patterns

    

    $results = $wordResults+$csvResults+$scanresults

   
    #creating table
    if($results.FilePath -ne $null){
        Write-Verbose "Creating Table"
        Write-Host "`n Files below contain SSN PII" -ForegroundColor cyan -BackgroundColor Black
        foreach ($result in $results) {
            $docOwner = Get-Acl -Path $results.FilePath | Select-Object -ExpandProperty Owner
            $lastAccesstime = Get-Item -Path $results.FilePath | Select-Object -ExpandProperty lastAccessTime 
            $creationDate = get-item -path $results.FilePath | Select-Object -ExpandProperty creationtime
        }
        $path = @($results.FilePath)
        $Owner = @($docOwner)

        $tableRows = @()

        for ($i = 0; $i -lt $path.Count; $i++){
            $row = @{
                "FilePath" = $Path[$i]
                "Owner" = $Owner[$i]
                "lastAccessTime" = $lastAccesstime[$i]
                "CreationDate" = $creationDate[$i]
            }
            $tableRows += New-Object PSObject -Property $row
        }

        if($ExportResultsToCSV){
            $currentTime = Get-Date
            $formattedDate = $currentTime.ToString("yyyy-MM-dd_HHmmss") 
            Write-host "`nExported PII Results are located in $env:userprofile\PII_output$formatteddate.csv" -ForegroundColor Yellow
            $tableRows | export-csv -Path $env:userprofile\PII_output$formatteddate.csv
        }

        return $tableRows | Format-Table   
    }
    else{ Write-Host "`nSSN related PII was not found in $uncpath or any of its sub directories`n" -ForegroundColor Yellow 
    }
}
function Get-IniContent {
    param (
        [string]$filePath
    )

    $ini = @{}
    switch -regex -file $filePath {
        "^\[(.+)\]$" {
            $section = $matches[1].Trim()
            $ini[$section] = @{}
            $currentSection = $section
        }
        "^(.+?)\s*=\s*(.*)" {
            if ($currentSection) {
                $name = $matches[1].Trim()
                $value = $matches[2].Trim()
                $ini[$currentSection][$name] = $value
            }
        }
    }
    return $ini
}
function Scan-ExcelForSSN {
    param (
        [string]$excelFilePath,
        [hashtable]$patterns
    )

    $excel = New-Object -ComObject Excel.Application
    $workbook = $excel.Workbooks.Open($excelFilePath)
    $excel.Visible = $false

    $results = @()

    foreach ($sheet in $workbook.Sheets) {
        $range = $sheet.UsedRange
        foreach ($row in $range.Rows) {
            foreach ($patternKey in $patterns.Keys) {
                $pattern = $patterns[$patternKey]
                foreach ($cell in $row.Cells) {
                    $text = $cell.Text
                    if ($text -match $pattern) {
                        $results += [PSCustomObject]@{
                            'FilePath' = $excelFilePath
                            #'Sheet' = $sheet.Name
                            #'Cell' = "$($cell.Address())"
                            #'MatchedPattern' = $patternKey
                            #'SSN' = $matches[0]
                        }
                    }
                }
            }
        }
    }

    $workbook.Close()
    $excel.Quit()

    return $results
}
$results
# Step 4: Scan each Excel file in a directory
$excelDirectory = "N:\automation\TestDocx"

$excelFiles = Get-ChildItem -Path $excelDirectory -Filter *.xlsx -Recurse

$scanResults = @()

foreach ($file in $excelFiles) {
    $scanResults += Scan-ExcelForSSN -excelFilePath $file.FullName -patterns $regexPatterns | select -Unique
}

# Step 5: Output results into a table
$scanResults 





function Search-PIInCSV{
    param (
        [string]$directory,
        [array]$patterns
    )

    $csvfiles = Get-ChildItem -Path $directory -Filter *.csv -Recurse 

    foreach ($csvfile in $csvFiles) {
        $content = Get-Content -Path $csvfile.FullName -Raw
        foreach ($section in $iniConfig.Keys) {
            foreach ($patternKey in $iniConfig[$section].Keys) {
                $pattern = $iniConfig[$section][$patternKey]
                $matches = [regex]::Matches($content, $pattern)
                    
                    if ($matches.Count -gt 0) {
                        [PSCustomObject]@{
                            FilePath = $csvfile.FullName 
                    }     
                }
            }
        }
    }

}

function Search-PIIInDocx {
    param (
        [string]$docxFilePath
       # [string]$patternsIniPath
    )
    $patternsIniPath = "$PSScriptRoot\pii_script.ini"
    $foundPII = @{}
    
    try {
        $tempDir = Join-Path -Path $env:TEMP -ChildPath ([System.IO.Path]::GetRandomFileName())
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($docxFilePath, $tempDir)
        $documentXmlPath = Join-Path $tempDir "word\document.xml"
        
        if (Test-Path $documentXmlPath) {
            $documentXml = Get-Content -Path $documentXmlPath -Raw
            
            # Read patterns from INI file
            $patterns = @{}
            $iniContents = Get-Content -Path $patternsIniPath
            $currentSection = ""
            
            foreach ($line in $iniContents) {
                $line = $line.Trim()
                
                if ($line -match '^\[(.+)\]$') {
                    $currentSection = $Matches[1]
                }
                elseif ($line -match '^(.+?)\s*=\s*(.*)$') {
                    $key = $Matches[1].Trim()
                    $value = $Matches[2].Trim()
                    
                    if (-not [string]::IsNullOrWhiteSpace($currentSection) -and -not [string]::IsNullOrWhiteSpace($key)) {
                        $patterns["$currentSection.$key"] = $value
                    }
                }
            }
            
            foreach ($patternKey in $patterns.Keys) {
                $pattern = $patterns[$patternKey]
                $RegMatches = [regex]::Matches($documentXml, $pattern)
                if ($RegMatches.Count -gt 0) {
                    $foundPII[$patternKey] = $RegMatches.Count
                }
            }
        }
        
        Write-Verbose "Starting function Search-PIIInDocx"    
    } 
    catch [System.IO.InvalidDataException] {
        Write-Host "[INFO] Document $docxFilePath is a protected, encrypted document and cannot be scanned." -ForegroundColor Yellow
    }
    catch {
        Write-Error $_.Exception.Message
    }
    finally {
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force
        }
    }

    return $foundPII
}

function Scan-Directory {
    param (
        [string]$directory,
        [array]$patterns
    )
    Try{
        Get-ChildItem -Path $directory -Filter *.docx -Recurse | ForEach-Object {
                    $filePath = $_.FullName
            $result = Search-PIIInDocx -docxFilePath $filePath #-patterns $patterns
            if ($result.Count -gt 0) {
                [PSCustomObject]@{
                    FilePath = $filePath
                    PII = $result
                }
            }
        }
    }
    catch{$_ }
}    