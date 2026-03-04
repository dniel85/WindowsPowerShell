<#
.Synopsis
   PowerShell module for reading INI files into a hashtable.
.DESCRIPTION
   Provides function Read-IniFile to parse INI files with multiple sections and keys.
.EXAMPLE
   $ini = Read-IniFile -Path path\to\ini\file\Servers.ini
   $ini.domaincontrollers
#>
function Read-IniFile{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
                    [string]$Path
    )
if(-not(test-path $path)){
        Throw "INI file not found: $path"
}

$ini = @{}
$currentSection = $null
get-content $Path | ForEach-Object {
        $line = $_.Trim()
        if($line -eq "" -or $line.StartsWith(";")) { return }

        if($line -match "^\[(.+)\]$") {
            $currentSection = $matches[1]
            if(-not $ini.ContainsKey($currentSection)){
                    $ini[$currentSection] = @()
            }
        }
        elseif ($line -match "^(.*?)=(.*)$" -and $currentSection) {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            $ini[$currentSection] += $value    
        }
    }
    return $ini
}
Export-ModuleMember -Function Read-IniFile
