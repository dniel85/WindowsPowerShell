 <#
.SYNOPSIS
Automatically searches for passwords in plaintext

.DESCRIPTION
This script iterates through user directories looking for stored passwords in plain text that match a pattern


.OUTPUTS
None

Displays status messages indicating repository state and Git operations.

.NOTES
Author: Darrell Nielsen

TAGS:
passwords
secret


#>
 [cmdletbinding()]
 param(
        [string]$directory
        )
$pattern = @'
^(?=(?:.*[!@#$%^&*()_+={}\[\]:;"'<>,.?/\\|]){2})(?=(?:.*[A-Z]){2})(?=(?:.*\d){2}).{14,}$
'@

$txtFiles = Get-ChildItem -Path $directory -Filter "*.txt" -Recurse

foreach ($file in $txtFiles) {

    $content = Get-Content -Path $file.FullName -Raw
    
    $matches = [regex]::Matches($content, $pattern)

    if ($matches.Count -gt 0) {
        foreach ($match in $matches) {
             [pscustomobject]@{
                filepath = $($file.fullName)
                Value =  $($match.Value)
            }

        }
    }
   
}
