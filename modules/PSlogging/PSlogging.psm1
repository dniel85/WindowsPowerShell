# Load Private files first
Get-ChildItem "$PSScriptRoot\Private\*.ps1" | ForEach-Object {
    . $_.FullName
}

# Load Public
Get-ChildItem "$PSScriptRoot\Public\*.ps1" | ForEach-Object {
    . $_.FullName
}

#Set alias
Set-Alias -name wl -Value Write-Log

# Export Public Functions
$PublicFunctions = Get-ChildItem "$PSScriptRoot\Public\*.ps1" |
                   ForEach-Object { $_.BaseName }

Export-ModuleMember -Function $PublicFunctions -Alias wl
