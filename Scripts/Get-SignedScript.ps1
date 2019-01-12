param(
[Parameter(Mandatory=$True)]
[string]$file
)

$Cert=(dir cert:currentuser\my\ -CodeSigningCert)
[byte[]]$byte = Get-Content -Encoding byte -ReadCount 4 -TotalCount 4 -Path $File
if (!($byte[0] -eq 0xef -and $byte[1] -eq 0xbb -and $byte[2] -eq 0xbf)){
    $source= gci $file
    Get-Content $file | Out-File -Encoding utf8 -filepath $env:temp\temp.ps1 -Force
    Move-Item $env:temp\temp.ps1 $file -Force
    }

Set-AuthenticodeSignature $file $cert