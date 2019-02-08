
$Path = "$Env:userprofile\AppData\Local\Google\Chrome\User Data\Default\History"
if (-not (Test-Path -Path $Path)) {

    Write-Verbose "[!] Could not find Chrome History for username: $UserName"

}

$Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'

$Value = Get-Content -Path "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"|Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort-Object -Unique

$Value | ForEach-Object {

    $Key = $_

    if ($Key -match $Search){

        New-Object -TypeName PSObject -Property @{

            User = $UserName

            Browser = 'Chrome'

            DataType = 'History'

            Data = $_

        }

    }

}


<#

Firefox

if (-not (Test-Path -Path $Path)) {

    Write-Verbose "[!] Could not find FireFox History for username: $UserName"

}

else {

    $Profiles = Get-ChildItem -Path "$Path\*.default\" -ErrorAction SilentlyContinue

    $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'

    $Value = Get-Content $Profiles\places.sqlite | Select-String -Pattern $Regex -AllMatches |Select-Object -ExpandProperty Matches |Sort -Unique

    $Value.Value |ForEach-Object {

        if ($_ -match $Search) {

            ForEach-Object {

            New-Object -TypeName PSObject -Property @{

                User = $UserName

                Browser = 'Firefox'

                DataType = 'History'

                Data = $_

                }    

            }

        }

    }

}

#>