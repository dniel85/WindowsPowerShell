param(
    [string]$SourcePath = (Resolve-Path "$PSScriptRoot\..").Path,
    [switch]$AddToProfile
)



$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)


if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run as Administrator." -ForegroundColor Red
    return
}

$loggedInUser = (Get-Process explorer -IncludeUserName |
               Select-Object -First 1 -ExpandProperty UserName).Split('\')[1]


$items = gci C:\Users\darrell.nielsen\documents\WindowsPowerShell

$PS7_UserDir = "C:\Users\$($loggedInUser)\Documents\PowerShell"
$PS7_AdminDir = "$env:userprofile\Documents\PowerShell"
$Admin_userDir = "$env:userprofile\Documents\WindowsPowerShell"

gci @($PS7_UserDir,$PS7_AdminDir,$Admin_userDir) | Remove-Item -Recurse 

foreach($item in $items){
Write-Host $item
Write-Host $item.fullname 
    New-Item -ItemType SymbolicLink -Path @("c:\users\darrell.nielsen\documents\powershell\$item",
                                            "c:\users\darrell.nielsen.adm\documents\windowspowershell\$item",
                                            "c:\users\darrell.nielsen.adm\documents\powershell\$item") -Target $item.FullName                                        
    }


    Write-Host "Profiles configured." -ForegroundColor Green


Write-Host "`nInstallation complete." -ForegroundColor Cyan