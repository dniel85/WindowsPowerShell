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

$items = Get-ChildItem C:\Users\$loggedInUser\documents\WindowsPowerShell

$PS7_UserDir = "C:\Users\$($loggedInUser)\Documents\PowerShell"
$PS7_AdminDir = "$env:userprofile\Documents\PowerShell"
$Admin_userDir = "$env:userprofile\Documents\WindowsPowerShell"
$paths = @(
    $PS7_UserDir
    $PS7_AdminDir
    $Admin_userDir
)

foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        Write-Host "Creating $path" -ForegroundColor Yellow
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
    else {
        Write-Host "Exists: $path" -ForegroundColor DarkGreen
    }
}
Get-ChildItem @($PS7_UserDir,$PS7_AdminDir,$Admin_userDir) | Remove-Item -Recurse 
foreach($item in $items){
Write-Host $item
Write-Host $item.fullname 
    New-Item -ItemType SymbolicLink -Path @("c:\users\$loggedInUser\documents\powershell\$item",
                                            "c:\users\$loggedInUser.adm\documents\windowspowershell\$item",
                                            "c:\users\$loggedInUser.adm\documents\powershell\$item") -Target $item.FullName                                        
    }
Write-Host "Profiles configured." -ForegroundColor Green

$SnippitjsonFile = "C:\users\$loggedinuser\documents\windowspowershell\files\VSCodeSetup\powershell.json"
$destinations = @("C:\Users\$loggedInUser\appdata\roaming\code\user\snippets\powershell.json",
                  "$env:userprofile\appdata\roaming\code\user\snippets\VSCodeSetup\powershell.json")
                  foreach($dest in $destinations){
                        if(!(test-path $dest)){
                            $dir = Split-Path $dest
                            if(!(test-path $dir)){
                                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                            }
                            Copy-Item $SnippitjsonFile -Destination $dest
                        }
                        else{
                            Write-Host "Snippits file already Exists at: $dest" -ForegroundColor DarkGreen
                        }
                  }
Write-Host "`nInstallation complete." -ForegroundColor Cyan