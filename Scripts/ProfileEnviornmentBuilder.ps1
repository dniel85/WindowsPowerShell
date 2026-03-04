if((get-windowsfeature RSAT-AD-PowerShell).installstate -ne "Installed"){
        Add-WindowsFeature RSAT-AD-PowerShell
}


$masterProfileLoader =@"
#Master Profile Loader

#function to check for admin rights
function Test-IsAdmin {
        `$currentUser = New-Object security.principal.windowsprincipal([Security.principal.windowsidentity]::GetCurrent())
        return `$currentUser.IsInRole([security.principal.windowsbuiltinrole]::Administrator)
}

`$adminProfile ="$HOME\documents\WindowsPowershell\Profile.admin.ps1"
`$UserProfile = "$Home\documents\WindowsPowerShell\Profile.user.ps1"

if(Test-IsAdmin) {
        if(Test-Path `$adminProfile) {
                . `$adminProfile
        }

    } else {
        if(Test-Path `$UserProfile) {
                . `$UserProfile
        }
    }
"@
$AdminProfile = @"
write-host @'

                 Preloaded Variables:
   **************************************************
   *     `$WinServers   =  List all Windows servers. *
   *     `$LinuxServers =  List all Linux servers.   *
   *     `$Users        =  All AD Users.             *
   *     `$modules      =  PSModulePath.             * 
   *     `$Scripts      =  PSScriptPath.             *
   *                                                *
   **************************************************

'@ -ForegroundColor Yellow
write-host @'
   **************************************************
   *         RUNNING AS ADMINISTRATOR               *
   **************************************************
'@ -ForegroundColor Red
function prompt {write-host "`$env:username " -ForegroundColor Cyan -nonewline
		write-host "ADMIN" -ForegroundColor Red -nonewline
		write-host " [`$pwd]" -Foregroundcolor Yellow -nonewline
		return " > "
		}
prompt
set-location -Path `$env:USERPROFILE
New-Variable -name WinServers -value  @(get-adcomputer -Filter {operatingsystem -like "*windows server*" -and Enabled -eq "True"}).name
New-Variable -name LinuxServers -value  @(get-adcomputer -Filter {operatingsystem -like "*Linux*" -and Enabled -eq "True"}).name
New-Variable -Name Users -Value @(get-aduser -Filter * |Select-Object name,samaccountname,enabled,distinguishedname)

New-variable -name Scripts -value "`$env:userprofile\documents\windowspowershell\scripts"
New-variable -name Modules -value "`$env:userprofile\documents\windowspowershell\modules"





"@
$userPro =@"
write-host @'

                 Preloaded Variables:
   **************************************************
   *     `$WinServers   =  List all Windows servers. *
   *     `$LinuxServers =  List all Linux servers.   *
   *     `$Users        =  All AD Users.             *
   *     `$modules      =  PSModulePath.             * 
   *     `$Scripts      =  PSScriptPath.             *
   *                                                *
   **************************************************

'@ -ForegroundColor Yellow

function prompt {write-host "`$env:username " -ForegroundColor Cyan -nonewline
		write-host " [`$pwd]" -Foregroundcolor Yellow -nonewline
		return " > "
		}
prompt
set-location -Path `$env:USERPROFILE
New-Variable -name WinServers -value  @(get-adcomputer -Filter {operatingsystem -like "*windows server*" -and Enabled -eq "True"}).name
New-Variable -name LinuxServers -value  @(get-adcomputer -Filter {operatingsystem -like "*Linux*" -and Enabled -eq "True"}).name
New-Variable -Name Users -Value @(get-aduser -Filter * |Select-Object name,samaccountname,enabled,distinguishedname)

New-variable -name Scripts -value "`$env:userprofile\documents\windowspowershell\scripts"
New-variable -name Modules -value "`$env:userprofile\documents\windowspowershell\modules"



"@

if(!(Test-Path $env:USERPROFILE\documents\windowspowershell)){mkdir $env:USERPROFILE\documents\WindowsPowerShell}
if(!(Test-Path $env:USERPROFILE\documents\windowspowershell\Modules)){mkdir $env:USERPROFILE\documents\WindowsPowerShell\Modules}
if(!(Test-Path $env:USERPROFILE\documents\windowspowershell\Scripts)){mkdir $env:USERPROFILE\documents\WindowsPowerShell\Scripts}
if(!(Test-Path $env:USERPROFILE\documents\windowspowershell\files)){mkdir $env:USERPROFILE\documents\WindowsPowerShell\Files}
$profileLoader1 = "$env:USERPROFILE\documents\windowspowershell\Microsoft.PowerShell_profile.ps1"
$profileLoader2 ="$env:USERPROFILE\documents\windowspowershell\profile.admin.ps1"
$profileLoader3 = "$env:USERPROFILE\documents\windowspowershell\profile.user.ps1"


New-Item -Path $profileLoader1 -ItemType File -Force -Value $masterProfileLoader
New-Item -Path $profileLoader2 -ItemType File -Force -Value $AdminProfile
New-Item -Path $profileLoader3 -ItemType File -Force -Value $UserPro

get-adComputer -Filter 'enabled -eq $true' | Select-Object Name -ExpandProperty name >> $env:userprofile\documents\windowspowershell\files\Computer_list.txt

powershell.exe