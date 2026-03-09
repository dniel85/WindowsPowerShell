<#
.SYNOPSIS
    Removes Internet Explorer

.DESCRIPTION
    This script scans a list of servers and checks if Internet Explorer is installed. 
    If it is found, the script will remove Internet Explorer using DISM and then restart the server.

.PARAMETER None
    This script does not accept parameters.
    

.EXAMPLE 
    .\Remove-IE.ps1

    Reads servers from:
    C:\STiG_Findings\ops\OPSRV.txt

    Checks for Internet Explorer on each server, removes it if found, and restarts the server.

.NOTES
    Author: Darrell Nielsen
    Created: 2026-03-09
    Version: 1.0

TAGS:
    remove
    uninstall
    InternetExplorer
    
#>

[cmdletbinding()]
    param()

foreach($server in $WinServers){
    Write-Host "Processing server $server" -ForegroundColor Yellow
    
    try{
        if(Test-Connection -ComputerName $server -Count 1 -Quiet){
            Invoke-Command -ComputerName $server -ScriptBlock {
               
                
                $installedpackages = dism /online /get-packages | Out-String

                $packages = @()
                foreach($line in $installedpackages -split "`n"){
                    if($line -match "Package Identity\s*:\s*(.+)") {
                        $packages += [pscustomobject]@{
                            PackageIdentity = $Matches[1].trim()
                        }
                    }
                }
                $IE_Installed = $packages.packageIdentity | where {$_ -like "*InternetExplorer*"} | select -First 1 
                

                if($IE_Installed -ne $null){
                    Write-Host "Internet Explorer is installed on $env:computername. Removing..." -ForegroundColor Yellow
                    dism /online /remove-package /quiet /packagename:$IE_Installed
                    Restart-Computer -Force 
                    write-host "internet explorer has been removed from $env:computername." -ForegroundColor Green
                } else{
                    Write-Host "IE is not installed on $env:computername." -ForegroundColor Cyan
                }
            } 
        }else{
            Write-Host "Server $server is not reachable. Skipping..." -ForegroundColor Red
            }
        }catch{
            Write-Host "An error occourred while processing ${$_}" -ForegroundColor Red
        }
    }
Write-Host "script has completed for all servers" -ForegroundColor Green

             