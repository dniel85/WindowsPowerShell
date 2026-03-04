#New-Variable -name WinServers -value  @(get-adcomputer -Filter {operatingsystem -like "*windows server*" -and Enabled -eq "True"}).name



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

             