
param(
    [parameter(mandatory=$true)]
    [string]$SourceIP,

    [string]$LogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
)

$LoggingTrue = (Get-NetFirewallProfile -Profile Domain,Public,Private | select LogAllowed,LogBlocked)

if(-not(test-path $LogPath) -or (($LoggingTrue).logallowed) -and (($LoggingTrue).lgblocked) | ForEach-Object {$_ -eq "True"}){
    write-host "Firewall log not found at : $logpath" -ForegroundColor DarkYellow
    Write-Host "attempting to enable..." -ForegroundColor DarkYellow
    }

    try{
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767
    }
    catch{
        Write-Host "Failed to enable firewall logging:" -ForegroundColor Red
        exit 1
    }



write-host "Tailing firewall log for source IP $SourceIP" -ForegroundColor cyan
write-host "Log file: $LogPath" -ForegroundColor Yellow

get-content -path $LogPath -Wait -Tail 10 | 
    foreach-object {

        if($_ -match "\b$SourceIP\b"){
            
            if($_ -match "ALLOW"){
                write-host $_ -ForegroundColor Green
            }
            elseif($_ -match "DROP"){
                Write-Host $_ -ForegroundColor Red
            }
            else{
                Write-Host $_
            }
        }
    }
Register-EngineEvent Powershell.exiting -Action {
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed False -LogBlocked False -LogMaxSizeKilobytes 32767
    }
 