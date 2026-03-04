$servers = Get-Content @('C:\Users\chayce.ward.adm\Documents\Allservers.txt')
foreach ($server in $servers) {
    Invoke-Command -ComputerName $server -ScriptBlock {gpupdate}

}