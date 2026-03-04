import-module ActiveDirectory
$winservers = (get-adcomputer -Filter {operatingsystem -like "*windows server*" -and Enabled -eq "True"}).name
$results = @()

foreach($server in $winservers){
    try{
        $output = invoke-command -ComputerName $server -ScriptBlock{

            $timezone = Get-WmiObject -Namespace "root\cimv2" -Class win32_timezone | select caption -ExpandProperty caption
            $HostName = $env:computername
            $w32tmoutput = w32tm /query /status
            #$exactTime = get-date -Format "HH:mm:ss:ms"

            $lastSyncTime = $null
            $timeSource = $null

            foreach($line in $w32tmoutput){
                if($line -match "Last Successful Sync Time\s*:\s*(.+)"){
                    $lastSyncTime = $Matches[1].Trim()
                }
                elseif ($line -match "Source\s*:\s*(.+)") {
                    $timeSource =$Matches[1].Trim() 
                }
            }

            return  [pscustomobject]@{
                Hostname = $HostName
                TimeZone = $timezone
                LastSyncTime = $lastSyncTime
                NTPServer = $timeSource
                #CurrentTime = $exactTime
        } | Select-Object hostname, timezone, lastsynctime, ntpserver #, CurrentTime
    }

    $results += $output
    }
    catch{
        $results += [pscustomobject]@{
            Hostname = $HostName
            TimeZone = "ERROR" 
            LastSyncTime = "ERROR"
            NTPServer = "ERROR"
            #CurrentTime = "ERROR"
        } | Select-Object hostname, timezone, lastsynctime, ntpserver #, CurrentTime
    }
}
$results | Format-Table -AutoSize 
