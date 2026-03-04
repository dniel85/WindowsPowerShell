$logname = $MyInvocation.MyCommand.Name.Replace('.ps1','.log')
$logfile = "C:\ScheduledTasks\Logs\$logname"
Start-Transcript -Path $logfile -Append

$cutoff = [datetime]::Now.AddDays(-60)

$inactiveUsers = Get-ADUser -Filter * -Properties lastlogonDate | 
    Where-Object {
        $_.Enabled -eq $true -and
        $_.lastlogondate -ne $null -and
        $_.lastlogondate -lt$cutoff -and
        $_.samaccountname -notmatch 'svc' -and
        $_.samaccountname -notmatch 'adm' -and
        $_.samaccountname -notmatch 'failsafe'
        } | 
        Select-Object -ExpandProperty samaccountname
if($inactiveUsers){
    foreach($user in $inactiveUsers){
        Disable-ADAccount -Identity $user 
        Write-Host "$user last logon is greater than 60 days Account is now disabled"
        }
    } else{ Write-Host "No users were found that need to be disabled"
}
Stop-Transcript 
