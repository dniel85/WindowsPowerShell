$LogName = ($MyInvocation.MyCommand).Name.replace('.ps1','.log').ToString()
$logfile = "C:\ScheduledTasks\Logs\$LogName"
Start-Transcript -Path $logfile -Append

$GetLastWarningEvent = (Get-WinEvent -FilterHashtable @{
 LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin'
 ID     =  50281
 } -MaxEvents 1).timecreated

 $dateCheck = [datetime]::Now.AddDays(-2)

 if($GetLastWarningEvent -eq $null){exit}

 if($GetLastWarningEvent -ne $null -and $GetLastWarningEvent -gt $dateCheck){
    Write-Host 'Resetting RDS Gateway now'

    <# Run this script to reset the RDP gateway graice period
    It's reccomended you set this up as a scheduled task on the ADM server #>
    $NextReset = (get-date).AddDays(120).GetDateTimeFormats()[7]
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod"

    $acl = Get-Acl $RegPath
    $acl.SetOwner([System.Security.Principal.NTAccount]"Administrators")
    Set-Acl -Path $RegPath -AclObject $acl

    $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("Administrators","FullControl","Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path $RegPath -AclObject $acl

    Remove-ItemProperty -Path $RegPath -Name "L$RTMTIMEBOMB*" -Force -ErrorAction SilentlyContinue

    Write-Host "RDS grace period has been reset. Server will now reboot. The next time the RDS grace period will need to be reset is on $NextReset" 
    Stop-Transcript
    #write-host "computer restarts"
    restart-computer -Force 
    }

Write-Host 'RDS grace period does not need to be reset at this time'
Stop-Transcript