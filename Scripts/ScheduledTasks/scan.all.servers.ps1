$scriptName = ($MyInvocation.MyCommand).Name.replace('.ps1','.log').ToString()
$logPath = "c:\ScheduledTasks\logs\$scriptName"

Start-Transcript -Path $logPath -Append 

$servers = Get-Content "D:\STIG Scan GNEXT\GNEXT_SERVERS.txt"

C:\ScheduledTasks\Scripts\Evaluate-STIG_1.2501.2\Evaluate-STIG\Evaluate-STIG.ps1 -ComputerName $servers -ScanType Classified -Output CKLB -OutputPath 'D:\STIG Scan GNEXT\'-Verbose 

Stop-Transcript 