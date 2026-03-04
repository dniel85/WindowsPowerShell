
$logPath = "c:\temp\SC_Scan.log"
Start-Transcript -Path $logPath -Append 

$servers = Get-Content "D:\STIG Scan GNEXT\GNEXT_SERVERS.txt"

C:\Users\darrell.nielsen.adm\Documents\WindowsPowerShell\Scripts\Evaluate-STIG_1.2501.2\Evaluate-STIG\Evaluate-STIG.ps1 -ComputerName $servers -ScanType Classified -Output CKLB -OutputPath 'D:\STIG Scan GNEXT\'


Stop-Transcript
#c:\windows\system32\windowspowershell\v1.0\powershell.exe -executionpolicy bypass -file "C:\users\darrell.nielsen.adm\documents\windowspowershell\scripts\scan.all.servers.ps1" -windowstyle hidden