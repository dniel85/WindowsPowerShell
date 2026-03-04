$WinServers = @(get-adcomputer -Filter {operatingsystem -like "*windows server*" -and Enabled -eq "True"}).name


$serverSum = $WinServers.Length 

$quarter = [math]::round($serverSum/4)


$1_Batch = $WinServers[0..($quarter -1)]

$2_batch = $WinServers[([int]$quarter)..([int]$quarter*2 -1)]

$3_Batch = $WinServers[([int]$quarter*2)..([int]$quarter*3 - 1)]

$4_Batch = $WinServers[($quarter*3)..($serverSum)]


C:\USERS\darrell.nielsen.adm\documents\windowspowershell\Scripts\Evaluate-STIG_1.2404.1\Evaluate-STIG\Evaluate-STIG.ps1 -ComputerName $1_Batch -Output CKL -OutputPath c:\temp\EvaluateStigCKLs
C:\USERS\darrell.nielsen.adm\documents\windowspowershell\Scripts\Evaluate-STIG_1.2404.1\Evaluate-STIG\Evaluate-STIG.ps1 -ComputerName $2_Batch -Output CKL -OutputPath c:\temp\EvaluateStigCKLs
C:\USERS\darrell.nielsen.adm\documents\windowspowershell\Scripts\Evaluate-STIG_1.2404.1\Evaluate-STIG\Evaluate-STIG.ps1 -ComputerName $3_Batch -Output CKL -OutputPath c:\temp\EvaluateStigCKLs
C:\USERS\darrell.nielsen.adm\documents\windowspowershell\Scripts\Evaluate-STIG_1.2404.1\Evaluate-STIG\Evaluate-STIG.ps1 -ComputerName $4_Batch -Output CKL -OutputPath c:\temp\EvaluateStigCKLs

