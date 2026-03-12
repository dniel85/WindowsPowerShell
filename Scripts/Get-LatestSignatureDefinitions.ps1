$scriptName = ($MyInvocation.MyCommand).Name.replace('.ps1','.log').ToString()
Start-Transcript -Path C:\ScheduledTasks\Logs\$scriptName -append

$servers = (Get-ADComputer -Filter {operatingsystem -like "*windows Server*" -and Enabled -eq "True"}).name

$creds = import-clixml -path "C:\ScheduledTasks\Scripts\files\cr\atm_cr.xml"
New-PSDrive -Name x -PSProvider FileSystem -Root \\eglinfs\SoftwareUpdates\AVDefinitions\Definitions -Credential $creds | Out-Null

if((Get-Item -Path x:\wd_defs_for_all\x64\mpam-fe.exe).lastwritetime -gt (get-date).AddDays(-9)){
    Copy-Item -Path x:\wd_defs_for_all -Recurse -Destination \\gxe-wsus\defendersignatures -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 60
    
    foreach($server in $servers){Invoke-Command -ComputerName $server -ScriptBlock {
        Write-Output "Updating $env:ComputerName...." 
        Update-MpSignature -UpdateSource FileShares
        $latestUpdate = (Get-MpComputerStatus).AntispywareSignatureLastUpdated
        Write-Output " last updated on $latestUpdate" 
            }
    }
}
Remove-PSDrive x 
Stop-Transcript