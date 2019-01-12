#Auto-Download and install patches

$env:SEE_MASK_NOZONECHECKS = 1 
$InstalledPatches = Get-HotFix | select-object -ExpandProperty HotFixID
$PatchMonth = get-date -UFormat %Y-%m
$PatchDate = get-date -UFormat %m-%d
$rootDir = "C:\temp\WindowsUpdates\"
$updateRepo = $rootDir+$PatchMonth
$logDir = $updateRepo+'\Logs'
$officeUpdates = $updateRepo+'\OfficeUpdates'
$PatchLog = "$logdir\Patch_Install_Log.txt"

 "______________________________________________________________________" | Out-File -FilePath $PatchLog -Append
 "Windows updater script started at $(get-date -format 'u')" | Out-File -FilePath $PatchLog -Append

if(! (Test-Path $rootDir))                             {New-Item -ItemType directory -Path $rootDir}
if(! (Test-Path "C:\temp\WindowsUpdates\UpdateLogs"))  {New-Item -ItemType directory -Path "C:\temp\WindowsUpdates\UpdateLogs"}
if(! (Test-Path $updateRepo))                          {New-Item -ItemType directory -Path $updateRepo}
if(! (Test-Path $logDir))                              {New-Item -ItemType directory -Path $logDir}
if(! (Test-Path "$updateRepo\$patchDate"))             {New-Item -ItemType directory -Path "$updateRepo\$PatchDate"}

 


function Install-WindowsPatches{
    
    try{
       
        if((Get-WmiObject win32_operatingSystem).caption -eq 'Microsoft Windows 10 Pro')
            {$osVersion = 'Windows_10'}
            else{$osVersion = 'Windows_Server_16'}

                
        $oldMSUpdates = Get-ChildItem -Path "$updateRepo\$PatchDate\" -Filter *.msu -Recurse | 
                 Where-Object {$installedPatches -contains ($_.baseName -replace '^.*?(KB\d{7}).*$', '$1')} 
                 foreach($Update in $oldMSUpdates){Remove-Item $Update.FullName -Force -Recurse}

        #$Files = Get-ChildItem -Path \\10.10.1.23\Domain_Objects\WindowsUpdates\$osVersion\$PatchMonth\ -Filter *.msu -Recurse |
         #   Where-Object {$InstalledPatches -notcontains ( $_.BaseName -replace '^.*?\-(kb\d{7})\-.*$', '$1' )}

            $Files = Get-ChildItem -Path \\10.10.1.23\Domain_Objects\WindowsUpdates\$osVersion\$PatchMonth\ -Filter *.msu -Recurse | 
                 Where-Object {$installedPatches -notcontains ($_.baseName -replace '^.*?(KB\d{7}).*$', '$1')}

           

        if($Files.Length -gt 1){
                
                
                 $Timeout = 10000
                 $icon = 'Info'
                 $Title = 'Windows Update'
                 $Text = 'Windows Updates are being installed, You may need to restart your workstation'
                 Add-Type -AssemblyName System.windows.forms

                if($script:balloon -eq $null){
                    $script:balloon = New-Object System.Windows.Forms.NotifyIcon
                    }

                $path                     = Get-Process -id $pid | Select-Object -ExpandProperty Path
                $Balloon.Icon             = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
                $Balloon.BalloonTipIcon   = $icon
                $Balloon.BalloonTipText   = $Text
                $balloon.BalloonTipTitle  = $Title
                $Balloon.Visible          = $true

                $Balloon.ShowBalloonTip($Timeout).dispose
                }

 
        foreach( $File in $Files){
            "Installing!!! $File" | Out-File -FilePath $PatchLog -Append

            Copy-Item -Path $File.FullName -Destination "$updateRepo\$PatchDate\$File" -Force 

            $null = wusa "$updateRepo\$PatchDate\$File" /quiet /norestart /log:C:\temp\WindowsUpdates\UpdateLogs\wusaUpdater.evtx /f
            Write-Host "installing $File"
            $updateWait = (Get-Process wusa).Id
            Wait-Process -Id $updateWait        
            }

        "Windows Update Script has completed at $(get-date -format 'u')" | Out-File -FilePath $PatchLog -Append
        "______________________________________________________________________" | Out-File -FilePath $PatchLog -Append
    }
    catch
        {$ErrorMessage = $_.Exception.Message
        "The script Failed at $ErrorMessage" | Out-File -FilePath $PatchLog -Append
        }
    $env:SEE_MASK_NOZONECHECKS = 0
}

function Test-PendingReboot{
    if (Get-ChildItem    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"  -EA Ignore) {return $true}
    if (get-item         "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Auto Update\RebootRequired"               -EA Ignore) {return $true}
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) {return $true}
    try{
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if(($status -ne $null) -and $status.RebootPending){return $true}    
    }catch{}
return $false
}

function Update-WindowsDefenderSignatures{  
    "Checking for Defender Signature Updates at $(get-date -format 'u')" | Out-File -FilePath $PatchLog -Append
     $LastSigUpdate = Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated 
        $LastSigUpdate = ($LastSigUpdate -split "/")[1]
        $DOM = get-date -format "dd"

    
        $defenderUpdates = (Get-ChildItem -Path \\10.10.1.23\Domain_Objects\WindowsDefender\ -Filter *.exe | ? {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}).name

        if(($LastSigUpdate -ne $DOM) -and ($defenderUpdates -ne $Null)){
                "Updates Found! Updating Windows Defender Signature Updates at $(get-date -format 'u')" | Out-File -FilePath $PatchLog -Append

                Start-Process \\10.10.1.23\Domain_Objects\WindowsDefender\$defenderUpdates -ArgumentList /f
                $Timeout = 10000
                 $icon = 'Info'
                 $Title = 'Windows Defender AntiVirus Update'
                 $Text = 'Windows Defender Signature AV Updates are being installed'
                 Add-Type -AssemblyName System.windows.forms

                if($script:balloon -eq $null){$script:balloon = New-Object System.Windows.Forms.NotifyIcon}

                $path                     = Get-Process -id $pid | Select-Object -ExpandProperty Path
                $Balloon.Icon             = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
                $Balloon.BalloonTipIcon   = $icon
                $Balloon.BalloonTipText   = $Text
                $balloon.BalloonTipTitle  = $Title
                $Balloon.Visible          = $true

                $Balloon.ShowBalloonTip($Timeout).dispose
                }
        
        else{
            "No Defender Signature Updates are avaliable at this time" | Out-File -FilePath $PatchLog -Append
                if($LastSigUpdate -ne $DOM){
                "WARNING:: Windows Defender is out of date The last Signature update was $LastSigUpdate" | Out-File -FilePath $PatchLog -Append
                Write-Warning "Windows Defender is out of Date"
                }
                else{
                "Windows Defender is up to date" | Out-File -FilePath $PatchLog -Append
                "Windows Update Script has completed at $(get-date -format 'u')" | Out-File -FilePath $PatchLog -Append
                "______________________________________________________________________" | Out-File -FilePath $PatchLog -Append
                }
            }


}
function Install-OfficeUpdates{
    if (!(Test-Path $officeUpdates)){New-Item -ItemType directory -Path $officeUpdates}
    $MSofficeUpdates = Get-ChildItem -Path \\10.10.1.23\Domain_Objects\WindowsUpdates\$osVersion\OfficeUpdates -Filter *.cab -Recurse

    Copy-Item -Path $MSofficeUpdates -Destination $officeUpdates -Force

    dism /online /add-package /packagepath:$officeUpdates+'.cab'


}
    $patchTimePM = get-date '4:00:00 PM'
    $patchTimeAM = get-date '11:59:00 PM'

    $rebootMin = get-date   '12:00:00 AM'
    $rebootMax = Get-Date   '2:00:00 AM'

    $now = Get-Date

    $rebootTime = $rebootMin.TimeOfDay -le $now.TimeOfDay -and $rebootMax.TimeOfDay -ge $now.TimeOfDay
    $patchTime = $patchTimePM.TimeOfDay -le $now.TimeOfDay -and $patchTimeAM.TimeOfDay -ge $now.TimeOfDay


    if (($rebootTime -eq $true) -and (Test-PendingReboot -eq $true)){Restart-Computer -Force}
        if (Test-PendingReboot -eq $true){
            $Timeout = 10000
            $icon = 'Warning'
            $Title = 'Restart Required'
            $Text = 'Recently installed updates require your workstation to be restarted. An automatic restart is scheduled tonight at Midnight'
            Add-Type -AssemblyName System.windows.forms

            if($script:balloon -eq $null){$script:balloon = New-Object System.Windows.Forms.NotifyIcon}
                $path                     = Get-Process -id $pid | Select-Object -ExpandProperty Path
                $Balloon.Icon             = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
                $Balloon.BalloonTipIcon   = $icon
                $Balloon.BalloonTipText   = $Text
                $balloon.BalloonTipTitle  = $Title
                $Balloon.Visible          = $true

                $Balloon.ShowBalloonTip($Timeout).dispose
        }
                
    if (! ($patchTime -eq $true)) {Update-WindowsDefenderSignatures}
         elseif ($osVersion = 'Windows_10') {Install-OfficeUpdates}
        
    
    if ($patchTime -eq $true) {Install-WindowsPatches}