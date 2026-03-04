#configuration
$targetSize = 500
$DriveLetter = "D"
$fileSystem = "NTFS"
$volumeLable = "ForwardedEvents"
$subName = wecutil es
$raw = wecutil gs $subName | Out-String
$xmlString = ($raw -split "`r?`n") | Where-Object {$_ -match "^<QueryList"}

    if($env:COMPUTERNAME -notlike '*SEC*'){
    [xml]$parsed = $xmlString -join "`r`n"
    [string]$subPath = $parsed.QueryList.Query.Select.Path
        if($subPath -eq "Sentris Sentris Security"){
            $subpath = $subPath.trim("Sentris")
            $subPath = $subPath.Replace(' ','')
        }
    }
    else{
        $subPath ="Security"
        }

$logName = "ForwardedEvents"
$maxSizeBites = 32GB
$fwdEventsFullPath = "$DriveLetter`:\Forwarded$($subpath)Events\$($logName).evtx"
$folder = Split-Path $fwdEventsFullPath
$maxsizeKB = [math]::Round($maxSizeBites / 1KB)

$existingPartition = Get-Partition -DriveLetter $DriveLetter -ErrorAction SilentlyContinue
$cdDrive = Get-WmiObject win32_cdromdrive | Select-Object -First 1 

if($existingPartition){
    Remove-PartitionAccessPath -DiskNumber $existingPartition.DiskNumber `
    -PartitionNumber $existingPartition.PartitionNumber `
    -AccessPath "$DriveLetter`:\" -Confirm $false
    } 

if($cdDrive.drive -eq "D:"){ 
    $letter = "W"

    $script = @"
    select volume $($cdDrive.Drive.TrimEnd(':'))
    assign letter =$letter
    exit
"@
    $script | Out-File -FilePath "$env:TEMP\cdrom.txt" -Encoding ascii
    diskpart /s "$env:TEMP\cdrom.txt"
    Remove-Item "$env:TEMP\cdrom.txt"    
    }

$disk = Get-Disk | Where-Object {$_.OperationalStatus -eq "Offline" -and $_.PartitionStyle -eq "RAW"}
    if(-not $disk) {
        Write-Host "No uninitialized disk found."
        }
    if($disk.IsReadOnly -eq "True"){
        Set-Disk -Number $disk.Number -IsReadOnly $false
        }

    if($disk.OperationalStatus -ne "Online"){
        Set-Disk -Number $disk.Number -IsOffline $false 
        }
    if($disk.PartitionStyle -eq "RAW"){
    Initialize-Disk -Number $disk.DiskNumber -PartitionStyle GPT
    Set-Disk -Number $disk.Number -PartitionStyle GPT
    }

$partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter $DriveLetter
Format-Volume -Partition $partition -FileSystem $fileSystem -NewFileSystemLabel $volumeLable -Confirm:$false

New-Item -Path "$DriveLetter`:\" -Name "Forwarded$($subPath)Events" -ItemType Directory 

Stop-Service Wecsvc -Force 
#Move-Item "C:\windows\System32\winevt\Logs\ForwardedEvents.evtx" "D:\ForwardedApplicationEvents\ForwardedEvents.evtx"
icacls $folder /grant "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" /grant "NT AUTHORITY\NETWORK SERVICE:(OI)(CI)(F)" /T
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$logName"
if((test-path $regPath) -eq $false){New-Item -Path $regPath   
New-ItemProperty -Path $regPath -Name "File" -Value $fwdEventsFullPath -PropertyType String -Force
}
else{
    Set-ItemProperty -Path $regPath -Name "File" -Value $fwdEventsFullPath
}

wevtutil sl ForwardedEvents /ms:$maxSizeBites /rt:$true /lfn:$fwdEventsFullPath
Start-Service Wecsvc
wevtutil gl ForwardedEvents | Select-String "File|MaxSize|Retention"