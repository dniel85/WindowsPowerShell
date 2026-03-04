
$tempPath = "C:\temp"
$IP_GXE = "115.0.112.16"
$IP_GXN = "115.32.112.16"
$Hostname = $env:computername

$username= $env:USERDNSDOMAIN+"\"+$env:USERNAME
$password = (Get-Credential).Password
$credential = New-Object System.Management.Automation.PSCredential ($username, $password)

if(-not(Test-Path -Path $tempPath)) {New-Item -Path $tempPath -ItemType Directory}
if((get-service scsm -ErrorAction SilentlyContinue).status -eq "Running"){Write-host "LRSystemMonitor is already installed $env:computername Quitting now...." -ForegroundColor Cyan
    start-sleep -seconds 3
    exit}


new-psdrive -Name Q -PSProvider FileSystem -Root "\\GXE-FS1.gnext.dev\GNext Share" -Persist -Credential $credential -ErrorAction Stop
Copy-Item 'Q:\LogRhythm\LR 7.19 Sysmons\LRSystemMonitor_64_7.19.0.1041.exe' -Destination c:\temp -ErrorAction Stop
Remove-PSDrive -Name Q
if($Hostname -like "GXE*"){ 
    $SelectedIP = $IP_GXE
}elseif($Hostname -like "GXN*"){
    $selectedIP = $IP_GXN
}

Unblock-File -Path "C:\temp\LRSystemMonitor_64_7.19.0.1041.exe"
$Process = start-process -filepath "C:\temp\LRSystemMonitor_64_7.19.0.1041.exe" -argumentlist "/s /v`" /qn ADDLOCAL=System_Monitor Host=$SelectedIP`"" -passthru
Wait-Process -id $Process.id
set-service -Name scsm -StartupType Automatic
start-service scsm
Remove-Item -Path "$tempPath\LRSystemMonitor_64_7.19.0.1041.exe"


