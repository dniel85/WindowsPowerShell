$mpam64 = "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64"
$mpam86 = "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86"

$nis64 = "https://go.microsoft.com/fwlink/?LinkID=187316&arch=x64&nri=true"
$nis86 = "https://go.microsoft.com/fwlink/?LinkID=187316&arch=x86&nri=true"

$x64_path = "C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x64\"
$x86_path = "C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x86\"
$transfer_Path = "N:\Transfer\For Darrell"

if(!(test-Path -PathType Container $x64_path)){New-Item -ItemType Directory -Path $x64_path}
if(!(test-Path -PathType Container $x86_path)){New-Item -ItemType Directory -Path $x86_path}
if(!(test-Path -PathType Container $transfer_path)){New-Item -ItemType Directory -Path $transfer_path}

Invoke-WebRequest $mpam64 -OutFile "C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x64\mpam-fe.exe" 
Invoke-WebRequest $mpam86 -OutFile "C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x86\mpam-fe.exe"

Invoke-WebRequest $nis64 -OutFile "C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x64\nis_full.exe" 
Invoke-WebRequest $nis86 -OutFile "C:\Users\darrell.nielsen\Desktop\DefenderUpdates\wd_dfs\x86\nis_full.exe"

gci 'N:\Transfer\For Darrell' | where {$_.name -like "*defenderUpdates.iso"} | Remove-Item

$date = (get-date).ToString("MM-dd-yy")

New-IsoFile -Source C:\Users\darrell.nielsen\Desktop\DefenderUpdates -Path "N:\Transfer\For Darrell\$date-defenderUpdates.iso"

start-sleep -Seconds 20 

Remove-Item -Path "C:\users\darrell.nielsen\Desktop\DefenderUpdates" -Recurse