$edgeProcesses = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
if ($edgeProcesses) {
        Stop-Process -Name "msedge" -Force
    } else {
}
Start-Sleep -Seconds 2
$edgeUserDataDir = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
$cacheDir = Join-Path -Path $edgeUserDataDir -ChildPath "Default\Cache"
if (Test-Path -Path $cacheDir) {
    Remove-Item -Path $cacheDir\* -Recurse -Force
} 
Start-Process "msedge.exe"