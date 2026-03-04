Import-Module PSlogging
Set-LogConfiguration -Levels ERROR,INFO,WARN
try{
$edgeProcesses = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
Write-Log -Var $edgeProcesses
if ($edgeProcesses) {
        Stop-Process -Name "msedge" -Force
    } else {
    Write-Log -Message "$edgeProcesses could not be found" -Level WARN
}
Start-Sleep -Seconds 2
Write-Log -Message "starting sleep..."
$edgeUserDataDir = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
Write-Log -Var $edgeUserDataDir 
$cacheDir = Join-Path -Path $edgeUserDataDir -ChildPath "Default\Cache"
Write-Log -Var $cacheDir
if (Test-Path -Path $cacheDir) {
    Remove-Item -Path $cacheDir\* -Recurse -Force
} 
Write-Log "restarting Edge.exe"
Start-Process "msedge.exe"
}
catch{
    Write-Log -Message "An error has occored at::$_" -Level ERROR
    }
Write-Log -Message "end of script" 