<#
.SYNOPSIS
Clears the Microsoft Edge browser cache.

.DESCRIPTION
This script stops any running Microsoft Edge processes, removes the cache
files located in the user's Edge profile directory, and then restarts Edge.

The script uses the PSLogging module to record informational messages,
warnings, and errors during execution.

.NOTES
Author: Darrell Nielsen
Requires: PSLogging module
Tested on: Windows 10/11 with Microsoft Edge installed

TAGS:
Edge
Cache
Browser
Maintenance

The script removes files located in:
%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache

If Microsoft Edge is running, the script will forcefully stop the process
before clearing the cache.

.EXAMPLE
PS C:\> .\Clear-EdgeCache.ps1

Stops Microsoft Edge, clears the cache directory, and restarts Edge.

.EXAMPLE
PS C:\> powershell -ExecutionPolicy Bypass -File .\Clear-EdgeCache.ps1

Runs the script from a command prompt or deployment tool.

.OUTPUTS
None

The script performs system maintenance actions and writes log entries
through the PSLogging module.

.LINK
https://learn.microsoft.com/en-us/deployedge/microsoft-edge-enterprise

#>
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