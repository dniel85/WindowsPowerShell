function Start-StayAwake {
<#
.SYNOPSIS
Prevents CPU lock

.DESCRIPTION
Sends a virtual key every minute to prevent workstation idle timeout.
Locks the workstation automatically when the timer expires or window is closed.

.PARAMETER Hours
Number of hours to stay awake. Default is 2.

.EXAMPLE
Stay-Awake
Stay-Awake -Hours 4
#>
param(
    [int]$Hours = 2
)

$cmd = "Import-Module MyCustomShell; Stay-Awake -Hours $Hours"

Start-Process powershell -ArgumentList "-NoExit","-Command",$cmd -WindowStyle Minimized
}