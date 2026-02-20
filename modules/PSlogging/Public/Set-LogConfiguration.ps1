function Set-LogConfiguration {
<#
.SYNOPSIS
    Configures logging behavior for Write-Log.

.PARAMETER EnableDebug
    Enables DEBUG level logging.

.PARAMETER DisableDebug
    Disables DEBUG level logging.

.PARAMETER Levels
    Specifies which log levels should be written.
    Valid values: INFO, WARN, ERROR, DEBUG
.PARAMETER MaxLogSizeMB
    Sepecifies the max log size before rotation
#>
    [CmdletBinding()]
    param(
        [switch]$EnableDebug,
        [switch]$DisableDebug,

        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string[]]$Levels,

        [ValidateRange(1,100)]
        [int]$MaxLogSizeMB = 5
    )

    if ($EnableDebug) {
        $script:LogDebugEnabled = $true
    }

    if ($DisableDebug) {
        $script:LogDebugEnabled = $false
    }

    if ($Levels) {
        $script:LogLevels = $Levels
    }

    if ($MaxLogSizeMB) {
        $script:MaxLogSizeMB = $MaxLogSizeMB
    }
}