function Write-Log {
<#
.SYNOPSIS
    Writes structured log entries to the standard log file.
.DESCRIPTION
    Write-Log writes messages to the configured log file with support
    for INFO, WARN, ERROR, and DEBUG levels.
.PARAMETER Message
    The message to write to the log.
.PARAMETER Level
    The severity level of the log entry.
    Valid values: INFO, WARN, ERROR, DEBUG.
.PARAMETER Var
    Optional variable to log for debugging purposes.
.PARAMETER Force
    Forces the message to be written regardless of log level configuration.
.EXAMPLE
    Write-Log -Message "Starting installation"
.EXAMPLE
    Write-Log -Message "Service failed" -Level ERROR
.NOTES
    Author: Darrell Nielsen
    Module: PSLogging
#>
    [CmdletBinding()]
    param (
        [Parameter(Position=0)]
        [string]$Message,

        [Parameter(Position=1)]
        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO",

        [object]$Var,
        [switch]$Force
    )

    # ===== Filtering Logic =====
    if (-not $Force) {

        # DEBUG controlled only by EnableDebug
        if ($Level -eq "DEBUG") {
            if (-not $script:LogDebugEnabled) { return }
        }
        else {
            if ($Level -notin $script:LogLevels) { return }
        }
    }

    if (-not $Message) {
        if ($PSBoundParameters.ContainsKey('Var')) {
            $Message = "Detected variable"
        }
        else {
            throw "Write-Log requires a message unless -Var is specified."
        }
    }

    # ===== Determine Execution Context =====
    $CallStack = Get-PSCallStack
    $Frame = $CallStack[1]
    $ScriptPath = $Frame.ScriptName

    $IsScript = $false

    if ($ScriptPath -and $ScriptPath.EndsWith(".ps1")) {
        $IsScript = $true
    }

    if ($IsScript) {

        $ScriptDirectory = Split-Path $ScriptPath -Parent
        $ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)

        $BaseLogPath = Join-Path $ScriptDirectory "Logs"
        $LogFolder = Join-Path $BaseLogPath $ScriptName
        $LogFile = Join-Path $LogFolder "$ScriptName.log"

        $LineNumber = $Frame.ScriptLineNumber
    }
    else {
        # Console logging location
        $BaseLogPath = Join-Path $HOME "Documents\WindowsPowerShell\Logs"
        $LogFolder = Join-Path $BaseLogPath "PowerShell_Console"
        $LogFile = Join-Path $LogFolder "PowerShell_Console.log"
    }

    # ===== Ensure Folder Exists =====
    if (-not (Test-Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }

    # ===== Rotation =====
    if (Test-Path $LogFile) {
        $MaxBytes = $script:MaxLogSizeMB * 1MB
        $CurrentSize = (Get-Item $LogFile).Length

        if ($CurrentSize -ge $MaxBytes) {
            $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($LogFile)
            $ArchivePath = Join-Path $LogFolder "$BaseName`_$Timestamp.log"
            Move-Item $LogFile $ArchivePath -Force
        }
    }

    # ===== Variable Handling =====
    if ($PSBoundParameters.ContainsKey('Var')) {
        try {
            $VarValue = if ($Var -is [System.Collections.IEnumerable] -and -not ($Var -is [string])) {
                ($Var | Out-String).Trim()
            }
            else {
                $Var.ToString()
            }
        }
        catch {
            $VarValue = "Unable to stringify variable"
        }

        $Message = "$Message | VAR: $VarValue"
    }

    $TimeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    if ($IsScript) {
        $Entry = "$TimeStamp [$Level] [L$LineNumber] $Message"
    }
    else {
        $Entry = "$TimeStamp [$Level] $Message"
    }

    # ===== Console Output =====
    if ([Environment]::UserInteractive) {
        switch ($Level) {
            "ERROR" { Write-Host $Entry -ForegroundColor Red }
            "WARN"  { Write-Host $Entry -ForegroundColor Yellow }
            "DEBUG" { Write-Host $Entry -ForegroundColor Black -BackgroundColor Yellow }
            default { Write-Host $Entry -ForegroundColor Green }
        }
    }

    Add-Content -Path $LogFile -Value $Entry
}