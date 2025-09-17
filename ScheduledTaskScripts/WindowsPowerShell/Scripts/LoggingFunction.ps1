# LoggingFunctions.ps1

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")] [string]$Level = "INFO",
        [switch]$LogFile,
        [switch]$LogEnabled  # New parameter to control logging
    )

    # Only log if logging is enabled
    if ($LogEnabled) {
        # Get current timestamp and line number
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $lineNumber = $MyInvocation.ScriptLineNumber
        $functionName = $MyInvocation.MyCommand.name

        # Format the log entry with timestamp, level, and line number
        $logEntry = "$timestamp [Line $lineNumber] [$Level] - $Message"

        # Write to console based on verbosity level
        if ($Level -eq "ERROR") {
            Write-Host $logEntry -ForegroundColor Red
        }elseif ($Level -eq "WARN") {
            Write-Host $logEntry -ForegroundColor Yellow
        }elseif ($Level -eq "INFO") {
            Write-Host $logEntry -ForegroundColor Green
        }

        # Append the log entry to the log file
        #$logEntry | Out-File -Append -FilePath $LogFile
    }
    if ($LogFile){
    $logPath = "C:\temp\logfile.log"
    $logEntry | Out-File -Append -FilePath $logPath
    }
}

