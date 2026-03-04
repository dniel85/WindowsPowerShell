# ================================
# Logging Configuration (Defaults)
# ================================
if (-not $script:LogDebugEnabled) {
    $script:LogDebugEnabled = $false
}

if (-not $script:LogLevels) {
    $script:LogLevels = @("INFO","WARN","ERROR")
}

if (-not $script:MaxLogSizeMB) {
    $script:MaxLogSizeMB = 5
}