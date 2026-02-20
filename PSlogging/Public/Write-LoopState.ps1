function Write-LoopState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        $Value,

        [int]$MaxIterations = 10
    )

    if (-not $script:LogDebugEnabled) { return }

    # Initialize counter dictionary if needed
    if (-not $script:LoopCounters) {
        $script:LoopCounters = @{}
    }

    # Initialize this loop counter if not present
    if (-not $script:LoopCounters.ContainsKey($Name)) {
        $script:LoopCounters[$Name] = 0
    }

    # Stop logging if limit reached
    if ($script:LoopCounters[$Name] -ge $MaxIterations) {
        return
    }

    # Increment counter
    $script:LoopCounters[$Name]++

    Write-Log "LOOP [$Name] (Iteration $($script:LoopCounters[$Name]))" -Level DEBUG -Var $Value
}