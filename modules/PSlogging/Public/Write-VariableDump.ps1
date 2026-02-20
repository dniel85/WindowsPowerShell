function Write-VariableDump {
    [CmdletBinding()]
    param(
        [switch]$IncludeAutomatic,
        [int]$Scope = 0
    )

    # Only run if debug logging enabled
    if (-not $script:LogDebugEnabled) {
        return
    }

    $Vars = Get-Variable -Scope $Scope

    if (-not $IncludeAutomatic) {
        $Vars = $Vars | Where-Object {
            $_.Name -notmatch '^(_|PS|MyInvocation|args|input)'
        }
    }

    foreach ($Var in $Vars) {
        try {
            Write-Log "VAR [$($Var.Name)]" -Level DEBUG -Var $Var.Value
        }
        catch {
            Write-Log "VAR [$($Var.Name)] could not be logged" -Level DEBUG
        }
    }
}
