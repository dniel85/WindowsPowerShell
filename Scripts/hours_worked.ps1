<#
.SYNOPSIS
Displays the first workstation access and last lock time.

.DESCRIPTION
Analyzes Windows Security Event Logs to determine when a user first
accessed the workstation and when it was last locked.

Evaluated events:

4624  - Interactive logon
4801  - Workstation unlock
4800  - Workstation lock

If the user unlocked after the last lock, the session is considered
active and the duration is calculated to the current time.

.PARAMETER Days
Number of days to analyze.

.PARAMETER Computer
Remote computer to query.

.EXAMPLE
hours_worked

.EXAMPLE
hours_worked -Days 5

.EXAMPLE
hours_worked -Computer PC01 -Days 3

.NOTES
Author  : Darrell Nielsen
Module  : PSScripts
Version : 1.2
#>

[CmdletBinding()]
param(
    [int]$Days = 1,
    [string]$Computer
)

$scriptBlock = {

param($Days)

$startDate = (Get-Date).Date.AddDays(-($Days-1))

# Pull all events once (much faster)
$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624,4800,4801
    StartTime=$startDate
} -ErrorAction SilentlyContinue

$results = @()

for ($i=0;$i -lt $Days;$i++) {

    $start = (Get-Date).Date.AddDays(-$i)
    $end   = $start.AddDays(1)

    $dayEvents = $events | Where-Object {
        $_.TimeCreated -ge $start -and $_.TimeCreated -lt $end
    }

    # First login
    $login = $dayEvents |
        Where-Object {
            $_.Id -eq 4624 -and $_.Properties[8].Value -eq 2
        } |
        Sort-Object TimeCreated |
        Select-Object -First 1

    # First unlock
    $unlock = $dayEvents |
        Where-Object {$_.Id -eq 4801} |
        Sort-Object TimeCreated |
        Select-Object -First 1

    # Last lock
    $lock = $dayEvents |
        Where-Object {$_.Id -eq 4800} |
        Sort-Object TimeCreated |
        Select-Object -Last 1

    # Last unlock
    $lastUnlock = $dayEvents |
        Where-Object {$_.Id -eq 4801} |
        Sort-Object TimeCreated |
        Select-Object -Last 1

    $eventsList = @()

    if ($login) {
        $eventsList += [PSCustomObject]@{
            User=$login.Properties[5].Value
            Time=$login.TimeCreated
            Type="Login"
        }
    }

    if ($unlock) {
        $eventsList += [PSCustomObject]@{
            User=$unlock.Properties[1].Value
            Time=$unlock.TimeCreated
            Type="Unlock"
        }
    }

    $first = $eventsList | Sort-Object Time | Select-Object -First 1

    if ($first) {

        # Determine if session is active
        if ($lock -and $lastUnlock) {

            if ($lastUnlock.TimeCreated -gt $lock.TimeCreated) {

                $endTime = Get-Date
                $lastLockValue = "(active)"

            }
            else {

                $endTime = $lock.TimeCreated
                $lastLockValue = $lock.TimeCreated

            }

        }
        elseif ($lock) {

            $endTime = $lock.TimeCreated
            $lastLockValue = $lock.TimeCreated

        }
        else {

            $endTime = Get-Date
            $lastLockValue = "(active)"

        }

        $span = New-TimeSpan -Start $first.Time -End $endTime

        $totalMinutes=[math]::Floor($span.TotalMinutes)
        $hours=[math]::Floor($totalMinutes/60)
        $minutes=$totalMinutes%60

        $duration="$hours hours $minutes minutes"

        $results += [PSCustomObject]@{
            Date        = $start.ToString("yyyy-MM-dd")
            User        = $first.User
            FirstAccess = $first.Time
            Method      = $first.Type
            LastLock    = $lastLockValue
            Duration    = $duration
        }

    }
    else {

        $results += [PSCustomObject]@{
            Date        = $start.ToString("yyyy-MM-dd")
            User        = "-"
            FirstAccess = "No Activity"
            Method      = "-"
            LastLock    = "-"
            Duration    = "-"
        }

    }

}

$results
}

# Run locally or remotely
if ($Computer) {

    Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $Days |
    Select-Object Date,User,FirstAccess,Method,LastLock,Duration |
    Sort-Object Date -Descending |
    Format-Table -AutoSize

}
else {

    & $scriptBlock $Days |
    Select-Object Date,User,FirstAccess,Method,LastLock,Duration |
    Sort-Object Date -Descending |
    Format-Table -AutoSize

}