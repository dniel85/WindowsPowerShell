param(
    [int]$Days = 1,

    [string[]]$ComputerName = $env:COMPUTERNAME
)

$scriptBlock = {

param($Days)

$results = @()

for ($i = 0; $i -lt $Days; $i++) {

    $start = (Get-Date).Date.AddDays(-$i)
    $end   = $start.AddDays(1)

    $login = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4624
        StartTime=$start
        EndTime=$end
    } -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[8].Value -eq 2 } |
    Sort-Object TimeCreated |
    Select-Object -First 1

    $unlock = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4801
        StartTime=$start
        EndTime=$end
    } -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated |
    Select-Object -First 1

    $lock = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4800
        StartTime=$start
        EndTime=$end
    } -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated |
    Select-Object -Last 1

    $events = @()

    if ($login) {
        $events += [PSCustomObject]@{
            User = $login.Properties[5].Value
            Time = $login.TimeCreated
            Type = "Login"
        }
    }

    if ($unlock) {
        $events += [PSCustomObject]@{
            User = $unlock.Properties[1].Value
            Time = $unlock.TimeCreated
            Type = "Unlock"
        }
    }

    $first = $events | Sort-Object Time | Select-Object -First 1

    if ($first) {

        $duration = "-"

        if ($lock) {

            $session = New-TimeSpan -Start $first.Time -End $lock.TimeCreated

            $totalMinutes = [math]::Floor($session.TotalMinutes)

            $hours   = [math]::Floor($totalMinutes / 60)
            $minutes = $totalMinutes % 60

            $duration = "$hours hours $minutes minutes"
        }

        $results += [PSCustomObject]@{
            Computer    = $env:COMPUTERNAME
            Date        = $start.ToString("yyyy-MM-dd")
            User        = $first.User
            FirstAccess = $first.Time
            Method      = $first.Type
            LastLock    = if ($lock) { $lock.TimeCreated } else { "-" }
            Duration    = $duration
        }

    }
    else {

        $results += [PSCustomObject]@{
            Computer    = $env:COMPUTERNAME
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

Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $Days |
Sort-Object Computer,Date -Descending |
Format-Table -AutoSize

