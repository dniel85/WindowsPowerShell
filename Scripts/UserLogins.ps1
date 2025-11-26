$user = "darrell.nielsen"
$DaysBack = 10
$StartDate = (Get-Date).AddDays(-$DaysBack)

$LogonEvents  = 4624
$LogoffEvents = 4647
$LockEvents   = 4800
$UnlockEvents = 4801
$EventIDs = $LogonEvents, $LogoffEvents, $LockEvents, $UnlockEvents

# HELPER FUNCTION TO MATCH USERNAME IN ANY PROPERTY
function EventHasUser {
    param($event, $username)
    foreach ($prop in $event.Properties) {
        if ($prop.Value -match $username) { return $true }
    }
    return $false
}

# HELPER FUNCTION TO MAP LOGON TYPE TO DESCRIPTION
function Get-LogonTypeDescription {
    param($event)
    if ($event.Id -eq 4624 -or $event.Id -eq 4647) {
        switch ($event.Properties[8].Value) {
            2  { return "Interactive (Console)" }
            3  { return "Network" }
            4  { return "Batch (Scheduled Task)" }
            5  { return "Service" }
            7  { return "Unlock" }
            8  { return "NetworkCleartext" }
            9  { return "NewCredentials" }
            10 { return "RemoteInteractive (RDP)" }
            11 { return "CachedInteractive" }
            default { return "Other" }
        }
    } elseif ($event.Id -eq 4800 -or $event.Id -eq 4801) {
        # For Lock/Unlock, use 1-based Property index
        switch ($event.Properties[1].Value) {
            2  { return "Interactive (Console)" }
            7  { return "Unlock" }
            10 { return "RemoteInteractive (RDP)" }
            default { return $event.Properties[1].Value }
        }
    } else {
        return $null
    }
}

# GET ALL EVENTS
$AllEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = $EventIDs
} | Sort-Object TimeCreated

# FILTER EVENTS
$Events = $AllEvents | Where-Object {
    $_.TimeCreated -ge $StartDate -and
    (EventHasUser $_ $User) -and
    ($_.Id -ne 4624 -or $_.Properties[8].Value -in 2,7,10)  # exclude scheduled task logons
} | Select-Object TimeCreated, Id, @{
    Name='EventType';
    Expression={
        switch ($_.Id) {
            4624 { "Logon" }
            4647 { "Logoff" }
            4800 { "Lock" }
            4801 { "Unlock" }
        }
    }
}, @{
    Name='LogonType';
    Expression={ Get-LogonTypeDescription $_ }
} | Sort-Object TimeCreated

# OUTPUT
Write-Host "`n=== Unlock/Lock/Login/Logoff Events for Last 10 Days ===`n"
$Events | Format-Table TimeCreated, Id, EventType, LogonType -AutoSize

# Optional CSV export
# $Events | Export-Csv "C:\Logs\UserEvents_$User.csv" -NoTypeInformation