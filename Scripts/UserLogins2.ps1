# ===============================
# PARAMETERS
# ===============================
$User = "darrell.nielsen"
$DaysBack = 10                    # Lookback period
$StartDate = (Get-Date).AddDays(-$DaysBack)

$EvtxFolder = "C:\Logs"  # Folder containing EVTX backups
$EventIDs = 4624,4647,4800,4801         # Events to track

$ExcludeScheduledTasks = $true           # Exclude logon type 4 (Batch) if desired

# ===============================
# HELPER FUNCTIONS
# ===============================
function EventHasUser {
    param($event, $username)
    foreach ($prop in $event.Properties) {
        if ($prop.Value -match $username) { return $true }
    }
    return $false
}

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
        switch ($event.Properties[1].Value) {
            2  { return "Interactive (Console)" }
            7  { return "Unlock" }
            10 { return "RemoteInteractive (RDP)" }
            default { return $event.Properties[1].Value }
        }
    } else { return $null }
}

# ===============================
# READ ALL EVTX FILES
# ===============================
Write-Host "Reading EVTX files from $EvtxFolder..."
$AllEvents = @()
Get-ChildItem -Path $EvtxFolder -Filter *.evtx | ForEach-Object {
    Write-Host "Reading file: $($_.FullName)"
    try {
        $AllEvents += Get-WinEvent -Path $_.FullName -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Failed to read $($_.FullName): $_"
    }
}
Write-Host "Total events read from all files: $($AllEvents.Count)"

# ===============================
# FILTER EVENTS
# ===============================
$FilteredEvents = $AllEvents | Where-Object {
    ($EventIDs -contains $_.Id) -and
    ($_.TimeCreated -ge $StartDate) -and
    (EventHasUser $_ $User) -and
    (-not ($ExcludeScheduledTasks -and $_.Id -eq 4624 -and $_.Properties[8].Value -eq 4))
}

Write-Host "Events after filtering by ID, date, user, and scheduled task exclusion: $($FilteredEvents.Count)"

# Map EventType and LogonType
$ProcessedEvents = $FilteredEvents | Select-Object TimeCreated, Id, @{
    Name='EventType';
    Expression={ switch ($_.Id) {4624{"Logon"}4647{"Logoff"}4800{"Lock"}4801{"Unlock"}} }
}, @{
    Name='LogonType';
    Expression={ Get-LogonTypeDescription $_ }
} | Sort-Object TimeCreated

# ===============================
# GROUP BY DAY AND SUMMARIZE
# ===============================
$DailySummary = $ProcessedEvents | Group-Object { $_.TimeCreated.Date } | ForEach-Object {
    $DayEvents = $_.Group
    [PSCustomObject]@{
        Date        = $_.Name
        FirstEvent  = $DayEvents[0].TimeCreated
        FirstType   = $DayEvents[0].EventType
        FirstLogon  = $DayEvents[0].LogonType
        LastEvent   = $DayEvents[-1].TimeCreated
        LastType    = $DayEvents[-1].EventType
        LastLogon   = $DayEvents[-1].LogonType
        TotalEvents = $DayEvents.Count
    }
}

# ===============================
# OUTPUT
# ===============================
Write-Host "`n=== Daily Unlock/Lock/Login/Logoff Summary for Last $DaysBack Days ===`n"
$DailySummary | Format-Table Date, FirstEvent, FirstType, FirstLogon, LastEvent, LastType, LastLogon, TotalEvents -AutoSize

# Optional: export to CSV
# $DailySummary | Export-Csv "C:\Logs\UserEvents_DailySummary.csv" -NoTypeInformation