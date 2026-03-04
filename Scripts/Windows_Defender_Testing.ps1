# Registers a new source for the Application log if not already present
if (-not [System.Diagnostics.EventLog]::SourceExists("DefenderTest")) {
    New-EventLog -LogName Application -Source "DefenderTest"
}

# Writes a custom event (simulating Defender alert) to the Application log
Write-EventLog -LogName Application -Source "DefenderTest" -EventId 1116 -EntryType Warning -Message "Simulated Windows Defender Malware Alert. ThreatName=TestSimulatedThreat Action=Blocked"