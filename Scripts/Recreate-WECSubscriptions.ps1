#################################
# Windows Event Collector Subscription Reset Script for Citrix VDAs
# written by Christopher Rice, 12/27/2023
# for 692d Cyberspace Ops Sqd, SIL Victory Team
# RELEASE VERSION v2.0.0 - AUG 23 2024 - Added array for multiple naming schemas - JDB
#################################

# Preliminary collection of information for where the subscriptions are being reset, and also
# ensuring the VDAs are in the correct security group
$WECServerSchema = Read-Host "What is the naming scheme of the WEC machines? (e.g. V3W-CTX-WEC-*)"
$WECServers = Get-ADComputer -Filter "Name -like '$WECServerSchema'"
if ($WECServers.Count -gt 0) {
    Write-Host "Found $($WECServers.Count) WEC servers..." -ForegroundColor Cyan
}
else {
    throw "Could not find the WEC servers with the naming scheme provided."
}

$VDAServerSchemas = Read-Host "What is the naming scheme of the VDA machines, separated by commas? (e.g. V3W-VDA-*,V3W-L4SIM-*,V3W-L5SIM-*)"

# Split the input into an array
$VDAServerSchemaArray = $VDAServerSchemas -Split ','

# Generate the filter string
$FilterString = ''
ForEach ($schema in $VDAServerSchemaArray) {
		if ($FilterString) {
			$FilterString += " -or Name -like '$schema'"
		} else {
			$FilterString = "Name -like '$schema'"
		}
}

$VDAServers = Get-ADComputer -Filter $FilterString
if ($VDAServers.Count -gt 0) {
    Write-Host "Found $($VDAServers.Count) VDAs..." -ForegroundColor Cyan
}
else {
    throw "Could not find the VDAs with the naming scheme provided."
}

$VDAGroupSchema = Read-Host "What is the name of the Citrix VDA security group used for log collection? (e.g. Citrix VDA West)"
$VDAGroup = Get-ADGroup -Filter "Name -like '$VDAGroupSchema'"
if ($VDAGroup.Name -eq $VDAGroupSchema) {
    Write-Host "Found a security group matching the name provided." -ForegroundColor Cyan
}
else {
    throw "Could not find the security group."
}

# ---------------------------------------------------------------------------------------------

# Adding the VDAs to the security group
Add-ADGroupMember -Identity $VDAGroup -Members $VDAServers
Write-Host "Added VDA(s) to the security group for log collection." -ForegroundColor Green

# ---------------------------------------------------------------------------------------------

# Defining block of work that will be performed on each WEC
$EventSubXMLQuery = {
    # Fetch existing subscription (THIS ASSUMES THERE IS ONLY ONE)
    Write-Host "Fetching existing subscription..." -ForegroundColor Gray -NoNewline
    $sub = wecutil es
    # Fetch the existing subscription's XML
    Write-Host "Fetching XML of current subscription..." -ForegroundColor Gray -NoNewline
    $subXML = wecutil gs $sub /f:xml
    $subXML > C:\Windows\Temp\WEC.xml
    # Remove the first line of the XML file, since it has just "XML" heading and messes with WEC... thanks, Windows
    # also if type is "Normal", replace with "Custom"
    (Get-Content C:\Windows\Temp\WEC.xml | Select-Object -Skip 1).Replace('Normal', 'Custom') | Set-Content C:\Windows\Temp\WEC.xml
    # Delete the existing subscription
    Write-Host "Deleting original subscription..." -ForegroundColor Gray
    wecutil ds $sub
    Start-Sleep 2
    # Recreate the subscription using the same XML
    Write-Host "Recreating subscription..." -ForegroundColor Gray -NoNewLine
    wecutil cs C:\Windows\Temp\WEC.xml
    Write-Host "Subscription recreated." -ForegroundColor Green
}

# ---------------------------------------------------------------------------------------------

ForEach ($WECServer in $WECServers) {
    Write-Host "Processing $($WECServer.Name)..." -ForegroundColor Yellow
    Invoke-Command -ComputerName $WECServer.Name -ScriptBlock $EventSubXMLQuery
}

# Write-Host "Pushing GPOs to VDAs..."
# ForEach ($VDAServer in $VDAServers) {
#     Invoke-Command -ComputerName $VDAServer.Name -ScriptBlock {gpupdate /force}
# }
