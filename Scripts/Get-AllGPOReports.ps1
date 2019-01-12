
#This Script will retrive all gpo settings for the Domain and output them in HTML & XML format

Write-Host "Creating Directory: $env:USERPROFILE\Desktop\GPO_Capture_$dateStr\HTML_Format " -BackgroundColor Black -ForegroundColor Yellow
Write-Host "Creating Directory: $env:USERPROFILE\Desktop\GPO_Capture_$dateStr\XML_Format " -BackgroundColor Black -ForegroundColor Yellow
$DateStr = $date.ToString("yyyyMMdd-hhmm")
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\Desktop\GPO_Capture_$dateStr"
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\Desktop\GPO_Capture_$dateStr\HTML_Format"
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\Desktop\GPO_Capture_$dateStr\XML_Format"

Write-Host "Retriving all HTML GPO settings" -BackgroundColor Black -ForegroundColor Yellow
Get-GPO -All | % {Get-GPOReport -Guid $_.Id -ReportType HTML -Path "$env:USERPROFILE\Desktop\GPO_Capture_$dateStr\HTML_Format\$($_.displayName).html"} -ErrorAction Ignore
Write-Host "Retriving all XML GPO settings" -BackgroundColor Black -ForegroundColor Yellow
Get-GPO -All | % {Get-GPOReport -Guid $_.Id -ReportType Xml -Path "$env:USERPROFILE\Desktop\GPO_Capture_$dateStr\XML_Format\$($_.displayName).xml"} -ErrorAction Ignore
Write-Host "All GPO settings have been saved to the local desktop uder GPO_Capture_$DateStr" -BackgroundColor Black -ForegroundColor Yellow
pause