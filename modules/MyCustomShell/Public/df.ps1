function df {
<#
.SYNOPSIS
Linux-style disk Free viewer.

.DESCRIPTION
Calculates directory sizes recursively and displays them sorted.

.EXAMPLE
du C:\Temp
#>
Get-CimInstance Win32_LogicalDisk -filter "DriveType=3" | 
               select-Object deviceID, VolumeName,
               @{Name="Size(GB)";Expression={[math]::round($_.Size/1GB,2)}},
               @{Name="Free(GB)";Expression={[math]::round($_.FreeSpace/1GB,2)}},
               @{Name="Used(GB)";Expression={[math]::round(($_.Size - $_.FreeSpace)/1GB,2)}},
               @{Name="%Used";Expression={ $percent = [math]::round((($_.Size - $_.FreeSpace)/$_.Size)*100,2)}} | ft 
      }