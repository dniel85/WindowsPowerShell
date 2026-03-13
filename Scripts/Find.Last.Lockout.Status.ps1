<#
.SYNOPSIS
    Provides a quick search to determine last lockout status

.DESCRIPTION
    This script queries all domain controllers for the last lockout event (Event ID 4740) related to a specified username.
    It retrieves the time of the lockout, the computer where the lockout occurred, and the event message.

.PARAMETER username
    The username for which to search for lockout events.

.EXAMPLE
    .\Find.Last.Lockout.Status.ps1 -username "jdoe"

.NOTES
    Author: Darrell Nielsen
    Created: 2026-03-09
    Version: 1.0

TAGS:
    tools
    security
    accountmanagement
    lockoutstatus
    lock
    lockedout
#>
[cmdletbinding()]
    param(
        [parameter(mandatory=$true)]
        $username
        )

import-module ActiveDirectory

Get-ADDomainController -Filter * | ForEach-Object{
    Get-WinEvent -ComputerName $_.hostname -FilterHashtable @{LogName='Security';ID=4740} | Where-Object {$_.Message -like '*$username*'} |
     Select-Object timecreated, @{Name='Computer';Expression={($_.properties[1].value)}}, Message
    }