##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Active Directory Forest
# Version:  V2R8
# Class:    UNCLASSIFIED
# Updated:  4/25/2023
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V8555 {
    <#
    .DESCRIPTION
        Vuln ID    : V-8555
        STIG ID    : AD.0230
        Rule ID    : SV-9052r2_rule
        CCI ID     : CCI-000366
        Rule Name  : DS10.0230 dsHeuristics Option
        Rule Title : Anonymous Access to AD forest data above the rootDSE level must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SettingName = "Anonymous access to AD Forest"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.

    Try {
        ForEach ($dc in ((Get-CimInstance Win32_ComputerSystem).Domain).ToString().Split(".")) {
            $Domain += ",dc=$($dc)"
        }
        $LdapObject = ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration" + $Domain)
        $ReturnedValue = (Get-ADObject -Identity $LdapObject -Properties dsHeuristics).dsHeuristics

        If ($ReturnedValue.Length -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "'dsHeuristics' is not configured." | Out-String
        }
        Else {
            If ($ReturnedValue.Length -ge 7 -and $ReturnedValue[6] -eq "2") {
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "dsHeuristics:`t'$ReturnedValue'" | Out-String
            }
            Else {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "dsHeuristics:`t'$ReturnedValue'" | Out-String
            }
        }
    }
    Catch {
        $FindingDetails += "Unable to determine if $($SettingName) is set to $($SettingState). Manual review required." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V8557 {
    <#
    .DESCRIPTION
        Vuln ID    : V-8557
        STIG ID    : AD.0295
        Rule ID    : SV-9054r3_rule
        CCI ID     : CCI-001891
        Rule Name  : Time Synchronization-Authoritative Source
        Rule Title : The Windows Time Service on the forest root PDC Emulator must be configured to acquire its time from an external time source.
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainRole = (Get-CimInstance Win32_ComputerSystem).DomainRole
    If ($DomainRole -ne "5") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is not the PDC Emulator so this requirement is NA."
    }
    Else {
        $W32TM = w32tm /query /configuration
        $Compliant = $true
        $ClientType = ($W32TM -Match "(?:Type: )(.*$)").Split(":")[1].Trim()
        If ($ClientType -notmatch "NTP") {
            # Finding
            $Compliant = $false
            $FindingDetails += "NTP Client Type is NOT Configured" | Out-String
            $FindingDetails += "Value: $($ClientType) [Expected: NTP]" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            # Configured Properly
            $FindingDetails += "NTP Client Type is Configured" | Out-String
            $FindingDetails += "Value:`t$($ClientType)" | Out-String
            $FindingDetails += "" | Out-String

            #This value only exists if Type is set to NTP
            $NTPServers = ($W32TM -Match "(?:NtpServer: )(.*$)").Split(":")[1].Replace('(Policy)', "").Trim()
            If ($NTPServers.Length -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configured NTP Servers" | Out-String
                $FindingDetails += "===========================" | Out-String
                ForEach ($Server in $NTPServers) {
                    $FindingDetails += "`t$($Server)" | Out-String
                }
            }
            else {
                $Compliant = $false
                $FindingDetails += "NTP Servers are NOT Configured" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Value: (Not Found)" | Out-String
            }
        }

        If ($Compliant -eq $false) {
            $Status = "Open"
        }
    }
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V15372 {
    <#
    .DESCRIPTION
        Vuln ID    : V-15372
        STIG ID    : DS00.3140_AD
        Rule ID    : SV-30999r4_rule
        CCI ID     : CCI-002235
        Rule Name  : Directory Schema Update Access
        Rule Title : Update access to the directory schema must be restricted to appropriate accounts.
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $NonNormCount = 0
    $NonNormPerms = @()

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        $SchemaPermissions = $(Get-Acl "AD:$((Get-ADRootDSE).schemaNamingContext)").Access | Sort-Object IdentityReference, ActiveDirectoryRights | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType
    }
    Else {
        $PSCommand = 'PowerShell.exe -Command {$(Get-Acl "AD:$((Get-ADRootDSE).schemaNamingContext)").Access | Sort-Object IdentityReference, ActiveDirectoryRights | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType}'
        $SchemaPermissions = Invoke-Expression $PSCommand
    }

    $FindingDetails += "`nSchema Permissions:" | Out-String
    ForEach ($SchemaPermission in $SchemaPermissions) {
        If (($SchemaPermission.IdentityReference -eq "NT AUTHORITY\Authenticated Users") -and ($SchemaPermission.ActiveDirectoryRights -eq "GenericRead")) {
            $FindingDetails += "  Permissions are set to the default for: Authenticated Users - Read" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -eq "NT AUTHORITY\SYSTEM") -and ($SchemaPermission.ActiveDirectoryRights -eq "GenericAll")) {
            $FindingDetails += "  Permissions are set to the default for: System - Full Control" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -like "*\Enterprise Read-only Domain Controllers") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")) {
            $FindingDetails += "  Permissions are set to the default for: Enterprise Read-only Domain Controllers - Replicating Directory Changes" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -like "*\Enterprise Read-only Domain Controllers") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")) {
            $FindingDetails += "  Permissions are set to the default for: Enterprise Read-only Domain Controllers - Replicating Directory Changes All" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -like "*\Enterprise Read-only Domain Controllers") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "89e95b76-444d-4c62-991a-0facbeda640c")) {
            $FindingDetails += "  Permissions are set to the default for: Enterprise Read-only Domain Controllers - Replicating Directory Changes In Filtered Set" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -Like "*\Schema Admins") -and (($SchemaPermission.ActiveDirectoryRights -like "*CreateChild*") -or ($SchemaPermission.ActiveDirectoryRights -like "*Self*") -or ($SchemaPermission.ActiveDirectoryRights -like "*WriteProperty*") -or ($SchemaPermission.ActiveDirectoryRights -like "*GenericRead*") -or ($SchemaPermission.ActiveDirectoryRights -like "*WriteDacl*") -or ($SchemaPermission.ActiveDirectoryRights -like "*WriteOwner*"))) {
            $FindingDetails += "  Permissions are set to the default for: Schema Admins - Special (except Full, Delete, and Delete subtree)" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -like "*\Schema Admins") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd")) {
            $FindingDetails += "  Permissions are set to the default for: Schema Admins - Change schema master" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -eq "BUILTIN\Administrators") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2")) {
            $FindingDetails += "  Permissions are set to the default for: Administrators - Manage replication topology" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -eq "BUILTIN\Administrators") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")) {
            $FindingDetails += "  Permissions are set to the default for: Administrators - Replicating Directory Changes" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -eq "BUILTIN\Administrators") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")) {
            $FindingDetails += "  Permissions are set to the default for: Administrators - Replicating Directory Changes All" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -eq "BUILTIN\Administrators") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "89e95b76-444d-4c62-991a-0facbeda640c")) {
            $FindingDetails += "  Permissions are set to the default for: Administrators - Replicating Directory Changes In Filtered Set" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -eq "BUILTIN\Administrators") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2")) {
            $FindingDetails += "  Permissions are set to the default for: Administrators - Replication Synchronization" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -eq "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2")) {
            $FindingDetails += "  Permissions are set to the default for: Enterprise Domain Controllers - Manage replication topology" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -eq "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")) {
            $FindingDetails += "  Permissions are set to the default for: Enterprise Domain Controllers - Replicating Directory Changes" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -eq "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")) {
            $FindingDetails += "  Permissions are set to the default for: Enterprise Domain Controllers - Replicating Directory Changes All" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -eq "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "89e95b76-444d-4c62-991a-0facbeda640c")) {
            $FindingDetails += "  Permissions are set to the default for: Enterprise Domain Controllers - Replicating Directory Changes In Filtered Set" | Out-String
        }
        ElseIf (($SchemaPermission.IdentityReference -eq "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS") -and ($SchemaPermission.ActiveDirectoryRights -eq "ExtendedRight") -and ($SchemaPermission.ObjectType -eq "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2")) {
            $FindingDetails += "  Permissions are set to the default for: Enterprise Domain Controllers - Replication Synchronization" | Out-String
        }
        Else {
            ++$NonNormCount
            $NonNormPerms += $SchemaPermission | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType
        }
    }

    If ($NonNormCount -ge 1) {
        $Status = "Open"
        $FindingDetails += "`nNon Standard Permissions in the Schema Permissions:" | Out-String
        $FindingDetails += "_______________________________________________________________________" | Out-String
        ForEach ($Object in $NonNormPerms) {
            $FindingDetails += "IdentityReference:`t`t$($Object.IdentityReference)" | Out-String
            $FindingDetails += "ActiveDirectoryRights:`t$($Object.ActiveDirectoryRights)" | Out-String
            $FindingDetails += "ObjectType:`t`t`t$($Object.ObjectType)" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
    }
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V72835 {
    <#
    .DESCRIPTION
        Vuln ID    : V-72835
        STIG ID    : AD.0017
        Rule ID    : SV-87487r1_rule
        CCI ID     : CCI-000366
        Rule Name  : AD.0017
        Rule Title : Membership to the Schema Admins group must be limited.
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $GroupName = "Schema Admins"
    Try {
        $Members = (Get-ADGroupMember $GroupName | Select-Object Name, SID, ObjectClass | Sort-Object Name) #to see members in schema admins
        If (($Members | Measure-Object).Count -le 0) {
            $Status = "NotAFinding"
            $FindingDetails += "$GroupName has no members."
        }
        Else {
            If (($Members | Measure-Object).Count -eq 1 -and $Members.Name -eq "BUILTIN\Administrators") {
                $Status = "NotAFinding"
            }
            $FindingStatus += "Members of the $($GroupName)"
            $FindingDetails += "=" * (12 + $GroupName.Length) | Out-String
            ForEach ($Object in $Members) {
                $FindingDetails += "Name:`t$($Object.Name)" | Out-String
                $FindingDetails += "SID:`t`t$($Object.SID)" | Out-String
                $FindingDetails += "Type:`t$($Object.ObjectClass)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Catch {
        $FindingDetails += "Unable to determine group membership of $($GroupName). Manual review required." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBqAwTqYz8dR08U
# Cgv1waqgvC3CQiwZUKaFiqwqkp4JhaCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
# CSqGSIb3DQEBCwUAMFoxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy
# bm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRUwEwYDVQQDEwxET0Qg
# SUQgQ0EtNTkwHhcNMjAwNzE1MDAwMDAwWhcNMjUwNDAyMTMzODMyWjBpMQswCQYD
# VQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0Qx
# DDAKBgNVBAsTA1BLSTEMMAoGA1UECxMDVVNOMRYwFAYDVQQDEw1DUy5OU1dDQ0Qu
# MDAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2/Z91ObHZ009DjsX
# ySa9T6DbT+wWgX4NLeTYZwx264hfFgUnIww8C9Mm6ht4mVfo/qyvmMAqFdeyhXiV
# PZuhbDnzdKeXpy5J+oxtWjAgnWwJ983s3RVewtV063W7kYIqzj+Ncfsx4Q4TSgmy
# ASOMTUhlzm0SqP76zU3URRj6N//NzxAcOPLlfzxcFPMpWHC9zNlVtFqGtyZi/STj
# B7ed3BOXmddiLNLCL3oJm6rOsidZstKxEs3I1llWjsnltn7fR2/+Fm+roWrF8B4z
# ekQOu9t8WRZfNohKoXVtVuwyUAJQF/8kVtIa2YyxTUAF9co9qVNZgko/nx0gIdxS
# hxmEvQIDAQABo4IBNzCCATMwHwYDVR0jBBgwFoAUdQmmFROuhzz6c5QA8vD1ebmy
# chQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5kaXNhLm1pbC9jcmwvRE9E
# SURDQV81OV9OQ09ERVNJR04uY3JsMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSAEDzAN
# MAsGCWCGSAFlAgELKjAdBgNVHQ4EFgQUVusXc6nN92xmQ3XNN+/76hosJFEwZQYI
# KwYBBQUHAQEEWTBXMDMGCCsGAQUFBzAChidodHRwOi8vY3JsLmRpc2EubWlsL3Np
# Z24vRE9ESURDQV81OS5jZXIwIAYIKwYBBQUHMAGGFGh0dHA6Ly9vY3NwLmRpc2Eu
# bWlsMB8GA1UdJQQYMBYGCisGAQQBgjcKAw0GCCsGAQUFBwMDMA0GCSqGSIb3DQEB
# CwUAA4IBAQBCSdogBcOfKqyGbKG45lLicG1LJ2dmt0Hwl7QkKrZNNEDh2Q2+uzB7
# SRmADtSOVjVf/0+1B4jBoyty90WL52rMPVttb8tfm0f/Wgw6niz5WQZ+XjFRTFQa
# M7pBNU54vI3bH4MFBTXUOEoSr0FELFQaByUWfWKrGLnEqYtpDde5FZEYKRv6td6N
# ZH7m5JOiCfEK6gun3luq7ckvx5zIXjr5VKhp+S0Aai3ZR/eqbBZ0wcUF3DOYlqVs
# LiPT0jWompwkfSnxa3fjNHD+FKvd/7EMQM/wY0vZyIObto3QYrLru6COAyY9cC/s
# Dj+R4K4392w1LWdo3KrNzkCFMAX6j/bWMIIEuTCCA6GgAwIBAgICAwUwDQYJKoZI
# hvcNAQELBQAwWzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVu
# dDEMMAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFjAUBgNVBAMTDURvRCBSb290
# IENBIDMwHhcNMTkwNDAyMTMzODMyWhcNMjUwNDAyMTMzODMyWjBaMQswCQYDVQQG
# EwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAK
# BgNVBAsTA1BLSTEVMBMGA1UEAxMMRE9EIElEIENBLTU5MIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAzBeEny3BCletEU01Vz8kRy8cD2OWvbtwMTyunFaS
# hu+kIk6g5VRsnvbhK3Ho61MBmlGJc1pLSONGBhpbpyr2l2eONAzmi8c8917V7Bpn
# JZvYj66qGRmY4FXX6UZQ6GdALKKedJKrMQfU8LmcBJ/LGcJ0F4635QocGs9UoFS5
# hLgVyflDTC/6x8EPbi/JXk6N6iod5JIAxNp6qW/5ZBvhiuMo19oYX5LuUy9B6W7c
# A0cRygvYcwKKYK+cIdBoxAj34yw2HJI8RQt490QPGClZhz0WYFuNSnUJgTHsdh2V
# NEn2AEe2zYhPFNlCu3gSmOSp5vxpZWbMIQ8cTv4pRWG47wIDAQABo4IBhjCCAYIw
# HwYDVR0jBBgwFoAUbIqUonexgHIdgXoWqvLczmbuRcAwHQYDVR0OBBYEFHUJphUT
# roc8+nOUAPLw9Xm5snIUMA4GA1UdDwEB/wQEAwIBhjBnBgNVHSAEYDBeMAsGCWCG
# SAFlAgELJDALBglghkgBZQIBCycwCwYJYIZIAWUCAQsqMAsGCWCGSAFlAgELOzAM
# BgpghkgBZQMCAQMNMAwGCmCGSAFlAwIBAxEwDAYKYIZIAWUDAgEDJzASBgNVHRMB
# Af8ECDAGAQH/AgEAMAwGA1UdJAQFMAOAAQAwNwYDVR0fBDAwLjAsoCqgKIYmaHR0
# cDovL2NybC5kaXNhLm1pbC9jcmwvRE9EUk9PVENBMy5jcmwwbAYIKwYBBQUHAQEE
# YDBeMDoGCCsGAQUFBzAChi5odHRwOi8vY3JsLmRpc2EubWlsL2lzc3VlZHRvL0RP
# RFJPT1RDQTNfSVQucDdjMCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcC5kaXNhLm1p
# bDANBgkqhkiG9w0BAQsFAAOCAQEAOQUb0g6nPvWoc1cJ5gkhxSyGA3bQKu8HnKbg
# +vvMpMFEwo2p30RdYHGvA/3GGtrlhxBqAcOqeYF5TcXZ4+Fa9CbKE/AgloCuTjEY
# t2/0iaSvdw7y9Vqk7jyT9H1lFIAQHHN3TEwN1nr7HEWVkkg41GXFxU01UHfR7vgq
# TTz+3zZL2iCqADVDspna0W5pF6yMla6gn4u0TmWu2SeqBpctvdcfSFXkzQBZGT1a
# D/W2Fv00KwoQgB2l2eiVk56mEjN/MeI5Kp4n57mpREsHutP4XnLQ01ZN2qgn+844
# JRrzPQ0pazPYiSl4PeI2FUItErA6Ob/DPF0ba2y3k4dFkUTApzGCAhQwggIQAgEB
# MGIwWjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoG
# A1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFTATBgNVBAMTDERPRCBJRCBDQS01OQIE
# AwIE1zANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAA
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCsM+ZqBJVHTXHI5WdcEhWT614Pce0y
# 8UgIGOnd2Lzc4jANBgkqhkiG9w0BAQEFAASCAQCXV6D+2JF6jq2t2+GBRrsqOwR2
# amNoyPvDO0SBFZYLTEIU9W0dhuazQeOpPfTHrpOkhYKVCPjHTwAFC2KHyVtKO8Rz
# htGSA9A1ppGCRa2XpgZBGH7aQ4mwcWuBET2kmBFP/nRR+tRmGG9zS5odjWy49CH8
# h0kfMr9tt36u4I9YluL2ZX11nPzEY19tUipECD6VPwxEHhXNoqjOCOEEL9qZhD57
# kY0K2ZhL9L0rkxXM6nrCG8g8HaR6oEIjsua4cwab92/aQDxs84b9P6QLxi8UJ0HJ
# b9GuZVwAWTliAqMRxKunBvj8W3c3xIsN5XL/dzXcjM1fs8xpoeHYgW3P8GnY
# SIG # End signature block
