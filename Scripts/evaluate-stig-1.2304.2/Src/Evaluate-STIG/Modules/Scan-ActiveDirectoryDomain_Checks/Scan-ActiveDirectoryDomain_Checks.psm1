##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Active Directory Domain
# Version:  V3R3
# Class:    UNCLASSIFIED
# Updated:  5/9/2023
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-TrustAttributes {
    $TrustAttributes = @{
        1  = "Non-Transitive";
        2  = "Uplevel clients only (Windows 2000 or newer)";
        4  = "Quarantined Domain";
        8  = "Forest Trust";
        16 = "Cross-Organizational Trust (Selective Authorization)";
        32 = "Intra-Forest Trust";
        64 = "SID History Enabled"
    }
    Return $TrustAttributes
}

Function Get-V243466 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243466
        STIG ID    : AD.0001
        Rule ID    : SV-243466r723433_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Membership to the Enterprise Admins group must be restricted to accounts used only to manage the Active Directory Forest.
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
    $Groups = @("Enterprise Admins")

    ForEach ($Group in $Groups) {
        Try {
            If (Get-ADGroup -Identity $Group) {
                $Exists = $true
            }
        }
        Catch {
            $Exists = $false
        }
        If ($Exists) {
            $ReturnedUsers = Get-ADGroupMember -identity $Group -Recursive | Select-Object Name, distinguishedName | Sort-Object Name -Unique
            If (($ReturnedUsers | Measure-Object).Count -eq 0) {
                $Status = "NotAFinding"
                $FindingDetails += "No Users are in the '$($Group)' Group" | Out-String
            }
            Else {
                $FindingDetails += "Members of '$($Group)'" | Out-String
                $FindingDetails += "=========================" | Out-String
                ForEach ($User in $ReturnedUsers) {
                    $FindingDetails += "Name:`t`t`t`t$($User.name)" | Out-String
                    $FindingDetails += "SamAccountName:`t`t$($User.SamAccountName)" | Out-String
                    $FindingDetails += "DistinguishedName:`t$($User.distinguishedName)" | Out-String
                    $FindingDetails += "" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "The group '$($Group)' does not exist within this domain." | Out-String
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

Function Get-V243467 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243467
        STIG ID    : AD.0002
        Rule ID    : SV-243467r723436_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Membership to the Domain Admins group must be restricted to accounts used only to manage the Active Directory domain and domain controllers.
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
    $Groups = @("Domain Admins")

    ForEach ($Group in $Groups) {
        $ReturnedUsers = Get-ADGroupMember -identity $Group -Recursive | Select-Object name, SamAccountName, distinguishedName | Sort-Object Name -Unique
        If (($ReturnedUsers | Measure-Object).Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "No Users are in the '$($Group)' Group" | Out-String
        }
        Else {
            $FindingDetails += "Members of '$($Group)'" | Out-String
            $FindingDetails += "=========================" | Out-String
            ForEach ($User in $ReturnedUsers) {
                $FindingDetails += "Name:`t`t`t`t$($User.name)" | Out-String
                $FindingDetails += "SamAccountName:`t`t$($User.SamAccountName)" | Out-String
                $FindingDetails += "DistinguishedName:`t$($User.distinguishedName)" | Out-String
                $FindingDetails += "" | Out-String
            }
            $FindingDetails += "" | Out-String
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

Function Get-V243471 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243471
        STIG ID    : AD.0008
        Rule ID    : SV-243471r854327_rule
        CCI ID     : CCI-001941
        Rule Name  : SRG-OS-000112
        Rule Title : Local administrator accounts on domain systems must not share the same password.
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
    $SchemaPath = (Get-ADRootDSE).schemaNamingContext
    If (-Not(Get-ADObject -SearchBase $SchemaPath -Filter 'name -eq "ms-Mcs-AdmPwd"')) {
        $FindingDetails += "It appears that the schema has not been extended for Local Administrator Password Solution (LAPS) as 'ms-Mcs-AdmPwd' is not a registered attribute." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Ensure unique passwords are set for all local administrator accounts on domain systems." | Out-String
    }
    Else {
        $NoAdmPwd = Get-ADComputer -Filter * -Properties OperatingSystem, ms-Mcs-AdmPwd | Where-Object {($_.Enabled -eq $true -and $_.Operatingsystem -like "*Windows*" -and $_.DistinguishedName -notlike "*OU=Domain Controllers*" -and $null -eq $_.'ms-Mcs-AdmPwd')} | Select-Object Name, DistinguishedName, OperatingSystem
        If (-Not($NoAdmPwd)) {
            $Status = "NotAFinding"
            $FindingDetails += "All enabled Windows computer objects have LAPS passwords recorded." | Out-String
        }
        Else {
            $FindingDetails += "$(($NoAdmPwd | Measure-Object).Count) computer objects found with no LAPS password recorded:" | Out-String
            $FindingDetails += "=============================================" | Out-String
            ForEach ($Item in $NoAdmPwd) {
                $FindingDetails += $Item.Name | Out-String
                # Stop processing to reduce scan time
                If (($FindingDetails | Measure-Object -Character).Characters -ge 38000) {
                    Break
                }
            }
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

Function Get-V243473 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243473
        STIG ID    : AD.0013
        Rule ID    : SV-243473r723565_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Separate domain accounts must be used to manage public facing servers from any domain accounts used to manage internal servers.
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
    $Members = ([ADSI]"WinNT://./Administrators").psbase.Invoke('Members') | ForEach-Object { ([ADSI]$_).InvokeGet('AdsPath') } | Sort-Object
    $FindingDetails += "The following are members of the local Administrators group:" | Out-String
    $FindingDetails += "-------------------------------------------------------------" | Out-String
    ForEach ($Member in $Members) {
        If ($Member -match "WinNT://$env:COMPUTERNAME/") {
            $FindingDetails += $Member -replace "WinNT://$env:COMPUTERNAME/", "" | Out-String
        }
        Else {
            $FindingDetails += $Member -replace "WinNT://", "" -replace "/", "\" | Out-String
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

Function Get-V243476 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243476
        STIG ID    : AD.0016
        Rule ID    : SV-243476r857176_rule
        CCI ID     : CCI-000199
        Rule Name  : SRG-OS-000076
        Rule Title : All accounts, privileged and unprivileged, that require smart cards must have the underlying NT hash rotated at least every 60 days.
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
    $DomainLevel = (Get-ADDomain).DomainMode
    $RollingNTLMSecrets = (Get-ADDomain).PublicKeyRequiredPasswordRolling

    $FindingDetails += "Domain Level:`t$($DomainLevel)" | Out-String
    $FindingDetails += "" | Out-String
    If ($DomainLevel -eq "Windows2016Domain" -or $DomainLevel -eq "Windows2019Domain") {
        $FindingDetails += "Rolling of expiring NTLM Secrets:`t$($RollingNTLMSecrets)" | Out-String
        If ($RollingNTLMSecrets -eq $true) {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "Domain functional level does not support rolling of expiring NTLM secrets.  Verify the organization rotates the NT hash for smart card-enforced accounts every 60 days." | Out-String
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

Function Get-V243477 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243477
        STIG ID    : AD.0017
        Rule ID    : SV-243477r723466_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : User accounts with domain level administrative privileges must be members of the Protected Users group in domains with a domain functional level of Windows 2012 R2 or higher.
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
    $DomainLevel = (Get-ADDomain).DomainMode
    $AcceptedDomainLevels = @("Windows2012R2Domain", "Windows2016Domain", "Windows2019Domain")
    $Groups = @("Enterprise Admins", "Domain Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators")
    $Compliant = $True

    If ($DomainLevel -in $AcceptedDomainLevels) {
        $ProtectedUsers = Get-ADGroupMember -Identity "Protected Users" -Recursive | Sort-Object Name -Unique

        ForEach ($Group in $Groups) {
            $GroupMembers += Get-ADGroupMember -Identity $Group -Recursive | Sort-Object Name -Unique
        }
        $GroupMembers = $GroupMembers | Sort-Object Name -Unique
        $MissingUsers = New-Object System.Collections.Generic.List[System.Object]

        ForEach ($Member in $GroupMembers) {
            If ($Member -notin $ProtectedUsers) {
                $Obj = [PSCustomObject]@{
                    Name              = $Member.name
                    SamAccountName    = $Member.SamAccountName
                    DistinguishedName = $Member.distinguishedName
                }
                $MissingUsers.Add($Obj)
            }
        }

        If (($MissingUsers | Measure-Object).Count -ge 1) {
            If (($MissingUsers | Measure-Object).Count -eq 1) {
                $FindingDetails += "Only one account is not in 'Protected Users'.  This is acceptable by STIG for availability." | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $False
                $FindingDetails += "Multiple accounts are not in 'Protected Users'.  STIG only allows for one accout to be excluded for availability." | Out-String
                $FindingDetails += "" | Out-String
            }

            $FindingDetails += "Users Missing From 'Protected Users' Group" | Out-String
            $FindingDetails += "============================================" | Out-String
            ForEach ($User in $MissingUsers) {
                $FindingDetails += "Name:`t`t`t`t$($User.Name)" | Out-String
                $FindingDetails += "SamAccountName:`t`t$($User.SamAccountName)" | Out-String
                $FindingDetails += "DistinguishedName:`t$($User.DistinguishedName)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        Else {
            $FindingDetails += "No users were missing from the 'Protected Users' group" | Out-String
        }

        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
    }
    Else {
        $Status = "Not_Applicable"
        $FindingDetails += "Domain Level: $($DomainLevel)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "The domain functional level is not Windows 2012 R2 or higher, so this check is Not Applicable" | Out-String
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

Function Get-V243478 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243478
        STIG ID    : AD.0018
        Rule ID    : SV-243478r723469_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Domain-joined systems (excluding domain controllers) must not be configured for unconstrained delegation.
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
    $Computers = Get-ADComputer -Filter {(TrustedForDelegation -eq $True) -and (PrimaryGroupID -eq 515)} -Properties Name, DistinguishedName, Enabled, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalName, Description, PrimaryGroupID

    If (($Computers | Measure-Object).Count -gt 0) {
        $Status = "Open"
        ForEach ($Computer in $Computers) {
            $FindingDetails += "Name:`t`t`t`t`t`t$($Computer.Name)" | Out-String
            $FindingDetails += "Enabled:`t`t`t`t`t`t$($Computer.Enabled)" | Out-String
            $FindingDetails += "Trusted For Delegation:`t`t`t$($Computer.TrustedForDelegation)" | Out-String
            $FindingDetails += "Trusted To Auth For Delegation:`t$($Computer.TrustedToAuthForDelegation)" | Out-String
            ForEach ($SPN in $Computer.ServicePrincipalName) {
                $FindingDetails += "Service Principal Name:`t`t`t$($SPN)" | Out-String
            }
            $FindingDetails += "Description:`t`t`t`t`t$($Computer.Description)" | Out-String
            $FindingDetails += "PrimaryGroupID:`t`t`t`t$($Computer.PrimaryGroupID)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "No computers are Trusted for Delegation and have a Primary Group ID of '515'" | Out-String
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

Function Get-V243480 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243480
        STIG ID    : AD.0160
        Rule ID    : SV-243480r723563_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : The domain functional level must be at a Windows Server version still supported by Microsoft.
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
    $Regex = "(?:Windows)(\d{4})"
    $DomainFunctionalLevel = (Get-ADDomain).DomainMode
    If ($DomainFunctionalLevel -match $Regex) {
        If ($Matches[1] -lt 2008) {
            $Status = "Open"
            $FindingDetails += "The domain function level is NOT 2008 or newer" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "The domain function level is 2008 or newer" | Out-String
            $FindingDetails += "" | Out-String
        }
        $FindingDetails += "Domain Level: $($DomainFunctionalLevel)" | Out-String
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

Function Get-V243481 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243481
        STIG ID    : AD.0170
        Rule ID    : SV-243481r890559_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Access to need-to-know information must be restricted to an authorized community of interest.
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
    $DomainTrusts = Get-ADTrust -Filter *

    If (($DomainTrusts | Measure-Object).Count -eq 0) {
        $Status = "NotAFinding"
        $FindingDetails += "No trusts are configured."
    }
    Else {
        $FindingDetails += "Domain Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $DomainTrusts) {

            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
            }
            $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
            $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
            $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
            $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
            $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
            $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
            $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
            $FindingDetails += "Trust Attributes: "
            If (($Attributes | Measure-Object).Count -gt 1) {
                For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                    If ($i -eq 0) {
                        $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                    }
                    Else {
                        $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                    }
                }
            }
            Else {
                $FindingDetails += "`t`t`t$($Attributes)" | Out-String
            }
            $FindingDetails += "" | Out-String
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

Function Get-V243482 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243482
        STIG ID    : AD.0180
        Rule ID    : SV-243482r723481_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Interconnections between DoD directory services of different classification levels must use a cross-domain solution that is approved for use with inter-classification trusts.
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
    $DomainTrusts = Get-ADTrust -Filter *

    If (($DomainTrusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $FindingDetails += "Domain Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $DomainTrusts) {
            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
            }
            $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
            $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
            $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
            $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
            $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
            $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
            $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
            $FindingDetails += "Trust Attributes: "
            If (($Attributes | Measure-Object).Count -gt 1) {
                For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                    If ($i -eq 0) {
                        $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                    }
                    Else {
                        $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                    }
                }
            }
            Else {
                $FindingDetails += "`t`t`t$($Attributes)" | Out-String
            }
            $FindingDetails += "" | Out-String
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

Function Get-V243483 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243483
        STIG ID    : AD.0181
        Rule ID    : SV-243483r723559_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : A controlled interface must have interconnections among DoD information systems operating between DoD and non-DoD systems or networks.
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
    $DomainTrusts = Get-ADTrust -Filter *

    If (($DomainTrusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $FindingDetails += "Domain Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $DomainTrusts) {
            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
            }
            $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
            $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
            $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
            $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
            $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
            $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
            $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
            $FindingDetails += "Trust Attributes: "
            If (($Attributes | Measure-Object).Count -gt 1) {
                For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                    If ($i -eq 0) {
                        $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                    }
                    Else {
                        $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                    }
                }
            }
            Else {
                $FindingDetails += "`t`t`t$($Attributes)" | Out-String
            }
            $FindingDetails += "" | Out-String
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

Function Get-V243484 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243484
        STIG ID    : AD.0190
        Rule ID    : SV-243484r890561_rule
        CCI ID     : CCI-000764
        Rule Name  : SRG-OS-000104
        Rule Title : Security identifiers (SIDs) must be configured to use only authentication data of directly trusted external or forest trust.
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
    $DomainTrusts = Get-ADTrust -Filter *

    If (($DomainTrusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $Compliant = $true
        $BadTrust = @()
        $GoodTrust = @()
        ForEach ($Trust in $DomainTrusts) {
            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                If ($Trust.SIDFIlteringForestAware -eq $false) {
                    $Compliant = $False
                    $BadTrust += $Trust
                }
                Else {
                    $GoodTrust += $Trust
                }
            }
            Else {
                If ($Trust.SIDFilterQuarantined -eq $false) {
                    $Compliant = $false
                    $BadTrust += $Trust
                }
                Else {
                    $GoodTrust += $Trust
                }
            }
        }

        If (($BadTrust | Measure-Object).Count -gt 0) {
            $FindingDetails += "Non-Compliant Domain Trusts" | Out-String
            $FindingDetails += "========================" | Out-String
            ForEach ($Trust in $BadTrust) {
                $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
                If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                    $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
                }
                $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
                $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
                $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
                $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
                $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
                $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
                $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
                $FindingDetails += "Trust Attributes: "
                If (($Attributes | Measure-Object).Count -gt 1) {
                    For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                        If ($i -eq 0) {
                            $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                        }
                        Else {
                            $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                        }
                    }
                }
                Else {
                    $FindingDetails += "`t`t`t$($Attributes)" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }
        If (($GoodTrust | Measure-Object).Count -gt 0) {
            $FindingDetails += "Compliant Domain Trusts" | Out-String
            $FindingDetails += "========================" | Out-String
            ForEach ($Trust in $GoodTrust) {
                $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
                If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                    $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
                }
                $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
                $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
                $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
                $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
                $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
                $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
                $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
                $FindingDetails += "Trust Attributes: "
                If (($Attributes | Measure-Object).Count -gt 1) {
                    For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                        If ($i -eq 0) {
                            $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                        }
                        Else {
                            $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                        }
                    }
                }
                Else {
                    $FindingDetails += "`t`t`t$($Attributes)" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }
        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
        }
        Else {
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

Function Get-V243485 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243485
        STIG ID    : AD.0200
        Rule ID    : SV-243485r723490_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080
        Rule Title : Selective Authentication must be enabled on outgoing forest trusts.
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
    $Trusts = Get-ADTrust -Filter *
    If (($Trusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $Compliant = $true
        $ForestTrusts = @()
        $BadTrust = @()
        $GoodTrust = @()
        ForEach ($Trust in $Trusts) {
            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                $ForestTrusts += $Trust
            }
        }

        If (($ForestTrusts | Measure-Object).Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "No forest trusts are configured." | Out-String
        }
        ElseIf (-Not($ForestTrusts.Direction -eq "Outbound")) {
            $Status = "NotAFinding"
            $FindingDetails += "No outbound forest trusts are configured." | Out-String
        }
        Else {
            ForEach ($Trust in $ForestTrusts) {
                If ($Trust.SelectiveAuthentication -eq $false) {
                    $Compliant = $False
                    $BadTrust += $Trust
                }
                Else {
                    $GoodTrust += $Trust
                }
            }

            If (($BadTrust | Measure-Object).Count -gt 0) {
                $FindingDetails += "Non-Compliant Domain Trusts" | Out-String
                $FindingDetails += "========================" | Out-String

                ForEach ($Trust in $BadTrust) {
                    $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
                    If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                        $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
                    }
                    Else {
                        $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
                    }
                    $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
                    $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
                    $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
                    $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
                    $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
                    $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
                    $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
                    $FindingDetails += "Trust Attributes: "
                    If (($Attributes | Measure-Object).Count -gt 1) {
                        For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                            If ($i -eq 0) {
                                $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                            }
                            Else {
                                $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                            }
                        }
                    }
                    Else {
                        $FindingDetails += "`t`t`t$($Attributes)" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }
            }

            If (($GoodTrust | Measure-Object).Count -gt 0) {
                $FindingDetails += "Compliant Domain Trusts" | Out-String
                $FindingDetails += "========================" | Out-String
                ForEach ($Trust in $GoodTrust) {
                    $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
                    If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                        $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
                    }
                    Else {
                        $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
                    }
                    $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
                    $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
                    $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
                    $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
                    $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
                    $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
                    $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
                    $FindingDetails += "Trust Attributes: "
                    If (($Attributes | Measure-Object).Count -gt 1) {
                        For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                            If ($i -eq 0) {
                                $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                            }
                            Else {
                                $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                            }
                        }
                    }
                    Else {
                        $FindingDetails += "`t`t`t$($Attributes)" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }
            }
            If ($Compliant -eq $true) {
                $Status = "NotAFinding"
            }
            Else {
                $Status = "Open"
            }
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

Function Get-V243486 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243486
        STIG ID    : AD.0220
        Rule ID    : SV-243486r723493_rule
        CCI ID     : CCI-000804
        Rule Name  : SRG-OS-000121
        Rule Title : The Anonymous Logon and Everyone groups must not be members of the Pre-Windows 2000 Compatible Access group.
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
    $MemberGroup = "Pre-Windows 2000 Compatible Access"
    $Users = Get-ADGroupMember -identity $MemberGroup -Recursive | Where-Object {$_.Name -eq "Everyone" -or $_.Name -eq "Anonymous Logon"}

    If (($Users | Measure-Object).Count -gt 0) {
        $Status = "Open"
        If ($Users -contains "Anonymous Logon") {
            $FindingDetails += "'Anonymous Logon' is a member of '$($MemberGroup)'" | Out-String
        }
        Else {
            $FindingDetails += "'Everyone' is a member of '$($MemberGroup)'" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Both 'Anonymous Logon' and 'Everyone' are not members of '$MemberGroup'."
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

Function Get-V243487 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243487
        STIG ID    : AD.0240
        Rule ID    : SV-243487r723496_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Membership in the Group Policy Creator Owners and Incoming Forest Trust Builders groups must be limited.
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
    $Compliant = $true
    $Groups = @("Incoming Forest Trust Builders", "Group Policy Creator Owners")

    ForEach ($Group in $Groups) {
        $ReturnedUsers = Get-ADGroupMember -Identity $Group -Recursive | Select-Object name, SamAccountName, distinguishedName | Sort-Object SamAccountName -Unique
        If (($ReturnedUsers | Measure-Object).Count -eq 0) {
            $FindingDetails += "No Users are in the '$($Group)' Group" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "Members of '$($Group)'" | Out-String
            $FindingDetails += "=========================" | Out-String
            ForEach ($User in $ReturnedUsers) {
                $FindingDetails += $User.Name | Out-String
            }
        }
        $FindingDetails += "" | Out-String
    }

    If ($Compliant -eq $true) {
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

Function Get-V243489 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243489
        STIG ID    : AD.0270
        Rule ID    : SV-243489r723564_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Read-only Domain Controller (RODC) architecture and configuration must comply with directory services requirements.
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
    $DomainName = (Get-ADDomain).DNSRoot
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainName | Select-Object HostName, OperatingSystem, IPv4Address, IPv6Address, Forest, Site, IsGlobalCatalog, IsReadOnly

    If ($AllDCs.IsReadOnly -eq $true) {
        $FindingDetails += "Read-only domain controllers (RODC):"
        $FindingDetails += "====================================" | Out-String
        ForEach ($DC in ($AllDCs | Where-Object IsReadOnly -EQ $true)) {
            $FindingDetails += "Hostname:`t`t$($DC.HostName)" | Out-String
            $FindingDetails += "OperatingSystem:`t$($DC.OperatingSystem)" | Out-String
            $FindingDetails += "IPv4Address:`t`t$($DC.IPv4Address)" | Out-String
            $FindingDetails += "IPv6Address:`t`t$($DC.IPv6Address)" | Out-String
            $FindingDetails += "Forest:`t`t`t$($DC.Forest)" | Out-String
            $FindingDetails += "Site:`t`t`t`t$($DC.Site)" | Out-String
            $FindingDetails += "IsGlobalCatalog:`t$($DC.IsGlobalCatalog)" | Out-String
            $FindingDetails += "IsReadOnly:`t`t$($DC.IsReadOnly)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "No read-only domain controllers (RODC) exist in the domain." | Out-String
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

Function Get-V243490 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243490
        STIG ID    : AD.AU.0001
        Rule ID    : SV-243490r723505_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Usage of administrative accounts must be monitored for suspicious and anomalous activity.
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
    $AuditCategorys = @("Logon", "User Account Management", "Account Lockout", "Security Group Management") #As specified in the STIG
    #$SettingState = "Success" #As specified in the STIG
    ForEach ($AuditCategory in $AuditCategorys) {
        Try {

            $Policy = (auditpol /get /subcategory:$AuditCategory | Where-Object { $_ -Match "\s$($AuditCategory)" }).Trim() #Returns a string
            If ( $Policy -Match "  [SNF].*$") {
                #Regex to essentially grab the last phrase in the string. Either "Success", "Failure", "Success or Failure", or "No Auditing"
                $Policy = $Matches[0].Trim() #Trim the two spaces before what was matched. '$Policy -Match' returns true/false, '$Matches' is the system variable -Match places anything it finds.
            }
            $Status = "NotAFinding"
            $FindingDetails += "Category:`t`t$($AuditCategory)" | Out-String
            $FindingDetails += "Audit On:`t`t$($Policy)" | Out-String
            $FindingDetails += "" | Out-String

        }
        Catch {
            #If the policy isn't configured as we want, it won't be found and will throw an error.
            $Status = "Open"
            $FindingDetails += "'$($AuditCategory)' is NOT configured to audit." | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Queries of Events" | Out-String
    $FindingDetails += "=====================" | Out-String

    $EventIDs = @("4740", "4728", "4732", "4756", "4624", "4625", "4648")

    ForEach ($EventID in $EventIDs) {
        $ReturnedEvent = Get-WinEvent -ErrorAction SilentlyContinue @{logname = 'system', 'application', 'security'; ID = $EventID} -MaxEvents 1 | Select-Object ContainerLog, ID, LevelDisplayName, Message, TimeCreated
        If ($Null -eq $ReturnedEvent) {
            $FindingDetails += "No event was found for EventID: $($EventID)" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $ReturnedEvent.Message -match "^.*?\." | Out-Null
            $Message = $matches[0]
            $FindingDetails += "Event ID:`t`t`t$($ReturnedEvent.ID)" | Out-String
            $FindingDetails += "Message:`t`t`t$($Message)" | Out-String
            $FindingDetails += "Level:`t`t`t$($ReturnedEvent.LevelDisplayName)" | Out-String
            $FindingDetails += "Container Log:`t`t$($ReturnedEvent.ContainerLog)" | Out-String
            $FindingDetails += "Time Created:`t`t$($ReturnedEvent.TimeCreated)" | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V243491 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243491
        STIG ID    : AD.AU.0002
        Rule ID    : SV-243491r723508_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Systems must be monitored for attempts to use local accounts to log on remotely from other systems.
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
    $AuditCategorys = @("Logon", "Account Lockout") #As specified in the STIG
    #$SettingState = "Success" #As specified in the STIG
    ForEach ($AuditCategory in $AuditCategorys) {
        Try {

            $Policy = (auditpol /get /subcategory:$AuditCategory | Where-Object { $_ -Match "\s$($AuditCategory)" }).Trim() #Returns a string
            If ( $Policy -Match "  [SNF].*$") {
                #Regex to essentially grab the last phrase in the string. Either "Success", "Failure", "Success or Failure", or "No Auditing"
                $Policy = $Matches[0].Trim() #Trim the two spaces before what was matched. '$Policy -Match' returns true/false, '$Matches' is the system variable -Match places anything it finds.
            }
            $Status = "NotAFinding"
            $FindingDetails += "Category:`t`t$($AuditCategory)" | Out-String
            $FindingDetails += "Audit On:`t`t$($Policy)" | Out-String
            $FindingDetails += "" | Out-String

        }
        Catch {
            #If the policy isn't configured as we want, it won't be found and will throw an error.
            $Status = "Open"
            $FindingDetails += "'$($AuditCategory)' is NOT configured to audit." | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Queries of Events" | Out-String
    $FindingDetails += "=====================" | Out-String

    $EventIDs = @("4624", "4625")

    ForEach ($EventID in $EventIDs) {
        $params = @{
            logname                   = 'system', 'security'
            ID                        = $EventID
            LogonType                 = '3'
            AuthenticationPackageName = 'NTLM'
        }
        $ReturnedEvent = Get-WinEvent -ErrorAction SilentlyContinue $params | Select-Object ContainerLog, ID, LevelDisplayName, Message, TimeCreated, Properties | Where-Object {$_.Properties[5].Value -ne "ANONYMOUS LOGON" -and $_.Properties[6].Value -notin $(Get-CimInstance Win32_NTDomain).DomainName | Select-Object -First 1}

        If ($Null -eq $ReturnedEvent) {
            $FindingDetails += "No event was found for EventID: $($EventID)" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $ReturnedEvents[0].Message -match "^.*?\." | Out-Null
            $Message = $matches[0]
            $FindingDetails += "Event ID:`t`t`t$($ReturnedEvent.ID)" | Out-String
            $FindingDetails += "Message:`t`t`t$($Message)" | Out-String
            $FindingDetails += "User:`t`t`t$($ReturnedEvent.Properties[5].Value)" | Out-String
            $FindingDetails += "Domain:`t`t`t$($ReturnedEvent.Properties[6].Value)" | Out-String
            $FindingDetails += "Level:`t`t`t$($ReturnedEvent.LevelDisplayName)" | Out-String
            $FindingDetails += "Container Log:`t`t$($ReturnedEvent.ContainerLog)" | Out-String
            $FindingDetails += "Time Created:`t`t$($ReturnedEvent.TimeCreated)" | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V243492 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243492
        STIG ID    : AD.AU.0003
        Rule ID    : SV-243492r723511_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Systems must be monitored for remote desktop logons.
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
    $AuditCategorys = @("Logon") #As specified in the STIG
    #$SettingState = "Success" #As specified in the STIG
    ForEach ($AuditCategory in $AuditCategorys) {
        Try {

            $Policy = (auditpol /get /subcategory:$AuditCategory | Where-Object { $_ -Match "\s$($AuditCategory)" }).Trim() #Returns a string
            If ( $Policy -Match "  [SNF].*$") {
                #Regex to essentially grab the last phrase in the string. Either "Success", "Failure", "Success or Failure", or "No Auditing"
                $Policy = $Matches[0].Trim() #Trim the two spaces before what was matched. '$Policy -Match' returns true/false, '$Matches' is the system variable -Match places anything it finds.
            }
            $Status = "NotAFinding"
            $FindingDetails += "Category:`t`t$($AuditCategory)" | Out-String
            $FindingDetails += "Audit On:`t`t$($Policy)" | Out-String
            $FindingDetails += "" | Out-String

        }
        Catch {
            #If the policy isn't configured as we want, it won't be found and will throw an error.
            $Status = "Open"
            $FindingDetails += "'$($AuditCategory)' is NOT configured to audit." | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Queries of Events" | Out-String
    $FindingDetails += "=====================" | Out-String

    $EventIDs = @("4624")

    ForEach ($EventID in $EventIDs) {

        $ReturnedEvent = Get-WinEvent -ErrorAction SilentlyContinue @{logname = 'system', 'application', 'security'; ID = $EventID; LogonType = '10'; AuthenticationPackageName = 'Negotiate'} | Select-Object -First 1 ContainerLog, ID, LevelDisplayName, Message, TimeCreated, Properties
        If ($Null -eq $ReturnedEvent) {
            $FindingDetails += "No event was found for EventID: $($EventID)" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $ReturnedEvent.Message -match "^.*?\." | Out-Null
            $Message = $matches[0]
            $FindingDetails += "Event ID:`t`t`t$($ReturnedEvent.ID)" | Out-String
            $FindingDetails += "Message:`t`t`t$($Message)" | Out-String
            $FindingDetails += "Logon Type:`t`t`t$($ReturnedEvent.Properties[8].Value)" | Out-String
            $FindingDetails += "Authentication Package Name:`t$($ReturnedEvent.Properties[10].Value)" | Out-String
            $FindingDetails += "Level:`t`t`t`t$($ReturnedEvent.LevelDisplayName)" | Out-String
            $FindingDetails += "Container Log:`t`t`t$($ReturnedEvent.ContainerLog)" | Out-String
            $FindingDetails += "Time Created:`t`t`t$($ReturnedEvent.TimeCreated)" | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V243494 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243494
        STIG ID    : DS00.1120_AD
        Rule ID    : SV-243494r723517_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Each cross-directory authentication configuration must be documented.
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
    $DomainTrusts = Get-ADTrust -Filter *

    If (($DomainTrusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $FindingDetails += "Domain Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $DomainTrusts) {

            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
            }
            $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
            $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
            $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
            $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
            $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
            $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
            $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
            $FindingDetails += "Trust Attributes: "
            If (($Attributes | Measure-Object).Count -gt 1) {
                For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                    If ($i -eq 0) {
                        $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                    }
                    Else {
                        $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                    }
                }
            }
            Else {
                $FindingDetails += "`t`t`t$($Attributes)" | Out-String
            }
            $FindingDetails += "" | Out-String
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

Function Get-V243495 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243495
        STIG ID    : DS00.1140_AD
        Rule ID    : SV-243495r854328_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-OS-000423
        Rule Title : A VPN must be used to protect directory network traffic for directory service implementation spanning enclave boundaries.
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
    $DomainName = (Get-ADDomain).DNSRoot
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainName | Select-Object HostName, OperatingSystem, IPv4Address, IPv6Address, Forest, Site, IsGlobalCatalog, IsReadOnly

    ForEach ($DC in $AllDCs) {
        $FindingDetails += "Hostname:`t`t$($DC.HostName)" | Out-String
        $FindingDetails += "OperatingSystem:`t$($DC.OperatingSystem)" | Out-String
        $FindingDetails += "IPv4Address:`t`t$($DC.IPv4Address)" | Out-String
        $FindingDetails += "IPv6Address:`t`t$($DC.IPv6Address)" | Out-String
        $FindingDetails += "Forest:`t`t`t$($DC.Forest)" | Out-String
        $FindingDetails += "Site:`t`t`t`t$($DC.Site)" | Out-String
        $FindingDetails += "IsGlobalCatalog:`t$($DC.IsGlobalCatalog)" | Out-String
        $FindingDetails += "IsReadOnly:`t`t$($DC.IsReadOnly)" | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V243496 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243496
        STIG ID    : DS00.3200_AD
        Rule ID    : SV-243496r804648_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Accounts from outside directories that are not part of the same organization or are not subject to the same security policies must be removed from all highly privileged groups.
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
    $Compliant = $true
    $Groups = @("Incoming Forest Trust Builders", "Group Policy Creator Owners", "Domain Admins", "Enterprise Admins", "Schema Admins")
    ForEach ($dc in ((Get-CimInstance Win32_ComputerSystem).Domain).ToString().Split(".")) {
        $LdapDomain += ",dc=$($dc)"
    }
    ForEach ($Group in $Groups) {
        $ReturnedUsers = Get-ADGroupMember -Identity $Group -Recursive | Select-Object name, SamAccountName, distinguishedName | Sort-Object Name -Unique
        If (($ReturnedUsers | Measure-Object).Count -eq 0) {
            $FindingDetails += "No Users are in the '$($Group)' Group" | Out-String
        }
        Else {
            If ($ReturnedUsers.DistingishedName -like "*$($LdapDomain)") {
                $Domain = (Get-CimInstance Win32_ComputerSystem).Domain
                $FindingDetails += "Accounts from outside '$($Domain)' exist"
                $Compliant = $false
            }
            $FindingDetails += "Members of '$($Group)'" | Out-String
            $FindingDetails += "=========================" | Out-String
            ForEach ($User in $ReturnedUsers) {
                $FindingDetails += "Name:`t`t`t`t$($User.name)" | Out-String
                $FindingDetails += "SamAccountName:`t`t$($User.SamAccountName)" | Out-String
                $FindingDetails += "DistinguishedName:`t$($User.distinguishedName)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        $FindingDetails += "" | Out-String
    }

    If ($compliant -eq $true) {
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

Function Get-V243497 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243497
        STIG ID    : DS00.3230_AD
        Rule ID    : SV-243497r723526_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Inter-site replication must be enabled and configured to occur at least daily.
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
    $ADSites = Get-ADReplicationSite -Filter * -Properties *
    If (($ADSites | Measure-Object).Count -eq 1) {
        $Status = "Not_Applicable"
        $FindingDetails += "Only one site exists so this requirement is NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Site: $($ADSites.Name)" | Out-String
    }
    Else {
        $Compliant = $true
        $SiteLinks = Get-ADReplicationSiteLink -Filter * -Properties *
        $FindingDetails += "Site Link Replication Frequency" | Out-String
        $FindingDetails += "===============================" | Out-String
        $FindingDetails += "" | Out-String
        ForEach ($SiteLink in $SiteLinks) {
            $FindingDetails += "Name:`t`t$($SiteLink.Name)" | Out-String
            If ($SiteLink.ReplicationFrequencyInMinutes -gt 1440) {
                $Compliant = $false
                $FindingDetails += "Frequency:`t$($SiteLink.ReplicationFrequencyInMinutes) [Expected: 1440 or less]" | Out-String
            }
            Else {
                $FindingDetails += "Frequency:`t$($SiteLink.ReplicationFrequencyInMinutes)" | Out-String
            }

            $TimeSlotsWithoutReplication = 0
            For ($i = 20; $i -lt (($SiteLink.Schedule) | Measure-Object).Count; $i++) {
                #Run through the replication schedule. There are 288 bytes in total, with the first 20 being a header.
                If ($SiteLink.Schedule[$i] -eq 240) {
                    #If the value equals 255, replication is set to happen; if 240, replication will not happen.
                    $TimeSlotsWithoutReplication += 1
                    If ($TimeSlotsWithoutReplication -eq 24) {
                        $Compliant = $false
                        $FindingDetails += "There are 24 hour period(s) with no available replication schedule.  [Finding]" | Out-String
                    }
                }
                Else {
                    $TimeSlotsWithoutReplication = 0
                }
            }
            $FindingDetails += "" | Out-String
        }

        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
        }
        Else {
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

Function Get-V243498 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243498
        STIG ID    : DS00.4140_AD
        Rule ID    : SV-243498r723529_rule
        CCI ID     : CCI-000067
        Rule Name  : SRG-OS-000032
        Rule Title : If a VPN is used in the AD implementation, the traffic must be inspected by the network Intrusion detection system (IDS).
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
    $DomainName = (Get-ADDomain).DNSRoot
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainName | Select-Object HostName, OperatingSystem, IPv4Address, IPv6Address, Forest, Site, IsGlobalCatalog, IsReadOnly

    ForEach ($DC in $AllDCs) {
        $FindingDetails += "Hostname:`t`t$($DC.HostName)" | Out-String
        $FindingDetails += "OperatingSystem:`t$($DC.OperatingSystem)" | Out-String
        $FindingDetails += "IPv4Address:`t`t$($DC.IPv4Address)" | Out-String
        $FindingDetails += "IPv6Address:`t`t$($DC.IPv6Address)" | Out-String
        $FindingDetails += "Forest:`t`t`t$($DC.Forest)" | Out-String
        $FindingDetails += "Site:`t`t`t`t$($DC.Site)" | Out-String
        $FindingDetails += "IsGlobalCatalog:`t$($DC.IsGlobalCatalog)" | Out-String
        $FindingDetails += "IsReadOnly:`t`t$($DC.IsReadOnly)" | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V243500 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243500
        STIG ID    : DS00.6140_AD
        Rule ID    : SV-243500r723535_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Active Directory must be supported by multiple domain controllers where the Risk Management Framework categorization for Availability is moderate or high.
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
    $DomainName = (Get-ADDomain).DNSRoot
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainName | Select-Object HostName, OperatingSystem, IPv4Address, IPv6Address, Forest, Site, IsGlobalCatalog, IsReadOnly

    If (($AllDCs | Measure-Object).Count -eq 1) {
        $FindingDetails += "Only one domain controller exists in the domain.  If Availability categorization is low, mark as NA.  Otherwise, mark as Open." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Multiple domain controllers exist in the domain." | Out-String
        $FindingDetails += "" | Out-String
    }

    ForEach ($DC in $AllDCs) {
        $FindingDetails += "Hostname:`t`t$($DC.HostName)" | Out-String
        $FindingDetails += "OperatingSystem:`t$($DC.OperatingSystem)" | Out-String
        $FindingDetails += "IPv4Address:`t`t$($DC.IPv4Address)" | Out-String
        $FindingDetails += "IPv6Address:`t`t$($DC.IPv6Address)" | Out-String
        $FindingDetails += "Forest:`t`t`t$($DC.Forest)" | Out-String
        $FindingDetails += "Site:`t`t`t`t$($DC.Site)" | Out-String
        $FindingDetails += "IsGlobalCatalog:`t$($DC.IsGlobalCatalog)" | Out-String
        $FindingDetails += "IsReadOnly:`t`t$($DC.IsReadOnly)" | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V243501 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243501
        STIG ID    : DS00.7100_AD
        Rule ID    : SV-243501r723557_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : The impact of INFOCON changes on the cross-directory authentication configuration must be considered and procedures documented.
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
    $DomainTrusts = Get-ADTrust -Filter *

    If (($DomainTrusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $FindingDetails += "Domain Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $DomainTrusts) {

            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
            }
            $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
            $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
            $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
            $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
            $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
            $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
            $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
            $FindingDetails += "Trust Attributes: "
            If (($Attributes | Measure-Object).Count -gt 1) {
                For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                    If ($i -eq 0) {
                        $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                    }
                    Else {
                        $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                    }
                }
            }
            Else {
                $FindingDetails += "`t`t`t$($Attributes)" | Out-String
            }
            $FindingDetails += "" | Out-String
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA1NPg1QhocmIzs
# FWCi1ONmud2JWqIohFTri0+tGhFpQKCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC9MExjD23p+kEu88EIHC2vwlFeSyza
# zFxMeu/hkoDHkTANBgkqhkiG9w0BAQEFAASCAQCKhi0YvuaUfFZt3DhCs6wnoe+k
# me8/px9es0xLwEnuG1K9vR2Ja5tNpQsUPLVQKx/mr/pvjMgApPuUAcOb46qiugnM
# GUhjTSB/ohoctUBwF2CrhulyrQ9VVTa/nQ7BD083XpHywRoMqaCcbNd+5Pz9/7Xd
# cn6QZWH6NTOlids7mwK/bvTikvYTUJIhFsRpyUQeJnZR9cKlTIcoOnUPOsmfIUoI
# zzPw4IdEInswlXn6jKHmJoip4ztNjN5wxl1bjG9RpbXcPpysRMxN9X42h6s1KUP8
# n+gBh8L63NB9fzjJjjVh+Wxjj8//xHPyKSzu0x6PLwTDkMIR/BN5FuJw5Vbm
# SIG # End signature block
