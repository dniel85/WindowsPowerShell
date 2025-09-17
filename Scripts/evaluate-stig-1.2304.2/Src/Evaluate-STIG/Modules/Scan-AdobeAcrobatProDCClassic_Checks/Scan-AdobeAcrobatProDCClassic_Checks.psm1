##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Adobe Acrobat Professional DC Classic Track
# Version:  V2R1
# Class:    UNCLASSIFIED
# Updated:  4/25/2023
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V213093 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213093
        STIG ID    : AADC-CL-000205
        Rule ID    : SV-213093r557504_rule
        CCI ID     : CCI-001695, CCI-002530
        Rule Name  : SRG-APP-000112
        Rule Title : Adobe Acrobat Pro DC Classic Enhanced Security for standalone mode must be enabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bEnhancedSecurityStandalone"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Enable Enhanced Security Standalone"  # GPO setting name identified in STIG
        $SettingState = "Enabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213094 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213094
        STIG ID    : AADC-CL-000210
        Rule ID    : SV-213094r557504_rule
        CCI ID     : CCI-001695, CCI-002530
        Rule Name  : SRG-APP-000112
        Rule Title : Adobe Acrobat Pro DC Classic Enhanced Security for browser mode must be enabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bEnhancedSecurityInBrowser"  # Value name identified in STIG
        $RegistryValue = @(1)  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Enable Enhanced Security In Browser"  # GPO setting name identified in STIG
        $SettingState = "Enabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213095 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213095
        STIG ID    : AADC-CL-000275
        Rule ID    : SV-213095r557504_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Acrobat Pro DC Classic PDF file attachments must be blocked.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "iFileAttachmentPerms"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Allow opening of non-PDF file attachments with external applications"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213096 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213096
        STIG ID    : AADC-CL-000280
        Rule ID    : SV-213096r557504_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Acrobat Pro DC Classic access to unknown websites must be restricted.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown\cDefaultLaunchURLPerms\"  # Registry path identified in STIG
        $RegistryValueName = "iUnknownURLPerms"  # Value name identified in STIG
        $RegistryValue = @("3")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Access to unknown websites"  # GPO setting name identified in STIG
        $SettingState = "Enabled with Block access"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213097 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213097
        STIG ID    : AADC-CL-000285
        Rule ID    : SV-213097r557504_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Acrobat Pro DC Classic access to websites must be blocked.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown\cDefaultLaunchURLPerms\"  # Registry path identified in STIG
        $RegistryValueName = "iURLPerms"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Access to websites"  # GPO setting name identified in STIG
        $SettingState = "Enabled with Block PDF files access to all web sites"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213098 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213098
        STIG ID    : AADC-CL-000290
        Rule ID    : SV-213098r557504_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Acrobat Pro DC Classic must be configured to block Flash Content.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bEnableFlash"  # Value name identified in STIG
        $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Enable Flash"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213099 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213099
        STIG ID    : AADC-CL-000295
        Rule ID    : SV-213099r557504_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : The Adobe Acrobat Pro DC Classic Send and Track plugin for Outlook must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown\cCloud"  # Registry path identified in STIG
        $RegistryValueName = "bAdobeSendPluginToggle"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Send and Track plugin"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213100 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213100
        STIG ID    : AADC-CL-000840
        Rule ID    : SV-213100r557504_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380
        Rule Title : Adobe Acrobat Pro DC Classic privileged file and folder locations must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bDisableTrustedFolders"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Privileged folder locations"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213102 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213102
        STIG ID    : AADC-CL-000990
        Rule ID    : SV-213102r557504_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427
        Rule Title : Adobe Acrobat Pro DC Classic periodic downloading of Adobe European certificates must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\Security\cDigSig\cEUTLDownload"  # User's loaded hive to perform check
        $RegistryPath = "HKCU:\Software\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\Security\cDigSig\cEUTLDownload"  # Registry path identified in STIG
        $RegistryValueName = "bLoadSettingsFromURL"  # Value name identified in STIG
        $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Load trusted certificates from an Adobe EUTL server"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213103 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213103
        STIG ID    : AADC-CL-001010
        Rule ID    : SV-213103r557504_rule
        CCI ID     : CCI-002530
        Rule Name  : SRG-APP-000431
        Rule Title : Adobe Acrobat Pro DC Classic Protected Mode must be enabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bProtectedMode"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Protected Mode"  # GPO setting name identified in STIG
        $SettingState = "Enabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213104 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213104
        STIG ID    : AADC-CL-001015
        Rule ID    : SV-213104r557504_rule
        CCI ID     : CCI-002530
        Rule Name  : SRG-APP-000431
        Rule Title : Adobe Acrobat Pro DC Classic Protected View must be enabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "iProtectedView"  # Value name identified in STIG
        $RegistryValue = @("2")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Protected View"  # GPO setting name identified in STIG
        $SettingState = "Enabled with 'All files'"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213105 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213105
        STIG ID    : AADC-CL-001075
        Rule ID    : SV-213105r557504_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : Unsupported versions of Adobe Acrobat Pro DC Classic must be uninstalled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersions = @("2015", "2017", "2020")
    $EoSDates = New-Object System.Collections.Generic.List[System.Object]
    ForEach ($Version in $ClassicVersions) {
        Switch ($Version) {
            "2015" {
                $NewObj = [PSCustomObject]@{
                    Version = $Version
                    EoS     = (Get-Date -Date 7/7/2020)
                }
            }
            "2017" {
                $NewObj = [PSCustomObject]@{
                    Version = $Version
                    EoS     = (Get-Date -Date 6/6/2022)
                }
            }
            "2020" {
                $NewObj = [PSCustomObject]@{
                    Version = $Version
                    EoS     = (Get-Date -Date 6/1/2025)
                }
            }
        }
        $EoSDates.Add($NewObj)
    }

    $Installs = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    $FindingDetails += "Refer to https://helpx.adobe.com/support/programs/eol-matrix.html for Adobe support periods." | Out-String
    $FindingDetails += "" | Out-String
    ForEach ($Item in $Installs) {
        If ((Get-Date) -gt ($EoSDates | Where-Object Version -EQ $Item.Version).EoS) {
            $Compliant = $false
            $EoSMsg = "Support ended on $(Get-Date ($EoSDates | Where-Object Version -EQ $Item.Version).EoS -Format MM/dd/yyyy)"
        }
        Else {
            $EoSMsg = "Support will end on $(Get-Date ($EoSDates | Where-Object Version -EQ $Item.Version).EoS -Format MM/dd/yyyy)"
        }
        $FindingDetails += "Name:`t`t`t$($Item.Name)" | Out-String
        $FindingDetails += "Version:`t`t`t$($Item.Version)" | Out-String
        $FindingDetails += "Track:`t`t`t$($Item.Track)" | Out-String
        $FindingDetails += "DisplayVersion:`t$($Item.DisplayVersion)" | Out-String
        $FindingDetails += "Architecture:`t`t$($Item.Architecture)" | Out-String
        $FindingDetails += "Support:`t`t`t$($EoSMsg)" | Out-String
        $FindingDetails += "" | Out-String
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
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

Function Get-V213106 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213106
        STIG ID    : AADC-CL-001280
        Rule ID    : SV-213106r557504_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133
        Rule Title : Adobe Acrobat Pro DC Classic Default Handler changes must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bDisablePDFHandlerSwitching"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Disable PDF handler switching"  # GPO setting name identified in STIG
        $SettingState = "Enabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213107 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213107
        STIG ID    : AADC-CL-001285
        Rule ID    : SV-213107r557504_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Acrobat Pro DC Classic must disable the ability to store files on Acrobat.com.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown\cCloud"  # Registry path identified in STIG
        $RegistryValueName = "bDisableADCFileStore"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Store files on Adobe.com"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213108 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213108
        STIG ID    : AADC-CL-001290
        Rule ID    : SV-213108r557504_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Acrobat Pro DC Classic Cloud Synchronization must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown\cServices"  # Registry path identified in STIG
        $RegistryValueName = "bTogglePrefsSync"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Cloud Synchronization"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213109 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213109
        STIG ID    : AADC-CL-001295
        Rule ID    : SV-213109r557504_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Acrobat Pro DC Classic Repair Installation must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPathArr = @("HKLM:\SOFTWARE\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\Installer", "HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\Installer")  # Registry path identified in STIG
        $RegistryValueName = "DisableMaintenance"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value(s) expected in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        ForEach ($RegistryPath in $RegistryPathArr) {
            If ($TempUserHivePath) {
                $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
                $FindingDetails += "" | Out-String
                $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
            }
            Else {
                $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
            }

            If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
                $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
                $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
            }
            Else {
                $RegistryResultValue = $RegistryResult.Value
            }

            If ($RegistryResult.Type -eq "(NotFound)") {
                If ($SettingNotConfiguredAllowed -eq $true) {
                    $Status = "NotAFinding"
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                    $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
                }
                Else {
                    $Status = "Open"
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                    $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
                }
            }
            Else {
                If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                    $Status = "NotAFinding"
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                    $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $Status = "Open"
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                    $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                    If ($RegistryResult.Value -in $RegistryValue) {
                        $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                    }
                    If ($RegistryResult.Type -eq $RegistryType) {
                        $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
                    }
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

Function Get-V213110 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213110
        STIG ID    : AADC-CL-001300
        Rule ID    : SV-213110r557504_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Acrobat Pro DC Classic third-party web connectors must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown\cServices"  # Registry path identified in STIG
        $RegistryValueName = "bToggleWebConnectors"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Third-party web connectors"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213111 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213111
        STIG ID    : AADC-CL-001305
        Rule ID    : SV-213111r557504_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Acrobat Pro DC Classic Webmail must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown\cWebmailProfiles"  # Registry path identified in STIG
        $RegistryValueName = "bDisableWebmail"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "WebMail"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213112 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213112
        STIG ID    : AADC-CL-001310
        Rule ID    : SV-213112r557504_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : The Adobe Acrobat Pro DC Classic Welcome Screen must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown\cWelcomeScreen"  # Registry path identified in STIG
        $RegistryValueName = "bShowWelcomeScreen"  # Value name identified in STIG
        $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Welcome Screen"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213113 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213113
        STIG ID    : AADC-CL-001315
        Rule ID    : SV-213113r557504_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Acrobat Pro DC Classic SharePoint and Office365 access must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cSharePoint"  # Registry path identified in STIG
        $RegistryValueName = "bDisableSharePointFeatures"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "SharePoint and Office 365 access"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213114 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213114
        STIG ID    : AADC-CL-001320
        Rule ID    : SV-213114r557504_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427
        Rule Title : Adobe Acrobat Pro DC Classic Periodic downloading of Adobe certificates must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\Security\cDigSig\cAdobeDownload"  # User's loaded hive to perform check
        $RegistryPath = "HKCU:\Software\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\Security\cDigSig\cAdobeDownload"  # Registry path identified in STIG
        $RegistryValueName = "bLoadSettingsFromURL"  # Value name identified in STIG
        $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Load trusted certificates from an Adobe AATL server"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213115 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213115
        STIG ID    : AADC-CL-001325
        Rule ID    : SV-213115r557504_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380
        Rule Title : Adobe Acrobat Pro DC Classic privileged host locations must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bDisableTrustedSites"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Privileged host locations"  # GPO setting name identified in STIG
        $SettingState = "Disabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "$SettingName is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V220324 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220324
        STIG ID    : AADC-CL-000955
        Rule ID    : SV-220324r557504_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000416
        Rule Title : Adobe Acrobat Pro DC Classic FIPS mode must be enabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Acrobat*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Acrobat Classic version."
    }
    Else {
        $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\AVGeneral"  # User's loaded hive to perform check
        $RegistryPath = "HKCU:\Software\Adobe\Adobe Acrobat\$($ClassicVersion[0].Version)\AVGeneral"  # Registry path identified in STIG
        $RegistryValueName = "bFIPSMode"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Enable FIPS"  # GPO setting name identified in STIG
        $SettingState = "Enabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA+Y5P8/UCreNdR
# uSgID6qy84sm0t5dXLh7QxXGMgJDL6CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD2dvB6tQvEwtOR1BKntfHYKcvjt/mD
# sVJ+zeSEmEkcjTANBgkqhkiG9w0BAQEFAASCAQDZrCO3nwc2HgP8pIwE6mYOvqPH
# Ht4K7lyN9t3lK6FSACCTIPEBn+P7ltyXi+att+8lJGUMcORhRKqf242UBjs/z3PP
# 3pHSMtniRKDLc1BZKL1H19D3YAyhamdtwb/W4+JYkYCT0+9Rl/j1EE+wyiy2f4Ei
# RZmET3c2tEJeT4It694tuZJl847i+aj0hXmhqhNZHLPeZzHbHls5lhxO/VJ1AoyG
# v6SvC8jOoawcYiBeNEHKrpGA2BB3Hwa1yosfJhI4iKQYU6d2qPXvfku/aoLpN0+W
# 0LBnulqrbdWiiDQvSOi6X2fmo00x9tzKL4WBSxHpw9n4PAB1IBePPfpCNFIM
# SIG # End signature block
