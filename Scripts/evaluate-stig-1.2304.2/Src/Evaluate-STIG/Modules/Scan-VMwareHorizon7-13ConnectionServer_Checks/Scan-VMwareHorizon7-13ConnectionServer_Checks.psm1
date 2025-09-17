##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     VMware Horizon 7.13 Connection Server
# Version:  V1R1
# Class:    UNCLASSIFIED
# Updated:  4/25/2023
# Author:   Navy Standard Integrated Personnel System (NSIPS)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V246882 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246882
        STIG ID    : HRZV-7X-000001
        Rule ID    : SV-246882r768606_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-AS-000001
        Rule Title : The Horizon Connection Server must limit the number of concurrent client sessions.
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
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "maxConnections" # Name of the setting identified in STIG
    $ExpectedValue = @("2000") # Value(s) expected in STIG
    $MaxAllowedValue = "4000" # Maximum value allowed in STIG
    $SettingDescription = "Maximum concurrent client connections" # Short description of the setting
    $FileNotExistAllowed = $true # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $true # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName"))) {
            # But the configuration setting does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
        }
        Else {
            # And the configuration setting exists
            If ( ($ConfigurationSettings[$SettingName] -in $ExpectedValue) -or ($ConfigurationSettings[$SettingName] -le $MaxAllowedValue) ) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")] [Max Allowed: $MaxAllowedValue]" | Out-String
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

Function Get-V246883 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246883
        STIG ID    : HRZV-7X-000002
        Rule ID    : SV-246883r790552_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-APP-000015-AS-000010
        Rule Title : The Horizon Connection Server must be configured to only support TLS 1.2 connections.
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
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "secureProtocols.1" # Name of the first setting identified in STIG
    $SettingName2 = "preferredSecureProtocol" # Name of the second setting identified in STIG
    $ExpectedValue = @("TLSv1.2") # Value(s) expected in STIG
    $ExpectedValue2 = @("TLSv1.2") # Value(s) expected in STIG
    $SettingDescription = "TLSv1.2 must be configured" # Short description of the setting
    $FileNotExistAllowed = $false # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $false # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist check adsi edit to see if it is enforced globally
        $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
        $Filter = "(CN=Common)"
        $AdsiPropertyName = "pae-ServerSSLSecureProtocols"
        $ExpectedPropertyValue = "\LIST:TLSv1.2"

        $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher([adsi]"$Root")
        $AdsiSearcher.SearchRoot
        $AdsiSearcher.Filter = "$Filter"
        [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
        $AdsiSearchResult = $AdsiSearcher.FindOne()

        Try {
            $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
        }
        Catch {
            $AdsiPropertyValue = "(Not Set)"
        }

        If ($AdsiPropertyValue -eq $ExpectedPropertyValue) {
            # TLSv1.2 is enforced globally for Horizon View servers, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist, however, $AdsiPropertyName is enforced globally via ADSI EDIT which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
            $FindingDetails += "LDAP Path:`t$Root" | Out-String
            $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
            $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
            $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
        }
        Else {
            If ($FileNotExistAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$ConfigurationFileName' file does not exist and $AdsiPropertyName is not being enforced globally via ADSI EDIT." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "LDAP Path:`t$Root" | Out-String
                $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
                $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
                $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected $ExpectedPropertyValue]" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "LDAP Path:`t$Root" | Out-String
                $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
                $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
                $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected $ExpectedPropertyValue]" | Out-String
            }
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName") -or ($ConfigurationSettings.ContainsKey("$SettingName2")))) {
            # But the configuration settings does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
        }
        Else {
            # And the configuration setting exists
            If ( ($ConfigurationSettings[$SettingName] -in $ExpectedValue) -and ($ConfigurationSettings[$SettingName2] -in $ExpectedValue2) ) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName2])" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                If ($ConfigurationSettings[$SettingName] -notin $ExpectedValue) {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
                }
                $FindingDetails += "Setting Name:`t$SettingName2" | Out-String
                If ($ConfigurationSettings[$SettingName2] -notin $ExpectedValue2) {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName2]) [Expected: $($ExpectedValue2 -join " or ")]" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName2])" | Out-String
                }
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
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

Function Get-V246884 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246884
        STIG ID    : HRZV-7X-000003
        Rule ID    : SV-246884r790553_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-APP-000015-AS-000010
        Rule Title : The Blast Secure Gateway must be configured to only support TLS 1.2 connections.
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
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "absg.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "appblastgateway\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "localHttpsProtocolLow" # Name of the first setting identified in STIG
    $SettingName2 = "localHttpsProtocolHigh" # Name of the second setting identified in STIG
    $ExpectedValue = @("tls1.2") # Value(s) expected in STIG
    $ExpectedValue2 = @("tls1.2") # Value(s) expected in STIG
    $SettingDescription = "Blast Secure Gateway must be configured to only support TLSv1.2" # Short description of the setting
    $FileNotExistAllowed = $false # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $false # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName") -or ($ConfigurationSettings.ContainsKey("$SettingName2")))) {
            # But the configuration settings does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
        }
        Else {
            # And the configuration setting exists
            If ( ($ConfigurationSettings[$SettingName] -in $ExpectedValue) -and ($ConfigurationSettings[$SettingName2] -in $ExpectedValue2) ) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName2])" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                If ($ConfigurationSettings[$SettingName] -notin $ExpectedValue) {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
                }
                $FindingDetails += "Setting Name:`t$SettingName2" | Out-String
                If ($ConfigurationSettings[$SettingName2] -notin $ExpectedValue2) {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName2]) [Expected: $($ExpectedValue2 -join " or ")]" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName2])" | Out-String
                }
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
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

Function Get-V246885 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246885
        STIG ID    : HRZV-7X-000004
        Rule ID    : SV-246885r768615_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-APP-000015-AS-000010
        Rule Title : The Horizon Connection Server must force server cipher preference.
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
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "honorClientOrder" # Name of the first setting identified in STIG
    $ExpectedValue = @("false") # Value(s) expected in STIG
    $SettingDescription = "Horizon Connection Server must force server cipher preference" # Short description of the setting
    $FileNotExistAllowed = $false # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $false # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist check adsi edit to see if it is enforced globally
        $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
        $Filter = "(CN=Common)"
        $AdsiPropertyName = "pae-ServerSSLHonorClientOrder"
        $ExpectedPropertyValue = "0"

        $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher([adsi]"$Root")
        $AdsiSearcher.Filter = "$Filter"
        [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
        $AdsiSearchResult = $AdsiSearcher.FindOne()

        Try {
            $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
        }
        Catch {
            $AdsiPropertyValue = "(Not Set)"
        }

        If ( $AdsiPropertyValue -eq $ExpectedPropertyValue) {
            # TLSv1.2 is enforced globally for Horizon View servers, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist, however, $AdsiPropertyName is enforced globally via ADSI EDIT which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
            $FindingDetails += "LDAP Path:`t$Root" | Out-String
            $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
            $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
            $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
        }
        Else {
            If ($FileNotExistAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$ConfigurationFileName' file does not exist and $AdsiPropertyName is not being enforced globally via ADSI EDIT." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "LDAP Path:`t$Root" | Out-String
                $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
                $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
                $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected $ExpectedPropertyValue]" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "LDAP Path:`t$Root" | Out-String
                $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
                $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
                $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected $ExpectedPropertyValue]" | Out-String
            }
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName") -or ($ConfigurationSettings.ContainsKey("$SettingName2")))) {
            # But the configuration settings does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
        }
        Else {
            # And the configuration setting exists
            If ($ConfigurationSettings[$SettingName] -in $ExpectedValue) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
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

Function Get-V246886 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246886
        STIG ID    : HRZV-7X-000005
        Rule ID    : SV-246886r768618_rule
        CCI ID     : CCI-000067
        Rule Name  : SRG-APP-000016-AS-000013
        Rule Title : The Horizon Connection Server must be configured to debug level logging.
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\VMware, Inc.\VMware VDM\"  # Registry path identified in STIG
    $RegistryValueName = "DebugEnabled"  # Value name identified in STIG
    $RegistryValue = @("True")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Debug level logging must be enabled"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $true  # Set to true if STIG allows for setting to be Not Configured.

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
        #$RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
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

Function Get-V246888 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246888
        STIG ID    : HRZV-7X-000007
        Rule ID    : SV-246888r790555_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080-AS-000045
        Rule Title : The Horizon Connection Server must require DoD PKI for administrative logins.
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
    $SettingName = "Smart Card Authentication for Administrators"
    $Root = "LDAP://localhost:389/OU=Server,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=$($env:COMPUTERNAME))"
    $AdsiPropertyName = "pae-CertAuthAdmin"
    $ExpectedPropertyValue = "3"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    Try {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }
    Catch {
        $AdsiPropertyValue = "(Not Set)"
    }

    If ( $AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected value: $ExpectedPropertyValue]" | Out-String
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

Function Get-V246889 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246889
        STIG ID    : HRZV-7X-000008
        Rule ID    : SV-246889r768627_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089-AS-000050
        Rule Title : The Horizon Connection Server must be configured with an events database.
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
    $SettingName = "Events Database"
    $Root = "LDAP://localhost:389/OU=Database,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=*)"
    $AdsiPropertyName = @("pae-DatabaseHostname", "pae-DatabaseName", "pae-DatabaseServerType", "pae-DatabaseTablePrefix", "pae-DatabaseUsername")

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.AddRange($AdsiPropertyName)
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    ForEach ($PropertyName in $AdsiPropertyName) {
        If ($AdsiSearchResult.Properties.Keys -notcontains "$PropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$PropertyName"])) {
            # Setting is not configured, set to Open
            $Status = "Open"
            $AdsiSearchResult.Properties["$PropertyName"] = "(Not Set)"
        }
    }

    If ($Status -eq "Open") {
        # Set finding details for an Open status
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Events Database details:" | Out-String
        $FindingDetails += "------------------------" | Out-String
        ForEach ($AdsiProperty in $AdsiPropertyName) {
            If ($AdsiSearchResult.Properties["$AdsiProperty"] -eq "(Not Set)") {
                $FindingDetails += "$AdsiProperty`:`t`t$($AdsiSearchResult.Properties["$AdsiProperty"]) [Expected a value other than (Not Set)]" | Out-String
            }
            Else {
                $FindingDetails += "$AdsiProperty`:`t`t$($AdsiSearchResult.Properties["$AdsiProperty"])" | Out-String
            }
        }
    }
    Else {
        # Set finding details for a NotAFinding status
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Events Database details:" | Out-String
        $FindingDetails += "------------------------" | Out-String
        ForEach ($AdsiProperty in $AdsiPropertyName) {
            $FindingDetails += "$AdsiProperty`:`t`t$($AdsiSearchResult.Properties["$AdsiProperty"])" | Out-String
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

Function Get-V246891 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246891
        STIG ID    : HRZV-7X-000010
        Rule ID    : SV-246891r768633_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175-AS-000124
        Rule Title : The Horizon Connection Server must perform full path validation on server-to-server TLS connection certificates.
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\VMware, Inc.\VMware VDM\Security\"  # Registry path identified in STIG
    $RegistryValueName = "CertificateRevocationCheckType"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Horizon Connection Server must perform full path validation on server-to-server TLS connection certificates"  # GPO setting name identified in STIG
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
        #$RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
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

Function Get-V246892 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246892
        STIG ID    : HRZV-7X-000011
        Rule ID    : SV-246892r768636_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175-AS-000124
        Rule Title : The Horizon Connection Server must validate client and administrator certificates.
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
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "enableRevocationChecking" # Name of the first setting identified in STIG
    $ExpectedValue = @("true") # Value(s) expected in STIG
    $SettingDescription = "Horizon Connection Server must validate client and administrator certificates" # Short description of the setting
    $FileNotExistAllowed = $false # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $false # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist check adsi edit to see if it is enforced globally
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist and $AdsiPropertyName is not being enforced globally via ADSI EDIT." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName") -or ($ConfigurationSettings.ContainsKey("$SettingName2")))) {
            # But the configuration settings does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName2 (Not found)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
        }
        Else {
            # And the configuration setting exists
            If ($ConfigurationSettings[$SettingName] -in $ExpectedValue) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
                }
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Contents of '$ConfigurationFileName':" | Out-String
                $FindingDetails += "-------------------------------------" | Out-String

                ForEach ($Line in (Get-Content -Path $ConfigurationFilePath)) {
                    $FindingDetails += $Line | Out-String
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

Function Get-V246893 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246893
        STIG ID    : HRZV-7X-000012
        Rule ID    : SV-246893r768639_rule
        CCI ID     : CCI-000803
        Rule Name  : SRG-APP-000179-AS-000129
        Rule Title : The Horizon Connection Server must only use FIPS 140-2 validated cryptographic modules.
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
    $SettingDescription = "Horizon Connection Server must only use FIPS 140-2 validated cryptographic modules"

    $FIPSModeEnabled = Get-ChildItem -Path C:\ProgramData\VMware\VDM\logs\* -Filter *.txt -ErrorAction SilentlyContinue | Select-String -SimpleMatch 'Broker started in FIPS mode'

    If ($FIPSModeEnabled) {
        # Found string in debug/log file(s), set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingDescription' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Found 'Broker started in FIPS mode' in the following log files:" | Out-String
        $FindingDetails += "-----------------------------" | Out-String
        ForEach ($Line in $FIPSModeEnabled) {
            $FindingDetails += $Line
        }
    }
    Else {
        # Did not find string in debug/log file(s), set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Did not find 'Broker started in FIPS mode' in any log files." | Out-String
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

Function Get-V246894 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246894
        STIG ID    : HRZV-7X-000013
        Rule ID    : SV-246894r768642_rule
        CCI ID     : CCI-001185
        Rule Name  : SRG-APP-000220-AS-000148
        Rule Title : The Horizon Connection Server must time out administrative sessions after 15 minutes or less.
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
    $SettingName = "Connection Server Session Timeout"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-ConsoleSessionTimeout"
    $MaxPropertyValue = "900"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiSearchResult.Properties["$AdsiPropertyName"] = "(Not Set)"
    }

    $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]

    If ( $AdsiPropertyValue -le $MaxPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected a value less than or equal to $MaxPropertyValue]" | Out-String
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

Function Get-V246895 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246895
        STIG ID    : HRZV-7X-000014
        Rule ID    : SV-246895r768645_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-APP-000267-AS-000170
        Rule Title : The Horizon Connection Server must protect log files from unauthorized access.
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
    $SettingName = "Log files must be protected from unauthorized access"
    $VDMLogsPath = "C:\ProgramData\VMware\VDM\logs"
    $ExpectedGroupsRegex = 'Administrators|NT Authority\\SYSTEM|NT Authority\\NETWORK SERVICE'

    $VdmLogsAccess = Get-Acl -Path $VDMLogsPath | Select-Object -ExpandProperty Access

    If ($VdmLogsAccess.IdentityReference -notmatch $ExpectedGroupsRegex) {
        # Setting is not configured according to the STIG, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "VDM Logs Path:`t$VDMLogsPath" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Security Access Details:" | Out-String
        ForEach ($AccessMember in $VdmLogsAccess) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "FileSystemRights:`t$($AccessMember.FileSystemRights)" | Out-String
            $FindingDetails += "AccessControlType:`t$($AccessMember.AccessControlType)" | Out-String
            $FindingDetails += "IdentityReference:`t$($AccessMember.IdentityReference)" | Out-String
            $FindingDetails += "IsInherited:`t`t$($AccessMember.IsInherited)" | Out-String
            $FindingDetails += "InheritanceFlags:`t$($AccessMember.InheritanceFlags)" | Out-String
            $FindingDetails += "PropagationFlags:`t$($AccessMember.PropagationFlags)" | Out-String
        }
    }
    Else {
        # Setting is configured according to the STIG, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "VDM Logs Path:`t$VDMLogsPath" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Security Access Details:" | Out-String
        ForEach ($AccessMember in $VdmLogsAccess) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "FileSystemRights:`t$($AccessMember.FileSystemRights)" | Out-String
            $FindingDetails += "AccessControlType:`t$($AccessMember.AccessControlType)" | Out-String
            $FindingDetails += "IdentityReference:`t$($AccessMember.IdentityReference)" | Out-String
            $FindingDetails += "IsInherited:`t`t$($AccessMember.IsInherited)" | Out-String
            $FindingDetails += "InheritanceFlags:`t$($AccessMember.InheritanceFlags)" | Out-String
            $FindingDetails += "PropagationFlags:`t$($AccessMember.PropagationFlags)" | Out-String
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

Function Get-V246896 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246896
        STIG ID    : HRZV-7X-000015
        Rule ID    : SV-246896r768648_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-APP-000358-AS-000064
        Rule Title : The Horizon Connection Server must offload events to a central log server in real time.
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
    $SettingName = "Event Syslog Network Off-loading"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-eventSyslogNetworkAddresses"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ($AdsiPropertyValue -ne "(Not Set)") {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected a value other than '(Not Set)']" | Out-String
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

Function Get-V246897 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246897
        STIG ID    : HRZV-7X-000016
        Rule ID    : SV-246897r768651_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427-AS-000264
        Rule Title : The Horizon Connection Server must be configured with a DoD-issued TLS certificate.
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
    $SettingName = "DoD-issued TLS Certificate"
    $CertPath = "Cert:\LocalMachine\My"
    $CertFriendlyName = "vdm"
    $CertExpectedIssuer = "DOD SW"

    $VdmCert = Get-ChildItem -Path "$CertPath\*" | Where-Object { $_.FriendlyName -eq "$CertFriendlyName" }

    If ($VdmCert.Issuer -match $CertExpectedIssuer) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Issued To:`t$($VdmCert.Subject -replace 'CN=|,.*')" | Out-String
        $FindingDetails += "Issued By:`t`t$($VdmCert.Issuer -replace 'CN=|,.*')" | Out-String
        $FindingDetails += "Expiration Date:`t$($VdmCert.NotAfter)" | Out-String
        $FindingDetails += "Friendly Name:`t$CertFriendlyName" | Out-String
        $FindingDetails += "Intended Purposes:`t$($VdmCert.EnhancedKeyUsageList.friendlyname -join ', ')" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Issued To:`t$($VdmCert.Subject -replace 'CN=|,.*')" | Out-String
        $FindingDetails += "Issued By:`t`t$($VdmCert.Issuer -replace 'CN=|,.*')" | Out-String
        $FindingDetails += "Expiration Date:`t$($VdmCert.NotAfter)" | Out-String
        $FindingDetails += "Friendly Name:`t$CertFriendlyName" | Out-String
        $FindingDetails += "Intended Purposes:`t$($VdmCert.EnhancedKeyUsageList.friendlyname -join ', ')" | Out-String
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

Function Get-V246898 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246898
        STIG ID    : HRZV-7X-000017
        Rule ID    : SV-246898r768654_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must reauthenticate users after a network interruption.
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
    $SettingName = "Reauthenticate users after a network interruption"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-ReAuthOnNetInterrupt"
    $ExpectedPropertyValue = "0"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ([string]$AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected value: $ExpectedPropertyValue]" | Out-String
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

Function Get-V246899 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246899
        STIG ID    : HRZV-7X-000018
        Rule ID    : SV-246899r768657_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must disconnect users after a maximum of ten hours.
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
    $SettingName = "Forcibly Disconnect Users"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-MaxSessionTime"
    $ExpectedPropertyValue = "600"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        # The value is stored in seconds, even though the number you enter into the console is in minutes. So let's divide it by 60 so it matches up with the STIG
        If ([int]($AdsiSearchResult.Properties["$AdsiPropertyName"])[0] -ge 0) {
            $AdsiPropertyValue = ([int]($AdsiSearchResult.Properties["$AdsiPropertyName"])[0] / 60)
        }
        Else {
            $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
        }
    }

    If ($AdsiPropertyValue -ne "-1" -and $AdsiPropertyValue -le $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected value less than or equal to $ExpectedPropertyValue, but not -1]" | Out-String
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

Function Get-V246900 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246900
        STIG ID    : HRZV-7X-000019
        Rule ID    : SV-246900r768660_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must disconnect applications after two hours of idle time.
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
    $SettingName = "Disconnect Applications and Discard SSO Credentials for Idle Users"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-UserIdleTimeout"
    $ExpectedPropertyValue = "120"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        # The value is stored in seconds, even though the number you enter into the console is in minutes. So let's divide it by 60 so it matches up with the STIG
        If ([int]($AdsiSearchResult.Properties["$AdsiPropertyName"])[0] -ge 0) {
            $AdsiPropertyValue = ([int]($AdsiSearchResult.Properties["$AdsiPropertyName"])[0] / 60)
        }
        Else {
            $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
        }
    }

    If ($AdsiPropertyValue -ne "-1" -and $AdsiPropertyValue -le $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected value less than or equal to $ExpectedPropertyValue, but not -1]" | Out-String
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

Function Get-V246901 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246901
        STIG ID    : HRZV-7X-000020
        Rule ID    : SV-246901r768663_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must discard SSO credentials after 15 minutes.
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
    $SettingName = "Discard SSO Credentials"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-SSOCredentialCacheTimeout"
    $ExpectedPropertyValue = "15"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ($AdsiPropertyValue -ne "-1" -and $AdsiPropertyValue -le $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected value less than or equal to $ExpectedPropertyValue, but not -1]" | Out-String
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

Function Get-V246902 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246902
        STIG ID    : HRZV-7X-000021
        Rule ID    : SV-246902r768666_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must not accept pass-through client credentials.
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
    $SettingName = "Accept logon as current user"
    $Root = "LDAP://localhost:389/OU=Server,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=$($env:COMPUTERNAME))"
    $AdsiPropertyName = "pae-SendBrokerServicePrincipal"
    $ExpectedPropertyValue = "0"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ([string]$AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue [Expected value: $ExpectedPropertyValue]" | Out-String
    }

    # Check if "Smart card authentication for users" is set to required
    $SettingName = "Smart card authentication for users"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-CertAuth"
    $ExpectedPropertyValue = "3"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ([string]$AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "Not_Applicable"
        $FindingDetails += "'$SettingName' is set to 'Required', this STIG is not applicable." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
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

Function Get-V246904 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246904
        STIG ID    : HRZV-7X-000023
        Rule ID    : SV-246904r768672_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must backup its configuration daily.
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
    $SettingName = "Automatic Backup Frequency"
    $Root = "LDAP://localhost:389/OU=Server,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=$($env:COMPUTERNAME))"
    $AdsiPropertyName = @("pae-LDAPBUFrequency", "pae-LDAPBUUnits")
    $ExpectedPropertyValue = @("1", "6", "12")
    $ExpectedPropertyValue2 = @("1", "2")

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.AddRange($AdsiPropertyName)
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    ForEach ($PropertyName in $AdsiPropertyName) {
        If ($AdsiSearchResult.Properties.Keys -notcontains "$PropertyName") {
            # Setting is not configured, add the property to the object and set the value
            $AdsiSearchResult.Properties["$PropertyName"] = "(Not Set)"
        }
    }

    If ($AdsiSearchResult.Properties["$($AdsiPropertyName[0])"] -in $ExpectedPropertyValue -and $AdsiSearchResult.Properties["$($AdsiPropertyName[1])"] -in $ExpectedPropertyValue2) {
        # Setting is configured, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t`t$($AdsiPropertyName[0])" | Out-String
        $FindingDetails += "Property Value:`t`t$($AdsiSearchResult.Properties["$($AdsiPropertyName[0])"])" | Out-String
        $FindingDetails += "Property Name:`t`t$($AdsiPropertyName[1])" | Out-String
        $FindingDetails += "Property Value:`t`t$($AdsiSearchResult.Properties["$($AdsiPropertyName[1])"])" | Out-String
    }
    Else {
        # Or, if it must exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t`t$($AdsiPropertyName[0])" | Out-String
        $FindingDetails += "Property Value:`t`t$($AdsiSearchResult.Properties["$($AdsiPropertyName[0])"])" | Out-String
        $FindingDetails += "Property Name:`t`t$($AdsiPropertyName[1])" | Out-String
        $FindingDetails += "Property Value:`t`t$($AdsiSearchResult.Properties["$($AdsiPropertyName[1])"])" | Out-String
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

Function Get-V246905 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246905
        STIG ID    : HRZV-7X-000024
        Rule ID    : SV-246905r768675_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server Instant Clone domain account must be configured with limited permissions.
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
    $Root = "LDAP://localhost:389/OU=VirtualCenter,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=*)"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($null -eq $AdsiSearchResult) {
        # Setting is configured, set to NotAFinding
        $Status = "Not_Applicable"
        $FindingDetails += "There are no vCenter Servers configured, therefore Instant Clone is not supported. This STIG is not applicable." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
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

Function Get-V246906 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246906
        STIG ID    : HRZV-7X-000025
        Rule ID    : SV-246906r768678_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.
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
    $RegistryPath = "HKLM:\Software\VMware, Inc.\VMware VDM\Plugins\wsnm\TunnelService\Params\"
    $RegistryValueName = "JvmOptions"
    $ExpectedValueString = "-Djdk.tls.rejectClientInitiatedRenegotiation=true"

    $JvmOptionsValue = (Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName).Value

    If ($JvmOptionsValue -match $ExpectedValueString) {
        # Setting is configured according to STIG, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "This Horizon Connection Server is configured in accordance with the security configuration settings based on DoD security guidance." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
        $FindingDetails += "Value Data:`t$JvmOptionsValue" | Out-String
    }
    ElseIf ($JvmOptionsValue -eq "(NotFound)") {
        # Setting does not exist, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "This Horizon Connection Server is configured in accordance with the security configuration settings based on DoD security guidance." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName (Not Found)" | Out-String
        $FindingDetails += "Value Data:`t$JvmOptionsValue (Not Found)" | Out-String
    }
    Else {
        # Setting is not configured according to STIG, set to Open
        $Status = "Open"
        $FindingDetails += "This Horizon Connection Server is NOT configured in accordance with the security configuration settings based on DoD security guidance." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
        $FindingDetails += "Value Data:`t$JvmOptionsValue" | Out-String
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

Function Get-V246907 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246907
        STIG ID    : HRZV-7X-000026
        Rule ID    : SV-246907r768681_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must have X-Frame-Options enabled.
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
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "X-Frame-Options" # Name of the setting identified in STIG
    $ExpectedValue = @("ON") # Value(s) expected in STIG
    $FileNotExistAllowed = $true # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $true # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName"))) {
            # But the configuration setting does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
        }
        Else {
            # And the configuration setting exists
            If ($ConfigurationSettings[$SettingName] -in $ExpectedValue) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
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

Function Get-V246908 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246908
        STIG ID    : HRZV-7X-000027
        Rule ID    : SV-246908r790559_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must have Origin Checking enabled.
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
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "checkOrigin" # Name of the setting identified in STIG
    $ExpectedValue = @("true") # Value(s) expected in STIG
    $FileNotExistAllowed = $true # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $true # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName"))) {
            # But the configuration setting does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
        }
        Else {
            # And the configuration setting exists
            If ($ConfigurationSettings[$SettingName] -in $ExpectedValue) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
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

Function Get-V246909 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246909
        STIG ID    : HRZV-7X-000028
        Rule ID    : SV-246909r768687_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must enable the Content Security Policy.
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
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "enableCSP" # Name of the setting identified in STIG
    $ExpectedValue = @("true") # Value(s) expected in STIG
    $FileNotExistAllowed = $true # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $true # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName"))) {
            # But the configuration setting does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
        }
        Else {
            # And the configuration setting exists
            If ($ConfigurationSettings[$SettingName] -in $ExpectedValue) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
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

Function Get-V246910 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246910
        STIG ID    : HRZV-7X-000029
        Rule ID    : SV-246910r768690_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must enable the proper Content Security Policy directives.
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
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = @("content-security-policy", "content-security-policy-newadmin", "content-security-policy-portal", "content-security-policy-rest") # Name of the setting identified in STIG
    $SettingDescription = "Content Security Policy directives"
    $FileNotExistAllowed = $true # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $true # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            ForEach ($Setting in $SettingName) {
                $FindingDetails += "Setting Name:`t$Setting (Not found)" | Out-String
            }
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            ForEach ($Setting in $SettingName) {
                $FindingDetails += "Setting Name:`t$Setting (Not found)" | Out-String
            }
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath | Where-Object { $_.Keys -match "$SettingName" }
        If (-not ($ConfigurationSettings)) {
            # But the configuration setting does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingDescription' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                ForEach ($Setting in $SettingName) {
                    $FindingDetails += "Setting Name:`t$Setting (Not found)" | Out-String
                }
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingDescription' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                ForEach ($Setting in $SettingName) {
                    $FindingDetails += "Setting Name:`t$Setting (Not found)" | Out-String
                }
            }
        }
        Else {
            # And the configuration setting exists, set to Open
            $Status = "Open"
            $FindingDetails += "'$SettingDescription' is NOT configured according to the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
            ForEach ($Key in $ConfigurationSettings) {
                $FindingDetails += "Setting Name:`t$Key [This setting should not exist in $ConfigurationFileName]" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings["$Key"]) [This value should not be configured]" | Out-String
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

Function Get-V246911 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246911
        STIG ID    : HRZV-7X-000030
        Rule ID    : SV-246911r768693_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The PCoIP Secure Gateway must be configured with a DoD-issued TLS certificate.
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
    $RegistryPath = "HKLM:\Software\Teradici\SecurityGateway\"
    $RegistryValueName = "SSLCertWinCertFriendlyName"
    $ExpectedValue = "vdm"

    $RegistryValue = (Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName).Value

    $SettingName = "Use PCoIP Secure Gateway"
    $Root = "LDAP://localhost:389/OU=Server,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=$($Env:COMPUTERNAME))"
    $AdsiPropertyName = "pae-BypassPCoIPSecureGateway"
    $ExpectedPropertyValue = "1"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ([string]$AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured, set to NotAFinding
        $Status = "Not_Applicable"
        $FindingDetails += "'$SettingName' is set to 'Disabled' for this Connection Server, this STIG is not applicable." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    ElseIf ($RegistryValue -eq $ExpectedValue) {
        # Setting is configured according to STIG, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$RegistryValueName' is set to '$ExpectedValue', this is not a finding." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
        $FindingDetails += "Value Data:`t$RegistryValue" | Out-String
    }
    ElseIf ($RegistryValue -eq "(NotFound)") {
        # Setting does not exist, set to Open
        $Status = "Open"
        $FindingDetails += "'$RegistryValueName' does not exist, this is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName (Not Found) [This registry value must exist]" | Out-String
        $FindingDetails += "Value Data:`t(Not Found)" | Out-String
    }
    Else {
        # Registry value differs from expected value, check to see if friendlyname certificate was issued by DoD
        $SettingName = "DoD-issued TLS Certificate"
        $CertPath = "Cert:\LocalMachine\My"
        $CertFriendlyName = $RegistryValue
        $CertExpectedIssuer = "DOD SW"

        $VdmCert = Get-ChildItem -Path "$CertPath\*" | Where-Object { $_.FriendlyName -eq "$CertFriendlyName" }

        If ($VdmCert) {
            # Certificate exists, check Issuer...
            If ($VdmCert.Issuer -match $CertExpectedIssuer) {
                # Cert was issued by DoD, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$CertFriendlyName' was issued by DoD, this is not a finding." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Issued To:`t$($VdmCert.Subject -replace 'CN=|,.*')" | Out-String
                $FindingDetails += "Issued By:`t`t$($VdmCert.Issuer -replace 'CN=|,.*')" | Out-String
                $FindingDetails += "Expiration Date:`t$($VdmCert.NotAfter)" | Out-String
                $FindingDetails += "Friendly Name:`t$CertFriendlyName" | Out-String
                $FindingDetails += "Intended Purposes:`t$($VdmCert.EnhancedKeyUsageList.friendlyname -join ', ')" | Out-String
            }
            Else {
                # Cert was not issued by DoD, set to Open
                $Status = "Open"
                $FindingDetails += "'$CertFriendlyName' was not issued by DoD, this is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Issued To:`t$($VdmCert.Subject -replace 'CN=|,.*')" | Out-String
                $FindingDetails += "Issued By:`t`t$($VdmCert.Issuer -replace 'CN=|,.*')" | Out-String
                $FindingDetails += "Expiration Date:`t$($VdmCert.NotAfter)" | Out-String
                $FindingDetails += "Friendly Name:`t$CertFriendlyName" | Out-String
                $FindingDetails += "Intended Purposes:`t$($VdmCert.EnhancedKeyUsageList.friendlyname -join ', ')" | Out-String
            }
        }
        Else {
            # Certificate does not exist, set to Open
            $Status = "Open"
            $FindingDetails += "A certificate with FriendlyName '$CertFriendlyName' does not exist, this is a finding." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Friendly Name:`t$CertFriendlyName" | Out-String
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

Function Get-V246912 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246912
        STIG ID    : HRZV-7X-000031
        Rule ID    : SV-246912r768696_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must not allow unauthenticated access.
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
    $SettingName = "Allow Unauthenticated Access"
    $Root = "LDAP://localhost:389/OU=Server,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=$($Env:COMPUTERNAME))"
    $AdsiPropertyName = "pae-AnonymousLogonEnabled"
    $ExpectedPropertyValue = "0"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    $SettingName2 = "Smart card authentication for users"
    $Root2 = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter2 = "(CN=Common)"
    $AdsiPropertyName2 = "pae-CertAuth"
    $ExpectedPropertyValue2 = "3"

    $AdsiSearcher2 = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher2.Filter = "$Filter2"
    [void]$AdsiSearcher2.PropertiesToLoad.Add("$AdsiPropertyName2")
    $AdsiSearchResult2 = $AdsiSearcher2.FindOne()

    If ($AdsiSearchResult2.Properties.Keys -notcontains "$AdsiPropertyName2" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult2.Properties["$AdsiPropertyName2"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue2 = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue2 = $AdsiSearchResult2.Properties["$AdsiPropertyName2"]
    }

    If ([string]$AdsiPropertyValue2 -eq $ExpectedPropertyValue2) {
        # Setting is configured, set to NotAFinding
        $Status = "Not_Applicable"
        $FindingDetails += "'$SettingName2' is set to 'Required', this STIG is not applicable." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName2" | Out-String
        $FindingDetails += "LDAP Path:`t$Root2" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter2" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName2" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue2" | Out-String
    }
    ElseIf ([string]$AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured according to STIG, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is set to 'Disabled', this is not a finding." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Setting is not configured according to STIG, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is set to 'Enabled', this is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
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

Function Get-V246913 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246913
        STIG ID    : HRZV-7X-000032
        Rule ID    : SV-246913r768699_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must require CAC reauthentication after user idle timeouts.
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
    $SettingName = "Enable 2-Factor Reauthentication"
    $Root = "LDAP://localhost:389/OU=Global,OU=Properties,DC=vdi,DC=vmware,DC=int"
    $Filter = "(CN=Common)"
    $AdsiPropertyName = "pae-EnableMultiFactorReAuth"
    $ExpectedPropertyValue = "1"

    $AdsiSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher(([adsi]"$Root"))
    $AdsiSearcher.Filter = "$Filter"
    [void]$AdsiSearcher.PropertiesToLoad.Add("$AdsiPropertyName")
    $AdsiSearchResult = $AdsiSearcher.FindOne()

    If ($AdsiSearchResult.Properties.Keys -notcontains "$AdsiPropertyName" -or [string]::IsNullOrWhiteSpace($AdsiSearchResult.Properties["$AdsiPropertyName"])) {
        # Setting is not configured, add the property to the object and set the value
        $AdsiPropertyValue = "(Not Set)"
    }
    Else {
        $AdsiPropertyValue = $AdsiSearchResult.Properties["$AdsiPropertyName"]
    }

    If ([string]$AdsiPropertyValue -eq $ExpectedPropertyValue) {
        # Setting is configured according to STIG, set to NotAFinding
        $Status = "NotAFinding"
        $FindingDetails += "'$SettingName' is set to 'Yes', this is not a finding." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
    }
    Else {
        # Setting is not configured according to STIG, set to Open
        $Status = "Open"
        $FindingDetails += "'$SettingName' is set to 'No', this is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Setting Name:`t$SettingName" | Out-String
        $FindingDetails += "LDAP Path:`t$Root" | Out-String
        $FindingDetails += "LDAP Filter:`t$Filter" | Out-String
        $FindingDetails += "Property Name:`t$AdsiPropertyName" | Out-String
        $FindingDetails += "Property Value:`t$AdsiPropertyValue" | Out-String
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

Function Get-V246915 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246915
        STIG ID    : HRZV-7X-000034
        Rule ID    : SV-246915r768705_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-AS-000237
        Rule Title : The Horizon Connection Server must prevent MIME type sniffing.
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
    $VMwareViewInstallPath = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -EQ "VMware Horizon 7 Connection Server").InstallLocation
    $ConfigurationFileName = "locked.properties" # Name of the configuration file identified in STIG
    $ConfigurationFilePath = $VMwareViewInstallPath + "sslgateway\conf\$ConfigurationFileName" # Path to the configuration file identified in STIG
    $SettingName = "x-content-type-options" # Name of the setting identified in STIG
    $ExpectedValue = @("true") # Value(s) expected in STIG
    $FileNotExistAllowed = $true # Set to true if STIG allows for configuration file to not exist.
    $SettingNotConfiguredAllowed = $true # Set to true if STIG allows for setting to not exist in configuration file.

    If (-not (Test-Path -Path $ConfigurationFilePath -ErrorAction SilentlyContinue)) {
        # If configuration file does not exist
        If ($FileNotExistAllowed) {
            # And it is allowed to not exist, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
        Else {
            # Or, if it must exist, set to Open
            $Status = "Open"
            $FindingDetails += "'$ConfigurationFileName' file does not exist which is NOT acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath (Not Found)" | Out-String
            $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
        }
    }
    Else {
        # If the configuration file exists...
        $ConfigurationSettings = Get-IniContent $ConfigurationFilePath
        If (-not ($ConfigurationSettings.ContainsKey("$SettingName"))) {
            # But the configuration setting does not exist
            If ($SettingNotConfiguredAllowed) {
                # And it is allowed to not exist, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is not configured which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
            Else {
                # Or, if it must exist, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is not configured which is NOT acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName (Not found)" | Out-String
            }
        }
        Else {
            # And the configuration setting exists
            If ($ConfigurationSettings[$SettingName] -in $ExpectedValue) {
                # Setting value is within allowed values, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName])" | Out-String
            }
            Else {
                # Setting value is not within spec, set to Open
                $Status = "Open"
                $FindingDetails += "'$SettingName' is NOT configured according to the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Configuration File Path:`t$ConfigurationFilePath" | Out-String
                $FindingDetails += "Setting Name:`t$SettingName" | Out-String
                $FindingDetails += "Value:`t`t$($ConfigurationSettings[$SettingName]) [Expected: $($ExpectedValue -join " or ")]" | Out-String
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

Function Get-V246916 {
    <#
    .DESCRIPTION
        Vuln ID    : V-246916
        STIG ID    : HRZV-7X-000035
        Rule ID    : SV-246916r768708_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456-AS-000266
        Rule Title : All Horizon components must be running supported versions.
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
    $RegistryPath = "HKLM:\Software\VMware, Inc.\VMware VDM\"
    $RegistryValueName = "ProductVersion"
    $SupportedVersions = @{
        "7.10" = (Get-Date -Date "2022-03-17")
        "7.13" = (Get-Date -Date "2022-10-15")
    }

    $ProductVersion = (Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName).Value
    $MajorVersion = $ProductVersion -replace '^(\d\.\d+).*$', '$1'
    $TodaysDate = Get-Date

    If ( $MajorVersion -in ($SupportedVersions).Keys ) {
        # Check that todays date is not after the end of support date
        If ( $SupportedVersions["$MajorVersion"] -gt $TodaysDate ) {
            # Installed Horizon View is a supported version, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "The installed Horizon View is supported according to VMware's Product Lifecycle Matrix." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value Data:`t$ProductVersion" | Out-String
            $FindingDetails += "Product Version:`t$MajorVersion" | Out-String
            $FindingDetails += "Today's Date:`t`t$TodaysDate" | Out-String
            $FindingDetails += "End of Support:`t$($SupportedVersions[$MajorVersion])" | Out-String
        }
        Else {
            # The installed Horizon View is no longer being supported, set to Open
            $Status = "Open"
            $FindingDetails += "The installed Horizon View is NOT supported according to VMware's Product Lifecycle Matrix." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value Data:`t$ProductVersion" | Out-String
            $FindingDetails += "Product Version:`t$MajorVersion" | Out-String
            $FindingDetails += "Today's Date:`t`t$TodaysDate" | Out-String
            $FindingDetails += "End of Support:`t$($SupportedVersions[$MajorVersion])" | Out-String
        }
    }
    Else {
        # The installed version is not one of the supported versions, set to Open
        $Status = "Open"
        $FindingDetails += "The installed Horizon View is NOT supported according to VMware's Product Lifecycle Matrix." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
        $FindingDetails += "Value Data:`t$ProductVersion" | Out-String
        $FindingDetails += "Product Version:`t$MajorVersion" | Out-String
        $FindingDetails += "Today's Date:`t`t$TodaysDate" | Out-String
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDWDsCFBZZNl9Mp
# WAWug5QW7I0mrDrRHGbAAr3BxLsP+KCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBkrgGpx0dlFZaXyvyUsHLDxHpAiB5g
# aljAXFU8X22q+DANBgkqhkiG9w0BAQEFAASCAQCMgfvs6nRJi4ZCGLC5rD/V3o0/
# M1P0iSo+2dtte5j0wSx5kSYMw+hLmwbQXDxriBEDNTrof3dmH4Wu3DxHawSaP0wf
# 7LOhkZihlrSsoALqlMS2A4BSA6YV7erIgy2XH96uZCYQCOo7gjn20UHJ/SM2mgyE
# dDhe/D2bRn71gQA2rltvpqW+fJLVMkulq0njb2seJUkc0LwabrBizwe3TNxAhjDg
# xDKWfrNcg83WdSoX8mMhrrVDwDNsrzf1ROlXF4yic9IWz7mnVFOjO+XcnQoPuOa/
# 6jJJPZj39LcJ3ywvhq7Na9Q5Mb39+Sde8rHK9DUHPHw3r47473e91S28k/0M
# SIG # End signature block
