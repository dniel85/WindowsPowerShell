##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Mozilla Firefox
# Version:  V6R4
# Class:    UNCLASSIFIED
# Updated:  4/25/2023
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V251545 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251545
        STIG ID    : FFOX-00-000001
        Rule ID    : SV-251545r849960_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : The installed version of Firefox must be supported.
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
    If ($IsLinux) {
        # Get Firefox install on Linux systems
        if ((Test-Path "/usr/lib64/firefox/") -or (Test-Path "/usr/lib/firefox/")) {
            $pkg_mgr = (Get-Content /etc/os-release | grep "ID_LIKE=").replace("ID_LIKE=", "").replace('"', "")
            switch ($pkg_mgr) {
                "debian" {
                    $FirefoxInstalls = @{
                        DisplayName     = $(apt -qq list firefox 2>/dev/null | grep installed)
                        DisplayVersion  = ""
                        InstallLocation = ""
                    }
                }
                "fedora" {
                    $FirefoxInstalls = @{
                        DisplayName     = $(rpm -qa | grep -i Firefox)
                        DisplayVersion  = ""
                        InstallLocation = ""
                    }
                }
            }
        }
        $FindingDetails += "Package entries for Firefox:" | Out-String
    }
    Else {
        $FirefoxInstalls = Get-InstalledSoftware | Where-Object DisplayName -Like "Mozilla Firefox*"
        $FindingDetails += "Apps and Features entries for Firefox:" | Out-String
    }

    $FindingDetails += "" | Out-String
    ForEach ($Item in $FirefoxInstalls) {
        $FindingDetails += "Name:`t$($Item.DisplayName)" | Out-String
        $FindingDetails += "Version:`t$($Item.DisplayVersion)" | Out-String
        $FindingDetails += "Path:`t`t$($Item.InstallLocation)" | Out-String
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

Function Get-V251546 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251546
        STIG ID    : FFOX-00-000002
        Rule ID    : SV-251546r820745_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-APP-000560
        Rule Title : Firefox must be configured to allow only TLS 1.2 or above.
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
    $RegistryValueName = "SSLVersionMin"  # Value name identified in STIG
    $RegistryValue = @("tls1.2","tls1.3")  # Value(s) expected in STIG
    $SettingName = "Minimum SSL version enabled"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.SSLVersionMin
        $RegistryResultValue = $Policies_JSON.SSLVersionMin
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251547 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251547
        STIG ID    : FFOX-00-000003
        Rule ID    : SV-251547r807113_rule
        CCI ID     : CCI-000187
        Rule Name  : SRG-APP-000177
        Rule Title : Firefox must be configured to ask which certificate to present to a website when a certificate is required.
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
    $RegistryValueName = "Preferences"  # Value name identified in STIG
    $SettingName = "Preferences"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.Preferences | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.Preferences."security.default_personal_cert"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_MULTI_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    # Built configuration item
    $Configuration = New-Object System.Collections.Generic.List[System.Object]
    $Configuration.Add([PSCustomObject]@{Name = "security.default_personal_cert"; Value = "Ask Every Time"; Status = "locked" })

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Type -ne $RegistryType) {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
        }
        Else {
            Try {
                $Json = $RegistryResult.Value | ConvertFrom-Json -ErrorAction Stop
                If (-Not($Json.($Configuration.Name))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but $($Configuration.Name) is not configured" | Out-String
                }
                ElseIf (-Not(($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value -and (($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    If ((($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value)) {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value) [Expected $($Configuration.Value)]" | Out-String
                    }
                    If ((($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status)) {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status) [Expected $($Configuration.Status)]" | Out-String
                    }
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "'$($SettingName)' is $($SettingState):" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                }
            }
            Catch {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
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

Function Get-V251548 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251548
        STIG ID    : FFOX-00-000004
        Rule ID    : SV-251548r807116_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to not automatically check for updated versions of installed search plugins.
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
    $RegistryValueName = "Preferences"  # Value name identified in STIG
    $SettingName = "Preferences"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.Preferences | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.Preferences."browser.search.update"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_MULTI_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    # Built configuration item
    $Configuration = New-Object System.Collections.Generic.List[System.Object]
    $Configuration.Add([PSCustomObject]@{Name = "browser.search.update"; Value = "false"; Status = "locked"})


    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Type -ne $RegistryType) {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
        }
        Else {
            Try {
                $Json = $RegistryResult.Value | ConvertFrom-Json -ErrorAction Stop
                If (-Not($Json.($Configuration.Name))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but $($Configuration.Name) is not configured" | Out-String
                }
                ElseIf (-Not(($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value -and (($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    If ((($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value)) {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value) [Expected $($Configuration.Value)]" | Out-String
                    }
                    If ((($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status)) {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status) [Expected $($Configuration.Status)]" | Out-String
                    }
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "'$($SettingName)' is $($SettingState):" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                }
            }
            Catch {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
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

Function Get-V251549 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251549
        STIG ID    : FFOX-00-000005
        Rule ID    : SV-251549r807119_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to not automatically update installed add-ons and plugins.
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
    $RegistryValueName = "ExtensionUpdate"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Extension Update"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.ExtensionUpdate
        $RegistryResultValue = $Policies_JSON.ExtensionUpdate
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251550 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251550
        STIG ID    : FFOX-00-000006
        Rule ID    : SV-251550r832305_rule
        CCI ID     : CCI-001242
        Rule Name  : SRG-APP-000278
        Rule Title : Firefox must be configured to not automatically execute or download MIME types that are not authorized for auto-download.
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
    If ($IsLinux) {
        $Status = "Not_Reviewed"
    }
    Else {
        $ExtensionsToEval = @("HTA","JSE","JS","MOCHA","SHS","VBE","VBS","SCT","WSC","FDF","XFDF","LSL","LSO","LSS","IQY","RQY","DOS","BAT","PS","EPS","WCH","WCM","WB1","WB3","WCH","WCM","AD")
        $Compliant = $true
        $ProfileFound = $false

        # Check if the UserToProcess has utilized Firefox
        $UserProfilePath = (Get-CimInstance Win32_UserProfile | Where-Object SID -EQ $UserSID).LocalPath
        If (Test-Path -Path "$UserProfilePath\AppData\Roaming\Mozilla\Firefox\Profiles") {
            $ProfileFound = $true
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String

            $HandlersJson = @(Get-ChildItem -Path "$UserProfilePath\AppData\Roaming\Mozilla\Firefox\Profiles" -Recurse -ErrorAction SilentlyContinue | Where-Object Name -EQ "handlers.json")
        }
        Else {
            $ProfileList = Get-UsersToEval

            # Find a user that has utilized Firefox
            Foreach ($UserProfile in $ProfileList) {
                $UserProfilePath = $UserProfile.LocalPath
                If ((Test-Path -Path "$UserProfilePath\AppData\Roaming\Mozilla\Firefox\Profiles")) {
                    $ProfileFound = $true
                    $FindingDetails += "Evaluate-STIG intended to utilize $($Username), but the user has NOT utilized Firefox on this system." | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "User Profile Evaluated: $($UserProfile.Username)" | Out-String
                    $FindingDetails += "" | Out-String

                    $HandlersJson = @(Get-ChildItem -Path "$UserProfilePath\AppData\Roaming\Mozilla\Firefox\Profiles" -Recurse -ErrorAction SilentlyContinue | Where-Object Name -EQ "handlers.json")
                    break
                }
            }
        }
        If ($ProfileFound) {
            If ($HandlersJson) {
                $Config = New-Object System.Collections.Generic.List[System.Object]
                $Json = (Get-Content $HandlersJson.FullName | ConvertFrom-Json).mimeTypes
                ForEach ($Item in $Json.PSObject.Properties) {
                    If ($Item.Value.extensions -in $ExtensionsToEval) {
                        If ($Item.Value.ask -eq $true) {
                            $Action = "Always Ask"
                        }
                        ElseIf ($Item.Value.action -eq 0) {
                            $Action = "Save File"
                        }
                        Else {
                            $Compliant = $false
                            $Action = "NOT set to 'Save File' or 'Always Ask' [Finding]"
                        }
                        $Extensions
                        $Handlers = $Item.Value.handlers

                        $NewObj = [PSCustomObject]@{
                            Extension = $Item.Value.extensions
                            Action    = $Action
                            Handlers  = $Handlers
                        }
                        $Config.Add($NewObj)
                    }
                }
                If ($Config) {
                    $FindingDetails += "The following extensions in question are configured:" | Out-String
                    $FindingDetails += "" | Out-String
                    ForEach ($Item in $Config) {
                        $FindingDetails += "Extension:`t$($Item.Extension)" | Out-String
                        $FindingDetails += "Action:`t`t$($Item.Action)" | Out-String
                        $FindingDetails += "Handlers:`t`t$($Item.Handlers)" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                }
                Else {
                    $FindingDetails += "None of the extensions in question are configured." | Out-String
                }
            }
            Else {
                $FindingDetails += "None of the extensions in question are configured." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        Else {
            $FindingDetails += "NO users have utilized Firefox on this system." | Out-String
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

Function Get-V251551 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251551
        STIG ID    : FFOX-00-000007
        Rule ID    : SV-251551r807125_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to disable form fill assistance.
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
    $RegistryValueName = "DisableFormHistory"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Form History"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DisableFormHistory
        $RegistryResultValue = $Policies_JSON.DisableFormHistory
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251552 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251552
        STIG ID    : FFOX-00-000008
        Rule ID    : SV-251552r822411_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to not use a password store with or without a master password.
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
    $RegistryValueName = "PasswordManagerEnabled"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Password Manager"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.PasswordManagerEnabled
        $RegistryResultValue = $Policies_JSON.PasswordManagerEnabled
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG


        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251553 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251553
        STIG ID    : FFOX-00-000009
        Rule ID    : SV-251553r862958_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to block pop-up windows.
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
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking"  # Registry path identified in STIG
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    # Build list of registry values to check
    $RegistryList = New-Object System.Collections.Generic.List[System.Object]
    $RegistryList.Add([PSCustomObject]@{ValueName = "Default"; Value = @("1", "true"); Type = @("REG_DWORD", "policies.json"); SettingName = "Block pop-ups from websites"; SettingState = "Enabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Locked"; Value = @("1", "true"); Type = @("REG_DWORD", "policies.json"); SettingName = "Do not allow preferences to be changed"; SettingState = "Enabled" })

    ForEach ($Item in $RegistryList) {
        If ($IsLinux) {
            $ExpectedValue = $Item.Value[1]
            $ExpectedType = $Item.Type[1]
            $RegistryResult = [PSCustomObject]@{
                Key       = ""
                ValueName = ""
                Value     = ""
                type      = ""
            }

            if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/etc/firefox/policies/policies.json") {
                $RegistryPath = "/etc/firefox/policies/policies.json"
                $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }

            $RegistryResult.Value = $Policies_JSON.PopupBlocking.$($Item.ValueName)

            if ($null -ne $RegistryResult.Value) {
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }
            $RegistryResultValue = $Policies_JSON.PopupBlocking
        }
        else {
            $ExpectedValue = $Item.Value[0]
            $ExpectedType = $Item.Type[0]
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $Item.ValueName

            If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
                $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
                $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
            }
            Else {
                $RegistryResultValue = $RegistryResult.Value
            }
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $FindingDetails += "'$($Item.SettingName)' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $($Item.Value) -and $RegistryResult.Type -in $($Item.Type)) {
                $FindingDetails += "'$($Item.SettingName)' is $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                If ($RegistryResult.Value -in $($Item.Value)) {
                    $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($($ExpectedValue) -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $($Item.Type)) {
                    $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$($ExpectedType)']" | Out-String
                }
            }
        }
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
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

Function Get-V251554 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251554
        STIG ID    : FFOX-00-000010
        Rule ID    : SV-251554r807134_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to prevent JavaScript from moving or resizing windows.
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
    $RegistryValueName = "Preferences"  # Value name identified in STIG
    $SettingName = "Preferences"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.Preferences | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.Preferences."dom.disable_window_move_resize"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_MULTI_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    # Built configuration item
    $Configuration = New-Object System.Collections.Generic.List[System.Object]
    $Configuration.Add([PSCustomObject]@{Name = "dom.disable_window_move_resize"; Value = "true"; Status = "locked"})

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Type -ne $RegistryType) {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
        }
        Else {
            Try {
                $Json = $RegistryResult.Value | ConvertFrom-Json -ErrorAction Stop
                If (-Not($Json.($Configuration.Name))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but $($Configuration.Name) is not configured" | Out-String
                }
                ElseIf (-Not(($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value -and (($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    If ((($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value)) {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value) [Expected $($Configuration.Value)]" | Out-String
                    }
                    If ((($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status)) {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status) [Expected $($Configuration.Status)]" | Out-String
                    }
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "'$($SettingName)' is $($SettingState):" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                }
            }
            Catch {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
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

Function Get-V251555 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251555
        STIG ID    : FFOX-00-000011
        Rule ID    : SV-251555r807137_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to prevent JavaScript from raising or lowering windows.
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
    $RegistryValueName = "Preferences"  # Value name identified in STIG
    $SettingName = "Preferences"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.Preferences | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.Preferences."dom.disable_window_flip"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_MULTI_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    # Built configuration item
    $Configuration = New-Object System.Collections.Generic.List[System.Object]
    $Configuration.Add([PSCustomObject]@{Name = "dom.disable_window_flip"; Value = "true"; Status = "locked"})

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Type -ne $RegistryType) {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
        }
        Else {
            Try {
                $Json = $RegistryResult.Value | ConvertFrom-Json -ErrorAction Stop
                If (-Not($Json.($Configuration.Name))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but $($Configuration.Name) is not configured" | Out-String
                }
                ElseIf (-Not(($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value -and (($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    If ((($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value)) {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value) [Expected $($Configuration.Value)]" | Out-String
                    }
                    If ((($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status)) {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status) [Expected $($Configuration.Status)]" | Out-String
                    }
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "'$($SettingName)' is $($SettingState):" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                }
            }
            Catch {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
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

Function Get-V251557 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251557
        STIG ID    : FFOX-00-000013
        Rule ID    : SV-251557r820752_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to disable the installation of extensions.
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
    $RegistryValueName = "Default"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Allow add-on installs from websites"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.InstallAddonsPermission.Default | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.InstallAddonsPermission
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\InstallAddonsPermission"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251558 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251558
        STIG ID    : FFOX-00-000014
        Rule ID    : SV-251558r807146_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Background submission of information to Mozilla must be disabled.
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
    $RegistryValueName = "DisableTelemetry"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Telemetry"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DisableTelemetry
        $RegistryResultValue = $Policies_JSON.DisableTelemetry
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251559 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251559
        STIG ID    : FFOX-00-000015
        Rule ID    : SV-251559r807149_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266
        Rule Title : Firefox development tools must be disabled.
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
    $RegistryValueName = "DisableDeveloperTools"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Developer Tools"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DisableDeveloperTools
        $RegistryResultValue = $Policies_JSON.DisableDeveloperTools
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251560 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251560
        STIG ID    : FFOX-00-000016
        Rule ID    : SV-251560r862961_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : Firefox must have the DoD root certificates installed.
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
    If ($IsLinux) {
        $Status = "Not_Reviewed"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Certificates"  # Registry path identified in STIG
        $RegistryValueName = "ImportEnterpriseRoots"  # Value name identified in STIG
        $RegistryValue = @("1", "true")  # Value(s) expected in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Import Enterprise Roots"  # GPO setting name identified in STIG
        $SettingState = "Enabled"  # GPO configured state identified in STIG.

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "" | Out-String

            # Build list of DoD Root CAs
            $CAs = New-Object System.Collections.Generic.List[System.Object]
            $CAs.Add([PSCustomObject]@{CA = "DoD Root CA 2"; Subject = "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US"; Thumbprint = "8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561"; NotAfter = "12/5/2029"})
            $CAs.Add([PSCustomObject]@{CA = "DoD Root CA 3"; Subject = "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US"; Thumbprint = "D73CA91102A2204A36459ED32213B467D7CE97FB"; NotAfter = "12/30/2029"})
            $CAs.Add([PSCustomObject]@{CA = "DoD Root CA 4"; Subject = "CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US"; Thumbprint = "B8269F25DBD937ECAFD4C35A9838571723F2D026"; NotAfter = "7/25/2032"})
            $CAs.Add([PSCustomObject]@{CA = "DoD Root CA 5"; Subject = "CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US"; Thumbprint = "4ECB5CC3095670454DA1CBD410FC921F46B8564B"; NotAfter = "6/14/2041"})

            $InstalledCAs = Get-ChildItem -Path Cert:Localmachine\root | Where-Object Subject -Like "*DoD*" | Select-Object Subject, Thumbprint, NotAfter
            $Compliant = $true
            ForEach ($CA in $CAs) {
                $FindingDetails += "Subject:`t`t$($CA.Subject)" | Out-String
                $FindingDetails += "Thumbprint:`t$($CA.Thumbprint)" | Out-String
                $FindingDetails += "NotAfter:`t`t$($CA.NotAfter)" | Out-String
                If ($InstalledCAs | Where-Object { ($_.Subject -eq $CA.Subject) -and ($_.Thumbprint -eq $CA.Thumbprint) }) {
                    $FindingDetails += "Installed:`t`t$true" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "Installed:`t`t$false" | Out-String
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

Function Get-V251562 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251562
        STIG ID    : FFOX-00-000018
        Rule ID    : SV-251562r849961_rule
        CCI ID     : CCI-002355
        Rule Name  : SRG-APP-000326
        Rule Title : Firefox must prevent the user from quickly deleting data.
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
    $RegistryValueName = "DisableForgetButton"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Forget Button"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DisableForgetButton
        $RegistryResultValue = $Policies_JSON.DisableForgetButton
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251563 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251563
        STIG ID    : FFOX-00-000019
        Rule ID    : SV-251563r807161_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox private browsing must be disabled.
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
    $RegistryValueName = "DisablePrivateBrowsing"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Private Browsing"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DisablePrivateBrowsing
        $RegistryResultValue = $Policies_JSON.DisablePrivateBrowsing
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251564 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251564
        STIG ID    : FFOX-00-000020
        Rule ID    : SV-251564r807164_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox search suggestions must be disabled.
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
    $RegistryValueName = "SearchSuggestEnabled"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Search Suggestions"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.SearchSuggestEnabled
        $RegistryResultValue = $Policies_JSON.SearchSuggestEnabled
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251565 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251565
        STIG ID    : FFOX-00-000021
        Rule ID    : SV-251565r832307_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox autoplay must be disabled.
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
    $RegistryValueName = "Default"  # Value name identified in STIG
    $RegistryValue = @("block-audio-video")  # Value(s) expected in STIG
    $SettingName = "Default autoplay level"  # GPO setting name identified in STIG
    $SettingState = "Enabled (Block Audio and Video)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.Permissions.AutoPlay.Default
        $RegistryResultValue = $Policies_JSON.Permissions.Autoplay
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay"  # Registry path identified in STIG
        $RegistryType = "REG_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251566 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251566
        STIG ID    : FFOX-00-000022
        Rule ID    : SV-251566r807170_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox network prediction must be disabled.
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
    $RegistryValueName = "NetworkPrediction"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Network Prediction"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.NetworkPrediction
        $RegistryResultValue = $Policies_JSON.NetworkPrediction
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251567 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251567
        STIG ID    : FFOX-00-000023
        Rule ID    : SV-251567r807173_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox fingerprinting protection must be enabled.
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
    $RegistryValueName = "Fingerprinting"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Fingerprinting"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.EnableTrackingProtection.Fingerprinting
        $RegistryResultValue = $Policies_JSON.EnableTrackingProtection
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251568 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251568
        STIG ID    : FFOX-00-000024
        Rule ID    : SV-251568r807176_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox cryptomining protection must be enabled.
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
    $RegistryValueName = "Cryptomining"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Cryptomining"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.EnableTrackingProtection.Cryptomining
        $RegistryResultValue = $Policies_JSON.EnableTrackingProtection
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251569 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251569
        STIG ID    : FFOX-00-000025
        Rule ID    : SV-251569r807179_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox Enhanced Tracking Protection must be enabled.
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
    $RegistryValueName = "Preferences"  # Value name identified in STIG
    $SettingName = "Preferences"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.Preferences | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.Preferences."browser.contentblocking.category"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_MULTI_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    # Built configuration item
    $Configuration = New-Object System.Collections.Generic.List[System.Object]
    $Configuration.Add([PSCustomObject]@{Name = "browser.contentblocking.category"; Value = "strict"; Status = "locked"})

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Type -ne $RegistryType) {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
        }
        Else {
            Try {
                $Json = $RegistryResult.Value | ConvertFrom-Json -ErrorAction Stop
                If (-Not($Json.($Configuration.Name))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but $($Configuration.Name) is not configured" | Out-String
                }
                ElseIf (-Not(($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value -and (($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    If ((($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value)) {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value) [Expected $($Configuration.Value)]" | Out-String
                    }
                    If ((($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status)) {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status) [Expected $($Configuration.Status)]" | Out-String
                    }
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "'$($SettingName)' is $($SettingState):" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                }
            }
            Catch {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
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

Function Get-V251570 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251570
        STIG ID    : FFOX-00-000026
        Rule ID    : SV-251570r820759_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox extension recommendations must be disabled.
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
    $RegistryValueName = "Preferences"  # Value name identified in STIG
    $SettingName = "Preferences"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.Preferences | ConvertTo-Json
        $RegistryResultValue = $Policies_JSON.Preferences."extensions.htmlaboutaddons.recommendations.enabled"
    }
    Else {
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_MULTI_SZ"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    # Built configuration item
    $Configuration = New-Object System.Collections.Generic.List[System.Object]
    $Configuration.Add([PSCustomObject]@{Name = "extensions.htmlaboutaddons.recommendations.enabled"; Value = "false"; Status = "locked" })

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Type -ne $RegistryType) {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
        }
        Else {
            Try {
                $Json = $RegistryResult.Value | ConvertFrom-Json -ErrorAction Stop
                If (-Not($Json.($Configuration.Name))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but $($Configuration.Name) is not configured" | Out-String
                }
                ElseIf (-Not(($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value -and (($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status))) {
                    $Status = "Open"
                    $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    If ((($Json.($Configuration.Name).Value).ToString() -eq $Configuration.Value)) {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value) [Expected $($Configuration.Value)]" | Out-String
                    }
                    If ((($Json.($Configuration.Name).Status).ToString() -eq $Configuration.Status)) {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                    }
                    Else {
                        $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status) [Expected $($Configuration.Status)]" | Out-String
                    }
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "'$($SettingName)' is $($SettingState):" | Out-String
                    $FindingDetails += $Configuration.Name | Out-String
                    $FindingDetails += "Value:`t$($Json.($Configuration.Name).Value)" | Out-String
                    $FindingDetails += "Status:`t$($Json.($Configuration.Name).Status)" | Out-String
                }
            }
            Catch {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState) but not correct:" | Out-String
            }
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
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

Function Get-V251571 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251571
        STIG ID    : FFOX-00-000027
        Rule ID    : SV-251571r820762_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox deprecated ciphers must be disabled.
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
    $RegistryValueName = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DisabledCiphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA
        $RegistryResultValue = $Policies_JSON.DisabledCiphers
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251572 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251572
        STIG ID    : FFOX-00-000028
        Rule ID    : SV-251572r807188_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must not recommend extensions as the user is using the browser.
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
    $RegistryValueName = "ExtensionRecommendations"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Extension Recommendations"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.UserMessaging.ExtensionRecommendations
        $RegistryResultValue = $Policies_JSON.UserMessaging
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\UserMessaging"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251573 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251573
        STIG ID    : FFOX-00-000029
        Rule ID    : SV-251573r822781_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : The Firefox New Tab page must not show Top Sites, Sponsored Top Sites, Pocket Recommendations, Sponsored Pocket Stories, Searches, Highlights, or Snippets.
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
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    # Build list of registry values to check
    $RegistryList = New-Object System.Collections.Generic.List[System.Object]
    $RegistryList.Add([PSCustomObject]@{ValueName = "Search"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Search"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "TopSites"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Top Sites"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "SponsoredTopSites"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Sponsored Top Sites"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Pocket"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Recommended by Pocket"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "SponsoredPocket"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Sponsored Pocket Stories"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Highlights"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Download History"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Snippets"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Snippets"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Locked"; Value = @("1", "true"); Type = @("REG_DWORD", "policies.json"); SettingName = "Do not allow settings to be changed"; SettingState = "Enabled" })

    ForEach ($Item in $RegistryList) {
        If ($IsLinux) {
            $ExpectedValue = $Item.Value[1]
            $ExpectedType  = $Item.Type[1]
            $RegistryResult = [PSCustomObject]@{
                Key       = ""
                ValueName = ""
                Value     = ""
                type      = ""
            }

            if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/etc/firefox/policies/policies.json") {
                $RegistryPath = "/etc/firefox/policies/policies.json"
                $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }

            $RegistryResult.Value = $Policies_JSON.FirefoxHome.$($Item.ValueName)

            if ($null -ne $RegistryResult.Value) {
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }
            $RegistryResultValue = $Policies_JSON.FirefoxHome
        }
        else {
            $ExpectedValue = $Item.Value[0]
            $ExpectedType  = $Item.Type[0]
            $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome"  # Registry path identified in STIG

            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $Item.ValueName

            If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
                $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
                $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
            }
            Else {
                $RegistryResultValue = $RegistryResult.Value
            }
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $FindingDetails += "'$($Item.SettingName)' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $($Item.Value) -and $RegistryResult.Type -in $($Item.Type)) {
                $FindingDetails += "'$($Item.SettingName)' is $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                If ($RegistryResult.Value -in $($Item.Value)) {
                    $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($($ExpectedValue) -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -in $($Item.Type)) {
                    $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$($ExpectedType )']" | Out-String
                }
            }
        }
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
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

Function Get-V251577 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251577
        STIG ID    : FFOX-00-000033
        Rule ID    : SV-251577r807203_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured so that DNS over HTTPS is disabled.
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
    $RegistryValueName = "Enabled"  # Value name identified in STIG
    $RegistryValue = @("0", "false")  # Value(s) expected in STIG
    $SettingName = "Enabled"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DNSOverHTTPS.Enabled
        $RegistryResultValue = $Policies_JSON.DNSOverHTTPS
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251578 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251578
        STIG ID    : FFOX-00-000034
        Rule ID    : SV-251578r807206_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox accounts must be disabled.
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
    $RegistryValueName = "DisableFirefoxAccounts"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Firefox Accounts"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DisableFirefoxAccounts
        $RegistryResultValue = $Policies_JSON.DisableFirefoxAccounts
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251580 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251580
        STIG ID    : FFOX-00-000036
        Rule ID    : SV-251580r809561_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox feedback reporting must be disabled.
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
    $RegistryValueName = "DisableFeedbackCommands"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Feedback Commands"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DisableFeedbackCommands
        $RegistryResultValue = $Policies_JSON.DisableFeedbackCommands
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V251581 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251581
        STIG ID    : FFOX-00-000037
        Rule ID    : SV-251581r807215_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox encrypted media extensions must be disabled.
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
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EncryptedMediaExtensions"  # Registry path identified in STIG
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    # Build list of registry values to check
    $RegistryList = New-Object System.Collections.Generic.List[System.Object]
    $RegistryList.Add([PSCustomObject]@{ValueName = "Enabled"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Enable Encrypted Media Extensions"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Locked"; Value = @("1", "true"); Type = @("REG_DWORD", "policies.json"); SettingName = "Lock Encrypted Media Extensions"; SettingState = "Enabled" })

    ForEach ($Item in $RegistryList) {
        If ($IsLinux) {
            $ExpectedValue = $Item.Value[1]
            $ExpectedType  = $Item.Type[1]
            $RegistryResult = [PSCustomObject]@{
                Key       = ""
                ValueName = ""
                Value     = ""
                type      = ""
            }

            if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/etc/firefox/policies/policies.json") {
                $RegistryPath = "/etc/firefox/policies/policies.json"
                $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }

            $RegistryResult.Value = $Policies_JSON.EncryptedMediaExtensions.$($Item.ValueName)

            if ($null -ne $RegistryResult.Value) {
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }
            $RegistryResultValue = $Policies_JSON.EncryptedMediaExtensions
        }
        else {
            $ExpectedValue = $Item.Value[0]
            $ExpectedType  = $Item.Type[0]
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $Item.ValueName

            If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
                $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
                $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
            }
            Else {
                $RegistryResultValue = $RegistryResult.Value
            }
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $FindingDetails += "'$($Item.SettingName)' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $($Item.Value) -and $RegistryResult.Type -in $($Item.Type)) {
                $FindingDetails += "'$($Item.SettingName)' is $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                If ($RegistryResult.Value -in $($Item.Value)) {
                    $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($($ExpectedValue) -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $($Item.Type)) {
                    $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$($ExpectedType)']" | Out-String
                }
            }
        }
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
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

Function Get-V252881 {
    <#
    .DESCRIPTION
        Vuln ID    : V-252881
        STIG ID    : FFOX-00-000017
        Rule ID    : SV-252881r820757_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox must be configured to not delete data upon shutdown.
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
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    # Build list of registry values to check
    $RegistryList = New-Object System.Collections.Generic.List[System.Object]
    $RegistryList.Add([PSCustomObject]@{ValueName = "Sessions"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Active Logins"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "History"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Browsing History"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Cache"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Cache"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Cookies"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Cookies"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Downloads"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Download History"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "FormData"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Form & Search History"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "Locked"; Value = @("1", "true"); Type = @("REG_DWORD", "policies.json"); SettingName = "Locked"; SettingState = "Enabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "OfflineApps"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Offline Website Data"; SettingState = "Disabled" })
    $RegistryList.Add([PSCustomObject]@{ValueName = "SiteSettings"; Value = @("0", "false"); Type = @("REG_DWORD", "policies.json"); SettingName = "Site Preferences"; SettingState = "Disabled" })

    ForEach ($Item in $RegistryList) {
        If ($IsLinux) {
            $ExpectedValue = $Item.Value[1]
            $ExpectedType  = $Item.Type[1]
            $RegistryResult = [PSCustomObject]@{
                Key       = ""
                ValueName = ""
                Value     = ""
                type      = ""
            }

            if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
                $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
                $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            elseif (Test-Path "/etc/firefox/policies/policies.json") {
                $RegistryPath = "/etc/firefox/policies/policies.json"
                $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }

            $RegistryResult.Value = $Policies_JSON.SanitizeOnShutdown.$($Item.ValueName)

            if ($null -ne $RegistryResult.Value) {
                $RegistryResult.Type = "policies.json"
            }
            else {
                $RegistryResult.Type = "(NotFound)"
            }
            $RegistryResultValue = $Policies_JSON.SanitizeOnShutdown
        }
        else {
            $ExpectedValue = $Item.Value[0]
            $ExpectedType  = $Item.Type[0]
            $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown"  # Registry path identified in STIG

            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $Item.ValueName

            If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
                $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
                $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
            }
            Else {
                $RegistryResultValue = $RegistryResult.Value
            }
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $FindingDetails += "'$($Item.SettingName)' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName) (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $($Item.Value) -and $RegistryResult.Type -in $($Item.Type)) {
                $FindingDetails += "'$($Item.SettingName)' is $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "'$($Item.SettingName)' is NOT $($Item.SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
                $FindingDetails += "Name:`t$($Item.ValueName)" | Out-String
                If ($RegistryResult.Value -in $($Item.Value)) {
                    $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($($ExpectedValue) -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $($Item.Type)) {
                    $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$($ExpectedType)']" | Out-String
                }
            }
        }
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
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

Function Get-V252908 {
    <#
    .DESCRIPTION
        Vuln ID    : V-252908
        STIG ID    : FFOX-00-000038
        Rule ID    : SV-252908r836395_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Pocket must be disabled.
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
    $RegistryValueName = "DisablePocket"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Pocket"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DisablePocket
        $RegistryResultValue = $Policies_JSON.DisablePocket
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V252909 {
    <#
    .DESCRIPTION
        Vuln ID    : V-252909
        STIG ID    : FFOX-00-000039
        Rule ID    : SV-252909r836408_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Firefox Studies must be disabled.
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
    $RegistryValueName = "DisableFirefoxStudies"  # Value name identified in STIG
    $RegistryValue = @("1", "true")  # Value(s) expected in STIG
    $SettingName = "Disable Firefox Studies"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($IsLinux) {
        $RegistryValue = $RegistryValue[1]
        $RegistryResult = [PSCustomObject]@{
            Key       = ""
            ValueName = ""
            Value     = ""
            type      = ""
        }
        $SettingNotConfiguredAllowed = $false
        $RegistryType = "policies.json"

        if (Test-Path "/usr/lib64/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib64/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib64/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/usr/lib/firefox/distribution/policies.json") {
            $RegistryPath = "/usr/lib/firefox/distribution/policies.json"
            $Policies_JSON = (Get-Content /usr/lib/firefox/distribution/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        elseif (Test-Path "/etc/firefox/policies/policies.json") {
            $RegistryPath = "/etc/firefox/policies/policies.json"
            $Policies_JSON = (Get-Content /etc/firefox/policies/policies.json | ConvertFrom-Json).policies
            $RegistryResult.Type = "policies.json"
        }
        else {
            $RegistryResult.Type = "(NotFound)"
        }

        $RegistryResult.Value = $Policies_JSON.DisableFirefoxStudies
        $RegistryResultValue = $Policies_JSON.DisableFirefoxStudies
    }
    Else {
        $RegistryValue = $RegistryValue[0]
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  # Registry path identified in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG

        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path:`t`t$RegistryPath" | Out-String
            $FindingDetails += "Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAjD5L8vswGx6sj
# x/U3R8z17f2qAF40ZF42RxErRxaOYaCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDsg6QplsE0iFduvYXNUixhRcoc3Y9g
# YEnYPT99YVbATDANBgkqhkiG9w0BAQEFAASCAQC5OZRN7gVtVNWHFk/2UTSyU9Aq
# HrcNEWqM7LCwtrFTMLwmysKqU1JIed0jA/7rp4Mafnk/K1c1B4tnIP9hxepZqxeK
# zBhwJl9HzVBL+ZqyQaDtUAi+lI8YGANhgDwxRtyTkOOQztAtmBi06egBgWsjftN1
# FDgiIuJlOD4DPG6rLczc4R8HZ//v7uwlxzHiP+WfqGkmf6JuER8WdMn/8p1zrUg2
# Yb3FPY3Ze8CoMq73uxy2jp8EglVL3Zz3c3Rwuh/7kQiEmf/NIieKgyHDfQP2C5cJ
# 6YmUEY/AEdXhaCxYT4rxZn3SsfVVX4yBNsDYM7RTd/Q6orjhlp3m8u/r7eaJ
# SIG # End signature block
