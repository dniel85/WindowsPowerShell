##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft IIS 10.0 Server
# Version:  V2R9
# Class:    UNCLASSIFIED
# Updated:  4/26/2023
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V218785 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218785
        STIG ID    : IIST-SV-000102
        Rule ID    : SV-218785r879562_rule
        CCI ID     : CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-001462, CCI-001464
        Rule Name  : SRG-APP-000092-WSR-000055
        Rule Title : The enhanced logging for the IIS 10.0 web server must be enabled and capture all user and web server events.
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
    $FlagsToCheck = ("Date", "Time", "ClientIP", "UserName", "Method", "URIQuery", "HttpStatus", "Referer")
    $MissingFlags = ""
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }
    $LogFlags = $Log.logExtFileFlags -split ","

    Foreach ($Flag in $FlagsToCheck) {
        If ($Flag -notin $LogFlags) {
            $Compliant = $false
            $MissingFlags += $Flag | Out-String
        }
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer are all logged." | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "The following minimum fields are not logged:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $MissingFlags | Out-String
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

Function Get-V218786 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218786
        STIG ID    : IIST-SV-000103
        Rule ID    : SV-218786r879562_rule
        CCI ID     : CCI-000139, CCI-001464, CCI-001851
        Rule Name  : SRG-APP-000092-WSR-000055
        Rule Title : Both the log file and Event Tracing for Windows (ETW) for the IIS 10.0 web server must be enabled.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }
    $LogTargetFormat = $Log.logTargetW3C

    If ($logTargetFormat -like "*ETW*" -and $logTargetFormat -like "*File*") {
        $FindingDetails += "Both ETW and Log file logging are enabled." | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "$LogTargetFormat is the only option selected." | Out-String
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

Function Get-V218788 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218788
        STIG ID    : IIST-SV-000110
        Rule ID    : SV-218788r879567_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-APP-000099-WSR-000061
        Rule Title : The IIS 10.0 web server must produce log records that contain sufficient information to establish the outcome (success or failure) of IIS 10.0 web server events.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }

    $customField1_logged = $false # the custom "Connection" field we're looking for
    $customField2_logged = $false # the custom "Warning" field we're looking for

    If ($Log.logFormat -ne "W3C") {
        $Status = "Open"
        $FindingDetails += "Log format is '$($Log.logFormat)' [Expected 'W3C']" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $FindingDetails += "Log format is '$($Log.logFormat)'" | Out-String
        $FindingDetails += "" | Out-String
    }

    ForEach ($Item in $Log.customFields.Collection) {
        If ($Item.sourceType -eq "RequestHeader" -and $Item.sourceName -eq "Connection") {
            $customField1_logged = $true
        }
        ElseIf ($Item.sourceType -eq "RequestHeader" -and $Item.sourceName -eq "Warning") {
            $customField2_logged = $true
        }
    }

    If ($customField1_logged -eq $true) {
        $FindingDetails += "The 'Request Header >> Connection' custom field is configured." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "The 'Request Header >> Connection' custom field is NOT configured." | Out-String
        $FindingDetails += "" | Out-String
    }

    If ($customField2_logged -eq $true) {
        $FindingDetails += "The 'Request Header >> Warning' custom field is configured." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "The 'Request Header >> Warning' custom field is NOT configured." | Out-String
        $FindingDetails += "" | Out-String
    }

    If ($Status -ne "Open") {
        # if we never marked a site as failing, then we pass the whole check.
        $Status = 'NotAFinding'
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

Function Get-V218789 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218789
        STIG ID    : IIST-SV-000111
        Rule ID    : SV-218789r879568_rule
        CCI ID     : CCI-001487
        Rule Name  : SRG-APP-000100-WSR-000064
        Rule Title : The IIS 10.0 web server must produce log records containing sufficient information to establish the identity of any user/subject or process associated with an event.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }

    $LogFlags = $Log.logExtFileFlags -Split ","
    $FlagsToCheck = ("UserAgent", "UserName", "Referer")
    $MissingFlags = ""
    $customField1_logged = $false # the custom "Authorization" field we're looking for
    $customField2_logged = $false # the custom "Content-Type" field we're looking for

    If ($Log.logFormat -ne "W3C") {
        $Status = "Open"
        $FindingDetails += "Log format is '$($Log.logFormat)' [Expected 'W3C']" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $FindingDetails += "Log format is '$($Log.logFormat)'" | Out-String
        $FindingDetails += "" | Out-String

        # check the standard fields first
        Foreach ($Flag in $FlagsToCheck) {
            If ($Flag -notin $LogFlags) {
                $MissingFlags += $Flag | Out-String
            }
        }

        If ($MissingFlags) {
            $Status = "Open"
            $FindingDetails += "The following minimum fields are not logged:" | Out-String
            $FindingDetails += $MissingFlags | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $FindingDetails += "User Agent, User Name, and Referrer are all logged." | Out-String
            $FindingDetails += "" | Out-String
        }

        ForEach ($Item in $Log.customFields.Collection) {
            If ($Item.sourceType -eq "RequestHeader" -and $Item.sourceName -eq "Authorization") {
                $customField1_logged = $true
            }
            ElseIf ($Item.sourceType -eq "ResponseHeader" -and $Item.sourceName -eq "Content-Type") {
                $customField2_logged = $true
            }
        }

        If ($customField1_logged -eq $true) {
            $FindingDetails += "The 'Request Header >> Authorization' custom field is configured." | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "The 'Request Header >> Authorization' custom field is NOT configured." | Out-String
            $FindingDetails += "" | Out-String
        }

        If ($customField2_logged -eq $true) {
            $FindingDetails += "The 'Response Header >> Content-Type' custom field is configured." | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "The 'Response Header >> Content-Type' custom field is NOT configured." | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    If ($Status -ne "Open") {
        # if we never marked a site as failing, then we pass the whole check.
        $Status = 'NotAFinding'
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

Function Get-V218790 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218790
        STIG ID    : IIST-SV-000115
        Rule ID    : SV-218790r879578_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-APP-000120-WSR-000070
        Rule Title : The log information from the IIS 10.0 web server must be protected from unauthorized modification or deletion.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }
    $LogPath = $Log.directory -replace "%SystemDrive%", $env:SYSTEMDRIVE
    If (Test-Path $LogPath) {
        $acl = Get-Acl -Path $LogPath
        $FindingDetails += "Current ACL of $LogPath is:" | Out-String
        $FindingDetails += $acl.Access | Format-List | Out-String
    }
    Else {
        $FindingDetails += "'$LogPath' does not exist." | Out-String
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

Function Get-V218791 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218791
        STIG ID    : IIST-SV-000116
        Rule ID    : SV-218791r879582_rule
        CCI ID     : CCI-001348
        Rule Name  : SRG-APP-000125-WSR-000071
        Rule Title : The log data and records from the IIS 10.0 web server must be backed up onto a different system or media.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }
    $LogPath = $Log.directory
    $FindingDetails += "Log Directory: $LogPath" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Ensure the logs in the directory above are being backed up." | Out-String
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

Function Get-V218793 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218793
        STIG ID    : IIST-SV-000118
        Rule ID    : SV-218793r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000075
        Rule Title : The IIS 10.0 web server must only contain functions necessary for operation.
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
    $SoftwareList = Get-InstalledSoftware
    $FindingDetails += "Software installed on this system:" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += $SoftwareList.DisplayName | Sort-Object | Out-String
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

Function Get-V218794 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218794
        STIG ID    : IIST-SV-000119
        Rule ID    : SV-218794r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000076
        Rule Title : The IIS 10.0 web server must not be both a website server and a proxy server.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        If (Get-WebConfiguration /webFarms/applicationRequestRouting) {
            $Proxy = Get-WebConfigurationProperty '/system.webServer/proxy' -Name enabled
            $FindingDetails += "Application Request Routing is installed." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Proxy Enabled: $($Proxy.Value)" | Out-String
            If ($Proxy.Value -eq $true) {
                $Status = "Open"
            }
            Else {
                $Status = "NotAFinding"
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "Application Request Routing is not installed." | Out-String
        }
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration /webFarms/applicationRequestRouting}"
        $ARR = Invoke-Expression $PSCommand
        If ($ARR) {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/proxy' -Name enabled}"
            $Proxy = Invoke-Expression $PSCommand
            $FindingDetails += "Application Request Routing is installed." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Proxy Enabled: $($Proxy.Value)" | Out-String
            If ($Proxy.Value -eq $true) {
                $Status = "Open"
            }
            Else {
                $Status = "NotAFinding"
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "Application Request Routing is not installed." | Out-String
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

Function Get-V218795 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218795
        STIG ID    : IIST-SV-000120
        Rule ID    : SV-218795r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000077
        Rule Title : All IIS 10.0 web server sample code, example applications, and tutorials must be removed from a production IIS 10.0 server.
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
    $ListOfSamples = ""
    $Drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" | Select-Object DeviceID
    $Paths = @("inetpub\", "Program Files\Common Files\System\msadc", "Program Files (x86)\Common Files\System\msadc")

    ForEach ($Drive in $Drives) {
        ForEach ($Path in $Paths) {
            $SearchPath = $Drive.DeviceID + "\" + $Path
            $FileSearch = Get-ChildItem -Path $SearchPath -Recurse -Filter *sample* -ErrorAction SilentlyContinue
            If ($FileSearch) {
                ForEach ($File in $FileSearch) {
                    $ListOfSamples += $File.FullName | Out-String
                }
            }
        }
    }

    If ($ListOfSamples -ne "") {
        $FindingDetails += "The following sample files were found:" | Out-String
        $FindingDetails += "" | Out-String
        ForEach ($File in $ListOfSamples) {
            $FindingDetails += $File
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "There are no sample files in the targeted directories." | Out-String
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

Function Get-V218796 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218796
        STIG ID    : IIST-SV-000121
        Rule ID    : SV-218796r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000078
        Rule Title : The accounts created by uninstalled features (i.e., tools, utilities, specific, etc.) must be deleted from the IIS 10.0 server.
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
    $FindingDetails += "Local user accounts on this system:" | Out-String
    $FindingDetails += "" | Out-String
    $server = ${env:computername}
    $computer = [ADSI]"WinNT://$server,computer"
    $computer.psbase.children | Where-Object { $_.psbase.schemaClassname -eq 'user' } | ForEach-Object {
        $FindingDetails += $_.Name | Out-String
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

Function Get-V218797 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218797
        STIG ID    : IIST-SV-000123
        Rule ID    : SV-218797r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000080
        Rule Title : The IIS 10.0 web server must be reviewed on a regular basis to remove any Operating System features, utility programs, plug-ins, and modules not necessary for operation.
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
    Switch -Wildcard (((Get-CimInstance Win32_OperatingSystem).Caption)) {
        "*Windows*Server*" {
            $Features = (Get-WindowsFeature | Where-Object Installed -EQ $true | Sort-Object Name).Name
        }
        "*Windows*10*" {
            Try {
                $Features = (Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object State -EQ "Enabled" | Sort-Object FeatureName).FeatureName
            }
            Catch {
                $Features = (Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object InstallState -EQ 1 | Sort-Object Name).Name
            }
        }
    }

    $FindingDetails += "The following Windows features are installed:" | Out-String
    $FindingDetails += "" | Out-String
    ForEach ($Feature in $Features) {
        $FindingDetails += $Feature | Out-String
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

Function Get-V218798 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218798
        STIG ID    : IIST-SV-000124
        Rule ID    : SV-218798r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000081
        Rule Title : The IIS 10.0 web server must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Configuration = (Get-WebConfiguration /system.webServer/staticContent).Collection
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; (Get-WebConfiguration /system.webServer/staticContent).Collection}"
        $Configuration = Invoke-Expression $PSCommand
    }
    $ExtensionFindings = ""
    $ExtensionsToCheck = @(".exe", ".dll", ".com", ".bat", ".csh")
    ForEach ($Extension in $ExtensionsToCheck) {
        If ($Configuration | Where-Object fileExtension -EQ $Extension) {
            $Compliant = $false
            $ExtensionFindings += $Extension | Out-String
        }
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "No invalid MIME types for OS shell program extensions found."
    }
    Else {
        $Status = "Open"
        $FindingDetails += "The following invalid MIME types for OS shell program extensions are configured:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $ExtensionFindings | Out-String
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

Function Get-V218799 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218799
        STIG ID    : IIST-SV-000125
        Rule ID    : SV-218799r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000085
        Rule Title : The IIS 10.0 web server must have Web Distributed Authoring and Versioning (WebDAV) disabled.
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
    Switch -Wildcard (((Get-CimInstance Win32_OperatingSystem).Caption)) {
        "*Windows*Server*" {
            If ((Get-WindowsFeature -Name "Web-DAV-Publishing").Installed -eq $true) {
                $Status = "Open"
                $FindingDetails += "Web-DAV-Publishing is installed."
            }
        }
        "*Windows*10*" {
            Try {
                If ((Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebDAV" -ErrorAction Stop).State -eq "Enabled") {
                    $Status = "Open"
                    $FindingDetails += "IIS-WebDAV is enabled."
                }
            }
            Catch {
                If ((Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object Name -EQ "IIS-WebDAV").InstallState -eq 1) {
                    $Status = "Open"
                    $FindingDetails += "IIS-WebDAV is enabled."
                }
            }
        }
    }

    If ($Status -ne "Open") {
        $Status = "NotAFinding"
        $FindingDetails += "WebDAV is not installed."
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

Function Get-V218800 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218800
        STIG ID    : IIST-SV-000129
        Rule ID    : SV-218800r879612_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175-WSR-000095
        Rule Title : The IIS 10.0 web server must perform RFC 5280-compliant certification path validation.
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
    $CertList = ""

    $Certs = Get-ChildItem Cert:\LocalMachine\My | Select-Object *
    ForEach ($Cert in $Certs) {
        If (([string]::IsNullOrEmpty($Cert.EnhancedKeyUsageList.FriendlyName)) -or ($Cert.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication")) {
            If ($Cert.Issuer -notlike "*DoD*") {
                $Compliant = $false
            }
            $CertList += "Name:`t`t$($Cert.FriendlyName)" | Out-String
            $CertList += "Subject:`t`t$($Cert.Subject)" | Out-String
            $CertList += "Issuer:`t`t$($Cert.Issuer)" | Out-String
            $CertList += "Thumbprint:`t$($Cert.Thumbprint)" | Out-String
            $CertList += "Expiration:`t$($Cert.NotAfter)" | Out-String
            $CertList += "" | Out-String
        }
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "All certificates are DoD issued:" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Non-DoD issued certificates found:" | Out-String
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += $CertList
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

Function Get-V218801 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218801
        STIG ID    : IIST-SV-000130
        Rule ID    : SV-218801r879627_rule
        CCI ID     : CCI-001166
        Rule Name  : SRG-APP-000206-WSR-000128
        Rule Title : Java software installed on a production IIS 10.0 web server must be limited to .class files and the Java Virtual Machine.
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
    $FileFindings = ""
    $Drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" | Select-Object DeviceID

    ForEach ($Drive in $Drives) {
        $BadFiles = (Get-ChildItem "$($Drive.DeviceID)\" -File -Recurse -Filter *.j??? -ErrorAction SilentlyContinue | Where-Object { ($_.FullName -NotLike "*Windows\CSC\*") -and ($_.FullName -NotLike "*Windows\WinSxS\*") -and ($_.Extension -in ".java", ".jpp") }).FullName
        If ($BadFiles) {
            ForEach ($File in $BadFiles) {
                $FileFindings += $File | Out-String
            }
        }
    }

    If ($FileFindings -eq $null -or $FileFindings -eq "") {
        $FindingDetails += "No .java or .jpp files were found on the system." | Out-String
        $Status = 'NotAFinding'
    }
    Else {
        $FindingDetails += "The following .java and/or .jpp files were found:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $FileFindings | Out-String
        $Status = 'Open'
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

Function Get-V218802 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218802
        STIG ID    : IIST-SV-000131
        Rule ID    : SV-218802r879631_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-WSR-000030
        Rule Title : IIS 10.0 Web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.
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
    $server = ($env:COMPUTERNAME)
    $computer = [ADSI]"WinNT://$server,computer"

    $FindingDetails += "Below is a list of local groups and their members (if any):" | Out-String
    $FindingDetails += "" | Out-String

    $computer.psbase.children | Where-Object { $_.psbase.schemaClassname -eq 'group' } | ForEach-Object {
        $FindingDetails += "Group:`t" + $_.name | Out-String
        $group = [ADSI]$_.psbase.path
        $group = [ADSI]$_.psbase.path
        $group.psbase.Invoke("Members") | ForEach-Object {
            $Member = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
            If ($Member) {
                $FindingDetails += "  $($Member)" | Out-String
            }
        }
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

Function Get-V218804 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218804
        STIG ID    : IIST-SV-000134
        Rule ID    : SV-218804r879638_rule
        CCI ID     : CCI-001664
        Rule Name  : SRG-APP-000223-WSR-000011
        Rule Title : The IIS 10.0 web server must use cookies to track session state.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $SessionState = Get-WebConfiguration /system.web/sessionState | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration /system.web/sessionState | Select-Object *}"
        $SessionState = Invoke-Expression $PSCommand
    }

    If ($SessionState.cookieless -eq "UseCookies") {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "Cookie Settings Mode is configured to '$($SessionState.cookieless)'" | Out-String
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

Function Get-V218805 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218805
        STIG ID    : IIST-SV-000135
        Rule ID    : SV-218805r879638_rule
        CCI ID     : CCI-001664
        Rule Name  : SRG-APP-000223-WSR-000145
        Rule Title : The IIS 10.0 web server must accept only system-generated session identifiers.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $SessionState = Get-WebConfiguration /system.web/sessionState | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration /system.web/sessionState | Select-Object *}"
        $SessionState = Invoke-Expression $PSCommand
    }

    $MinTimeout = New-TimeSpan -Hours 00 -Minutes 20 -Seconds 00

    If (($SessionState.cookieless -eq "UseCookies") -and ($SessionState.timeout.CompareTo($MinTimeout) -le 0)) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "Cookie Settings Mode is configured to '$($SessionState.cookieless)'" | Out-String
    $FindingDetails += "Time-out is configured to '$($SessionState.timeout)'" | Out-String
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

Function Get-V218807 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218807
        STIG ID    : IIST-SV-000137
        Rule ID    : SV-218807r879642_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-WSR-000144
        Rule Title : The production IIS 10.0 web server must utilize SHA2 encryption for the Machine Key.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $MachineKey = Get-WebConfiguration /system.web/machineKey | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration /system.web/machineKey | Select-Object *}"
        $MachineKey = Invoke-Expression $PSCommand
    }

    If (($MachineKey.validation -like "*HMAC*") -and ($MachineKey.decryption -eq "Auto")) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "Validation method is configured to '$($MachineKey.validation)'" | Out-String
    $FindingDetails += "Encryption method is configured to '$($MachineKey.decryption)'" | Out-String
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

Function Get-V218808 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218808
        STIG ID    : IIST-SV-000138
        Rule ID    : SV-218808r879652_rule
        CCI ID     : CCI-001310
        Rule Name  : SRG-APP-000251-WSR-000157
        Rule Title : Directory Browsing on the IIS 10.0 web server must be disabled.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $DirectoryBrowse = Get-WebConfiguration /system.webServer/directoryBrowse | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration /system.webServer/directoryBrowse | Select-Object *}"
        $DirectoryBrowse = Invoke-Expression $PSCommand
    }

    If ($DirectoryBrowse.enabled -like "*False*") {
        $Status = "NotAFinding"
        $FindingDetails += "Directory Browsing is disabled." | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Directory Browsing is NOT disabled." | Out-String
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

Function Get-V218809 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218809
        STIG ID    : IIST-SV-000139
        Rule ID    : SV-218809r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000142
        Rule Title : The IIS 10.0 web server Indexing must only index web content.
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
    $indexKey = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\ContentIndex\Catalogs" -ErrorAction SilentlyContinue | Out-String
    If ($indexKey -eq '') {
        #failed return of the registry key value leaves an empty string and not NULL
        $FindingDetails += "The ContentIndex\Catalogs key does not exist so this check is Not Applicable." | Out-String
        $Status = 'Not_Applicable'
    }
    Else {
        $FindingDetails += "The contentIndex key exists." | Out-String
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

Function Get-V218810 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218810
        STIG ID    : IIST-SV-000140
        Rule ID    : SV-218810r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 10.0 web server, patches, loaded modules, and directory paths.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $HttpErrors = Get-WebConfiguration system.webServer/httpErrors | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration system.webServer/httpErrors | Select-Object *}"
        $HttpErrors = Invoke-Expression $PSCommand
    }

    If ($HttpErrors.errorMode -eq "DetailedLocalOnly") {
        $Status = "NotAFinding"
        $FindingDetails += "Error Responses is configured to 'Detailed errors for local requests and custom error pages for remote requests'" | Out-String
    }
    ElseIf ($HttpErrors.errorMode -eq "Custom") {
        $Status = "NotAFinding"
        $FindingDetails += "Error Responses is configured to 'Custom error pages'" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Error Responses is NOT configured to 'Detailed errors for local requests and custom error pages for remote requests' or 'Custom error pages'" | Out-String
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += "errorMode:`t$($HttpErrors.errorMode)" | Out-String
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

Function Get-V218812 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218812
        STIG ID    : IIST-SV-000142
        Rule ID    : SV-218812r879692_rule
        CCI ID     : CCI-002314
        Rule Name  : SRG-APP-000315-WSR-000004
        Rule Title : The IIS 10.0 web server must restrict inbound connections from non-secure zones.
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
    $managerService = Get-ItemProperty HKLM:\Software\Microsoft\WebManagement\Server -ErrorAction SilentlyContinue

    If ($managerService.EnableRemoteManagement -eq 1) {
        $FindingDetails += "The Web Management service is installed and active. This means that remote administration of IIS is possible." | Out-String
        $FindingDetails += "Verify only known, secure IP ranges are configured as 'Allow'." | Out-String
    }
    Else {
        $FindingDetails += "The remote management feature of IIS is not installed so this check is Not Applicable." | Out-String
        $Status = 'Not_Applicable'
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

Function Get-V218813 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218813
        STIG ID    : IIST-SV-000143
        Rule ID    : SV-218813r879693_rule
        CCI ID     : CCI-002322
        Rule Name  : SRG-APP-000316-WSR-000170
        Rule Title : The IIS 10.0 web server must provide the capability to immediately disconnect or disable remote access to the hosted applications.
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
    $FindingDetails += "There is nothing preventing an administrator from shutting down either the webservice or an individual IIS site in the event of an attack. Documentation exists describing how." | Out-String
    $Status = 'NotAFinding'
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

Function Get-V218814 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218814
        STIG ID    : IIST-SV-000144
        Rule ID    : SV-218814r879717_rule
        CCI ID     : CCI-002235
        Rule Name  : SRG-APP-000340-WSR-000029
        Rule Title : IIS 10.0 web server system files must conform to minimum file permission requirements.
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
    $Path = ((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp).PathWWWRoot -split "inetpub")[0] + "inetpub"

    $FindingDetails += "ACL for $($Path):" | Out-String
    $FindingDetails += (Get-Acl $Path).Access | Format-List | Out-String
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

Function Get-V218815 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218815
        STIG ID    : IIST-SV-000145
        Rule ID    : SV-218815r879730_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-WSR-000150
        Rule Title : The IIS 10.0 web server must use a logging mechanism configured to allocate log record storage capacity large enough to accommodate the logging requirements of the IIS 10.0 web server.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }

    $SchedulesToCheck = ("Hourly", "Daily", "Weekly", "Monthly")

    If ($Log.period -in $SchedulesToCheck) {
        $Status = "NotAFinding"
        $FindingDetails += "Logs are set to roll over $($Log.period)." | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Logs are NOT set to roll over on a schedule." | Out-String
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

Function Get-V218816 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218816
        STIG ID    : IIST-SV-000147
        Rule ID    : SV-218816r879753_rule
        CCI ID     : CCI-000213, CCI-001813, CCI-002385
        Rule Name  : SRG-APP-000380-WSR-000072
        Rule Title : Access to web administration tools must be restricted to the web manager and the web managers designees.
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
    If (Test-Path "$($env:WINDIR)\system32\inetsrv\Inetmgr.exe") {
        $FindingDetails += "ACL for $($env:WINDIR)\system32\inetsrv\Inetmgr.exe:" | Out-String
        $FindingDetails += (Get-Acl "$env:WINDIR\system32\inetsrv\Inetmgr.exe").Access | Format-List | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "InetMgr.exe does not exist on this system." | Out-String
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

Function Get-V218817 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218817
        STIG ID    : IIST-SV-000148
        Rule ID    : SV-218817r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-WSR-000175
        Rule Title : The IIS 10.0 web server must not be running on a system providing any other role.
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
    $SoftwareList = Get-InstalledSoftware
    $FindingDetails += "Software installed on this system:" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += $SoftwareList.DisplayName | Sort-Object | Out-String
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

Function Get-V218818 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218818
        STIG ID    : IIST-SV-000149
        Rule ID    : SV-218818r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-WSR-000175
        Rule Title : The Internet Printing Protocol (IPP) must be disabled on the IIS 10.0 web server.
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
    If (Test-Path "$env:windir\web\printers") {
        $Status = "Open"
        $FindingDetails += "'$env:windir\web\printers' exists. [Finding]" | Out-String
    }
    Else {
        $FindingDetails += "'$env:windir\web\printers' does not exist." | Out-String
        $FindingDetails += "" | Out-String
        Switch -Wildcard (((Get-CimInstance Win32_OperatingSystem).Caption)) {
            "*Windows*Server*" {
                If (((Get-WindowsFeature -Name Print-Services).Installed -eq $false) -and ((Get-WindowsFeature -Name Internet-Print-Client).Installed -eq $false)) {
                    $Status = "Not_Applicable"
                    $FindingDetails += "The Print Services role and the Internet Printing role are not installed so this check is Not Applicable." | Out-String
                }
                ElseIf ((Get-WindowsFeature -name "Internet-Print-Client").installed -eq $true) {
                    $Status = "Open"
                    $FindingDetails += "Internet-Print-Client is installed." | Out-String
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "Internet-Print-Client is not installed." | Out-String
                }
            }
            "*Windows*10*" {
                Try {
                    If ((Get-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-InternetPrinting-Client" -ErrorAction Stop).State -eq "Enabled") {
                        $Status = "Open"
                        $FindingDetails += "Printing-Foundation-InternetPrinting-Client is enabled." | Out-String
                    }
                    Else {
                        $Status = "NotAFinding"
                        $FindingDetails += "Printing-Foundation-InternetPrinting-Client is not enabled." | Out-String
                    }
                }
                Catch {
                    If ((Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object Name -EQ "Printing-Foundation-InternetPrinting-Client").InstallState -eq 1) {
                        $Status = "Open"
                        $FindingDetails += "Printing-Foundation-InternetPrinting-Client is enabled." | Out-String
                    }
                    Else {
                        $Status = "NotAFinding"
                        $FindingDetails += "Printing-Foundation-InternetPrinting-Client is not enabled." | Out-String
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

Function Get-V218819 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218819
        STIG ID    : IIST-SV-000151
        Rule ID    : SV-218819r879806_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435-WSR-000148
        Rule Title : The IIS 10.0 web server must be tuned to handle the operational requirements of the hosted application.
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
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"

    $uriEnableCache = Get-RegistryResult -Path $RegistryPath -ValueName URIEnableCache
    $uriMaxUriBytes = Get-RegistryResult -Path $RegistryPath -ValueName UriMaxUriBytes
    $uriScavengerPeriod = Get-RegistryResult -Path $RegistryPath -ValueName UriScavengerPeriod

    If ($uriEnableCache.Value -eq "(NotFound)" -or $uriMaxUriBytes.Value -eq "(NotFound)" -or $uriScavengerPeriod.Value -eq "(NotFound)") {
        $Compliant = $false
    }

    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
    $FindingDetails += "Value Name:`turiEnableCache" | Out-String
    $FindingDetails += "Value:`t`t$($uriEnableCache.Value)" | Out-String
    $FindingDetails += "Type:`t`t$($uriEnableCache.Type)" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
    $FindingDetails += "Value Name:`turiMaxUriBytes" | Out-String
    $FindingDetails += "Value:`t`t$($uriMaxUriBytes.Value)" | Out-String
    $FindingDetails += "Type:`t`t$($uriMaxUriBytes.Type)" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
    $FindingDetails += "Value Name:`turiScavengerPeriod" | Out-String
    $FindingDetails += "Value:`t`t$($uriScavengerPeriod.Value)" | Out-String
    $FindingDetails += "Type:`t`t$($uriScavengerPeriod.Type)" | Out-String
    $FindingDetails += "" | Out-String

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

Function Get-V218820 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218820
        STIG ID    : IIST-SV-000152
        Rule ID    : SV-218820r879810_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000152
        Rule Title : IIS 10.0 web server session IDs must be sent to the client using TLS.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Session = Get-WebConfigurationProperty '/system.webServer/asp' -Name session
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/asp' -Name session}"
        $Session = Invoke-Expression $PSCommand
    }

    If ($Session.keepSessionIdSecure -eq $true) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "keepSessionIdSecure is set to $($Session.keepSessionIdSecure)"
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

Function Get-V218821 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218821
        STIG ID    : IIST-SV-000153
        Rule ID    : SV-218821r903106_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000156
        Rule Title : An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved Transport Layer Security (TLS) version.
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

    # TLS 1.2 Check
    # -------------
    # Check DisabledByDefault - "0" REG_DWORD
    $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    $RegistryResult = Get-RegistryResult -Path $Path -ValueName "DisabledByDefault"
    $FindingDetails += $Path | Out-String
    If ($RegistryResult.Value -ne "(NotFound)") {
        $FindingDetails += "ValueName 'DisabledByDefault' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
    }
    Else {
        $FindingDetails += "ValueName 'DisabledByDefault' does NOT exist" | Out-String
    }
    If ($RegistryResult.Value -ne "0" -or $RegistryResult.Type -ne "REG_DWORD") {
        $Compliant = $false
    }

    # Check Enabled - "1" REG_DWORD
    $RegistryResult = Get-RegistryResult -Path $Path -ValueName "Enabled"
    If ($RegistryResult.Value -ne "(NotFound)") {
        $FindingDetails += "ValueName 'Enabled' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
    }
    Else {
        $FindingDetails += "ValueName 'Enabled' does NOT exist" | Out-String
    }
    If ($RegistryResult.Value -ne "1" -or $RegistryResult.Type -ne "REG_DWORD") {
        $Compliant = $false
    }
    $FindingDetails += "" | Out-String

    # TLS 1.0, TLS 1.1, SSL 2.0, and SSL 3.0 Checks
    # ---------------------------------------------
    $Paths = @("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server")
    ForEach ($Path in $Paths) {
        # Check DisabledByDefault - "1" REG_DWORD
        $RegistryResult = Get-RegistryResult -Path $Path -ValueName "DisabledByDefault"
        $FindingDetails += $Path | Out-String
        If ($RegistryResult.Value -ne "(NotFound)") {
            $FindingDetails += "ValueName 'DisabledByDefault' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
        }
        Else {
            $FindingDetails += "ValueName 'DisabledByDefault' does NOT exist" | Out-String
        }
        If ($RegistryResult.Value -ne "1" -or $RegistryResult.Type -ne "REG_DWORD") {
            $Compliant = $false
        }

        # Check Enabled - "0" REG_DWORD
        $RegistryResult = Get-RegistryResult -Path $Path -ValueName "Enabled"
        If ($RegistryResult.Value -ne "(NotFound)") {
            $FindingDetails += "ValueName 'Enabled' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
        }
        Else {
            $FindingDetails += "ValueName 'Enabled' does NOT exist" | Out-String
        }
        If ($RegistryResult.Value -ne "0" -or $RegistryResult.Type -ne "REG_DWORD") {
            $Compliant = $false
        }
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

Function Get-V218822 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218822
        STIG ID    : IIST-SV-000154
        Rule ID    : SV-218822r879810_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000156
        Rule Title : The IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved Transport Layer Security (TLS) version.
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

    # TLS 1.2 Check
    $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    $RegistryResult = Get-RegistryResult -Path $Path -ValueName "DisabledByDefault"
    $FindingDetails += $Path | Out-String
    If ($RegistryResult.Value -ne "(NotFound)") {
        $FindingDetails += "ValueName 'DisabledByDefault' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
    }
    Else {
        $FindingDetails += "ValueName 'DisabledByDefault' does NOT exist" | Out-String
    }
    $FindingDetails += "" | Out-String
    If ($RegistryResult.Value -ne "0" -or $RegistryResult.Type -ne "REG_DWORD") {
        $Compliant = $false
    }

    # TLS 1.0, TLS 1.1, SSL 2.0, and SSL 3.0 Checks
    $Paths = @("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server")
    ForEach ($Path in $Paths) {
        # Check DisabledByDefault - "1" REG_DWORD
        $RegistryResult = Get-RegistryResult -Path $Path -ValueName "DisabledByDefault"
        $FindingDetails += $Path | Out-String
        If ($RegistryResult.Value -ne "(NotFound)") {
            $FindingDetails += "ValueName 'DisabledByDefault' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
        }
        Else {
            $FindingDetails += "ValueName 'DisabledByDefault' does NOT exist" | Out-String
        }
        If ($RegistryResult.Value -ne "1" -or $RegistryResult.Type -ne "REG_DWORD") {
            $Compliant = $false
        }

        # Check Enabled - "0" REG_DWORD
        $RegistryResult = Get-RegistryResult -Path $Path -ValueName "Enabled"
        If ($RegistryResult.Value -ne "(NotFound)") {
            $FindingDetails += "ValueName 'Enabled' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
        }
        Else {
            $FindingDetails += "ValueName 'Enabled' does NOT exist" | Out-String
        }
        If ($RegistryResult.Value -ne "0" -or $RegistryResult.Type -ne "REG_DWORD") {
            $Compliant = $false
        }
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

Function Get-V218823 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218823
        STIG ID    : IIST-SV-000156
        Rule ID    : SV-218823r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000079
        Rule Title : All accounts installed with the IIS 10.0 web server software and tools must have passwords assigned and default passwords changed.
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
    $LocalUsers = Get-LocalUser | Where-Object SID -NotLike "*-503" # Exclude 'DefaultAccount'

    $FindingDetails += "Local user accounts on this system.  Confirm if any are used by IIS and if so, verify that default passwords have been changed:" | Out-String
    $FindingDetails += "" | Out-String
    ForEach ($User in $LocalUsers) {
        $FindingDetails += "Name:`t`t$($User.Name)" | Out-String
        $FindingDetails += "Enabled:`t`t$($User.Enabled)" | Out-String
        $FindingDetails += "SID:`t`t`t$($User.SID)" | Out-String
        If ($null -eq $User.PasswordLastSet) {
            $FindingDetails += "Password Age:`tNever Set" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $FindingDetails += "Password Age:`t$((New-TimeSpan -Start $($User.PasswordLastSet) -End (Get-Date)).Days) days" | Out-String
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

Function Get-V218824 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218824
        STIG ID    : IIST-SV-000158
        Rule ID    : SV-218824r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : Unspecified file extensions on a production IIS 10.0 web server must be removed.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $isapiRestriction = Get-WebConfigurationProperty '/system.webServer/security/isapiCgiRestriction' -Name notListedIsapisAllowed | Select-Object Value
        $cgiRestriction = Get-WebConfigurationProperty '/system.webServer/security/isapiCgiRestriction' -Name notListedCgisAllowed | Select-Object Value
    }
    Else {
        $PSCommand1 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/isapiCgiRestriction' -Name notListedIsapisAllowed | Select-Object Value}"
        $PSCommand2 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/isapiCgiRestriction' -Name notListedCgisAllowed | Select-Object Value}"
        $isapiRestriction = Invoke-Expression $PSCommand1
        $cgiRestriction = Invoke-Expression $PSCommand2
    }

    If ($isapiRestriction.value -eq $false) {
        $FindingDetails += "Unspecified ISAPI is not enabled. NOT A FINDING." | Out-String
    }
    Else {
        $FindingDetails += "Unspecified ISAPI is enabled. FINDING." | Out-String
        $Status = 'Open'
    }
    If ($cgiRestriction.value -eq $false) {
        $FindingDetails += "Unspecified CGI is not enabled. NOT A FINDING." | Out-String
    }
    Else {
        $FindingDetails += "Unspecified CGI is enabled. FINDING." | Out-String
        $Status = 'Open'
    }

    If ($Status -ne 'Open') {
        $Status = 'NotAFinding'
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

Function Get-V218825 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218825
        STIG ID    : IIST-SV-000159
        Rule ID    : SV-218825r881082_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The IIS 10.0 web server must have a global authorization rule configured to restrict access.
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
    Try {
        $IIS_NetFxFeatures = Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object {($_.FeatureName -like "IIS-NetFxExtensibility*") -and ($_.State -eq "Enabled")}
    }
    Catch {
        $IIS_NetFxFeatures = Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object {($_.Name -like "IIS-NetFxExtensibility*") -and ($_.InstallState -eq 1)}
    }

    If (-Not($IIS_NetFxFeatures)) {
        $Status = "Not_Applicable"
        $FindingDetails += "IIS .NET Extensibility features are not installed so this requirement is NA."
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "MSExchangeServiceHost") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting Exchange so this requirement is NA."
    }
    Else {
        $Compliant = $true
        $RuleList = New-Object System.Collections.Generic.List[System.Object]

        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $AuthCollection = Get-WebConfigurationProperty -Filter '/system.web/authorization' -Name *
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty -Filter '/system.web/authorization' -Name *}"
            $AuthCollection = Invoke-Expression $PSCommand
        }

        # If All Users rule does not exist, mark as non-compliant
        If (-Not($AuthCollection.Collection | Where-Object {($_.users -eq "*" -and $_.ElementTagName -eq "allow")})) {
            $Compliant = $false
            $NewObj = [PSCustomObject]@{
                Mode      = "allow"
                Users     = "All Users"
                Roles     = ""
                Verbs     = ""
                Compliant = $false
                Reason    = "Expected rule missing"
            }
            $RuleList.Add($NewObj)
        }

        # If Anonymous Users rule does not exist, mark as non-compliant
        If (-Not($AuthCollection.Collection | Where-Object {($_.users -eq "?" -and $_.ElementTagName -eq "deny")})) {
            $Compliant = $false
            $NewObj = [PSCustomObject]@{
                Mode      = "deny"
                Users     = "Anonymous Users"
                Roles     = ""
                Verbs     = ""
                Compliant = $false
                Reason    = "Expected rule missing"
            }
            $RuleList.Add($NewObj)
        }

        # If any unexpected rules exist, mark as non-compliant
        ForEach ($Item in $AuthCollection.Collection) {
            If (($Item.users -eq "*" -and $Item.ElementTagName -eq "allow") -or ($Item.users -eq "?" -and $Item.ElementTagName -eq "deny")) {
                $RuleCompliant = $true
                $Reason = ""
            }
            Else {
                $Compliant = $false
                $RuleCompliant = $false
                $Reason = "Unexpected rule"
            }

            $NewObj = [PSCustomObject]@{
                Mode      = $Item.ElementTagName
                Users     = $(Switch ($Item.users) {
                        "*" {
                            "All Users"
                        } "?" {
                            "Anonymous Users"
                        } Default {
                            $Item.users
                        }
                    })
                Roles     = $Item.roles
                Verbs     = $Item.verbs
                Compliant = $RuleCompliant
                Reason    = $Reason
            }
            $RuleList.Add($NewObj)
        }

        If ($RuleList | Where-Object Compliant -EQ $false) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Non-Compliant Rules:" | Out-String
            $FindingDetails += "--------------------" | Out-String
            ForEach ($Rule in ($RuleList | Where-Object Compliant -EQ $false)) {
                $FindingDetails += "Mode:`t$($Rule.mode)" | Out-String
                $FindingDetails += "Users:`t$($Rule.users)" | Out-String
                $FindingDetails += "Roles:`t$($Rule.roles)" | Out-String
                $FindingDetails += "Verbs:`t$($Rule.verbs)" | Out-String
                $FindingDetails += "Reason:`t$($Rule.Reason)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }

        $FindingDetails += "Compliant Rules:" | Out-String
        $FindingDetails += "----------------" | Out-String
        ForEach ($Rule in ($RuleList | Where-Object Compliant -EQ $true)) {
            $FindingDetails += "Mode:`t$($Rule.mode)" | Out-String
            $FindingDetails += "Users:`t$($Rule.users)" | Out-String
            $FindingDetails += "Roles:`t$($Rule.roles)" | Out-String
            $FindingDetails += "Verbs:`t$($Rule.verbs)" | Out-String
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

Function Get-V218826 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218826
        STIG ID    : IIST-SV-000200
        Rule ID    : SV-218826r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000001
        Rule Title : The IIS 10.0 websites MaxConnections setting must be configured to limit the number of allowed simultaneous session requests.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $MaxConnections = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/limits' -Name maxConnections
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/limits' -Name maxConnections}"
        $MaxConnections = Invoke-Expression $PSCommand
    }

    If ($MaxConnections.Value -gt 0) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "MaxConnections is set to $($MaxConnections.Value)" | Out-String
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

Function Get-V218827 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218827
        STIG ID    : IIST-SV-000205
        Rule ID    : SV-218827r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The IIS 10.0 web server must enable HTTP Strict Transport Security (HSTS).
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
    $ReleaseId = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId
    If ($ReleaseId -lt "1709") {
        $Status = "NotAFinding"
        $FindingDetails += "Windows Server 2016 version is $ReleaseId which does not natively support HTST so this requirement is Not A Finding."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $HSTSenabled = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name enabled
            $HSTSmaxage = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name max-age
            $HSTSincludeSubDomains = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name includeSubDomains
            $HSTSredirectHttpToHttps = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name redirectHttpToHttps
        }
        Else {
            $PSCommand1 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name enabled}"
            $PSCommand2 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name max-age}"
            $PSCommand3 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name includeSubDomains}"
            $PSCommand4 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name redirectHttpToHttps}"
            $HSTSenabled = Invoke-Expression $PSCommand1
            $HSTSmaxage = Invoke-Expression $PSCommand2
            $HSTSincludeSubDomains = Invoke-Expression $PSCommand3
            $HSTSredirectHttpToHttps = Invoke-Expression $PSCommand4
        }

        If ($HSTSenabled.Value -eq $true) {
            $FindingDetails += "HSTS is enabled. NOT A FINDING." | Out-String
        }
        Else {
            $FindingDetails += "HSTS is not enabled. FINDING." | Out-String
            $Status = "Open"
        }

        If ($HSTSmaxage.Value -gt 0) {
            $FindingDetails += "HSTS max-age is $($HSTSmaxage.Value). NOT A FINDING." | Out-String
        }
        ElseIf (-Not($HSTSmaxage.Value)) {
            $FindingDetails += "HSTS max-age is not configured. FINDING." | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "HSTS max-age is $($HSTSmaxage.Value). FINDING." | Out-String
            $Status = "Open"
        }

        If ($HSTSincludeSubDomains.Value -eq $true) {
            $FindingDetails += "HSTS includeSubDomains is enabled. NOT A FINDING." | Out-String
        }
        Else {
            $FindingDetails += "HSTS includeSubDomains is not enabled. FINDING." | Out-String
            $Status = "Open"
        }

        If ($HSTSredirectHttpToHttps.Value -eq $true) {
            $FindingDetails += "HSTS redirectHttpToHttps is enabled. NOT A FINDING." | Out-String
        }
        Else {
            $FindingDetails += "HSTS redirectHttpToHttps is not enabled. FINDING." | Out-String
            $Status = 'Open'
        }

        If ($Status -ne 'Open') {
            $Status = 'NotAFinding'
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

Function Get-V228572 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228572
        STIG ID    : IIST-SV-000160
        Rule ID    : SV-228572r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000075
        Rule Title : An IIS Server configured to be a SMTP relay must require authentication.
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
    If ((Get-CimInstance Win32_OperatingSystem).Caption -like "*Windows*Server*") {
        $SMTP_Feature = Get-WindowsFeature | Where-Object Name -EQ "SMTP-Server"
        $FindingDetails += "SMTP-Server Feature:`t$($SMTP_Feature.InstallState)" | Out-String
        $FindingDetails += "" | Out-String
    }

    $Port25 = Get-NetTCPConnection | Where-Object LocalPort -EQ 25 | Select-Object -Property LocalPort, State, @{'Name' = 'ProcessName'; 'Expression' = {(Get-Process -Id $_.OwningProcess).Name}}
    If (-Not($Port25)) {
        $FindingDetails += "System is not listening on port 25.  Confirm there are no SMTP relays using a custom port.  If no SMTP relays exist, this may be marked as 'Not Applicable'." | Out-String
    }
    Else {
        $FindingDetails += "Process found on port 25.  Confirm if it is SMTP and if so, that it's configured per STIG." | Out-String
        $FindingDetails += "" | Out-String
        ForEach ($Item in $Port25) {
            $FindingDetails += "LocalPort:`t$($Item.LocalPort)" | Out-String
            $FindingDetails += "State`t`t:$($Item.State)" | Out-String
            $FindingDetails += "ProcessName:`t$($Item.ProcessName)" | Out-String
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

Function Get-V241788 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241788
        STIG ID    : IIST-SV-000210
        Rule ID    : SV-241788r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : HTTPAPI Server version must be removed from the HTTP Response Header information.
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
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"  # Registry path identified in STIG
    $RegistryValueName = "DisableServerHeader"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "HTTPAPI Server version"  # GPO setting name identified in STIG
    $SettingState = "removed from the HTTP Response Header information"  # GPO configured state identified in STIG.

    $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        $Status = "Open"
        $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
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

Function Get-V241789 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241789
        STIG ID    : IIST-SV-000215
        Rule ID    : SV-241789r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : ASP.NET version must be removed from the HTTP Response Header information.
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $CustomHeaders = Get-WebConfiguration -Filter 'system.webServer/httpProtocol/customHeaders' | Select-Object -ExpandProperty Collection
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration -Filter 'system.webServer/httpProtocol/customHeaders' | Select-Object -ExpandProperty Collection}"
        $CustomHeaders = Invoke-Expression $PSCommand
    }

    If ("X-Powered-By" -in $CustomHeaders.Name) {
        $Status = "Open"
        $FindingDetails += "'X-Powered-By' HTTP header has NOT been removed:" | Out-String
        ForEach ($Item in ($CustomHeaders | Where-Object Name -EQ "X-Powered-By")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Name:`t$($Item.name)" | Out-String
            $FindingDetails += "Value:`t$($Item.value)" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "'X-Powered-By' HTTP header has been removed." | Out-String
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDlf5+L3wUhC1YT
# LKWG7zS3rpPF+ZAnMqCigbRYBl3QyKCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBjLt9VvlYnCsBRgog2xZfDZGxFsEQf
# xNlWVA2C6nj1GDANBgkqhkiG9w0BAQEFAASCAQC36R8RorbLo1R/+GDUiEyDZm1C
# AgT6scDgysRCa+wME5qW0O2D7PEe1rrqbbhNNxTDAQLYRfLDydewyxwYQabxtA2f
# ufRSsKWbHiC5QnFHeB7KVrWF9LetckRgoTejzFQseiGAnz4Qii6UsHWXGh9EEqZV
# /62CcFcnRIHMVDi8sYnSa9JaVd0d/aCmsYjfb08qfVN840baUbP+5LLA797sq0kH
# Y5Le3kcCrySJTzuKEVj22wAUowsOZvvyc4RPsaoo8pquJJaRC9YqrMZl6VM4ZL1E
# K3A+XGr8pyGEdGbH+Zl7TSq8qZUwngjrN2BDGcAKyGhGz1ttq87Xv5qg4/P1
# SIG # End signature block
