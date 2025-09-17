##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft Exchange 2016 Mailbox Server
# Version:  V2R4
# Class:    UNCLASSIFIED
# Updated:  4/25/2023
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V228354 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228354
        STIG ID    : EX16-MB-000010
        Rule ID    : SV-228354r612748_rule
        CCI ID     : CCI-001403
        Rule Name  : SRG-APP-000027
        Rule Title : Exchange must have Administrator audit logging enabled.
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
    $Setting = "AdminAuditLogEnabled"
    $ExpectedValue = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-AdminAuditLogConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-AdminAuditLogConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228355 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228355
        STIG ID    : EX16-MB-000020
        Rule ID    : SV-228355r612748_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033
        Rule Title : Exchange servers must use approved DoD certificates.
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
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ExchangeCertificate -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ExchangeCertificate -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        $FindingDetails += "CertificateDomains:`t$($Item.CertificateDomains -join ', ')" | Out-String
        If ($Item.Issuer -like "CN=DoD*") {
            $FindingDetails += "Issuer:`t`t`t$($Item.Issuer)" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "Issuer:`t`t`t$($Item.Issuer) [Not DoD issued]" | Out-String
        }
        $FindingDetails += "Services:`t`t`t$($Item.Services)" | Out-String
        $FindingDetails += "NotAfter:`t`t`t$($Item.NotAfter)" | Out-String
        $FindingDetails += "Thumbprint:`t`t$($Item.Thumbprint)" | Out-String
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

Function Get-V228356 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228356
        STIG ID    : EX16-MB-000030
        Rule ID    : SV-228356r612748_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-APP-000038
        Rule Title : Exchange auto-forwarding email to remote domains must be disabled or restricted.
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
    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $Setting = "AutoForwardEnabled"
        $ExpectedValue = $false
        $Compliant = $true

        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
            $Result = Get-RemoteDomain
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RemoteDomain}"
            $Result = Invoke-Expression $PSCommand
        }

        ForEach ($Item in $Result) {
            If ($Item.$($Setting) -eq $ExpectedValue -or $Item.DomainName -like "*.mil" -or $Item.DomainName -like "*.gov") {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "DomainName:`t`t`t$($Item.DomainName)" | Out-String
                $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "DomainName:`t`t`t$($Item.DomainName)" | Out-String
                $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228357 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228357
        STIG ID    : EX16-MB-000040
        Rule ID    : SV-228357r612748_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : Exchange Connectivity logging must be enabled.
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
    $Setting = "ConnectivityLogEnabled"
    $ExpectedValue = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportService -Identity $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportService -Identity $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228358 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228358
        STIG ID    : EX16-MB-000050
        Rule ID    : SV-228358r612748_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : The Exchange Email Diagnostic log level must be set to the lowest level.
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
    $Setting = "EventLevel"
    $ExpectedValue = "Lowest"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-EventLogLevel | Where-Object $Setting -NE $ExpectedValue
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-EventLogLevel | Where-Object $Setting -ne $ExpectedValue}"
        $Result = Invoke-Expression $PSCommand
    }

    If (-Not($Result)) {
        $Status = "NotAFinding"
        $FindingDetails += "All Event Log Levels configured to 'Lowest'." | Out-String
    }
    Else {
        $Status = "Open"
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Identity)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228359 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228359
        STIG ID    : EX16-MB-000060
        Rule ID    : SV-228359r612748_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : Exchange Audit record parameters must be set.
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
    $Setting = "AdminAuditLogParameters"
    $ExpectedValue = '*'

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-AdminAuditLogConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-AdminAuditLogConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ([String]$Result.$($Setting) -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228360 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228360
        STIG ID    : EX16-MB-000070
        Rule ID    : SV-228360r612748_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-APP-000098
        Rule Title : Exchange Circular Logging must be disabled.
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
    $Setting = "CircularLoggingEnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-MailboxDatabase -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-MailboxDatabase -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228361 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228361
        STIG ID    : EX16-MB-000080
        Rule ID    : SV-228361r612748_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-APP-000098
        Rule Title : Exchange Email Subject Line logging must be disabled.
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
    $Setting = "MessageTrackingLogSubjectLoggingEnabled"
    $ExpectedValue = $false

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportService -Identity $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportService -Identity $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228362 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228362
        STIG ID    : EX16-MB-000090
        Rule ID    : SV-228362r612748_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-APP-000098
        Rule Title : Exchange Message Tracking Logging must be enabled.
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
    $Setting = "MessageTrackingLogEnabled"
    $ExpectedValue = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportService -Identity $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportService -Identity $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228364 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228364
        STIG ID    : EX16-MB-000110
        Rule ID    : SV-228364r612748_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Exchange Send Fatal Errors to Microsoft must be disabled.
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
    $Setting = "ErrorReportingEnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ExchangeServer -Status
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ExchangeServer -Status}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228366 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228366
        STIG ID    : EX16-MB-000130
        Rule ID    : SV-228366r612748_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Exchange must not send Customer Experience reports to Microsoft.
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
    $Setting = "CustomerFeedbackEnabled"
    $ExpectedValue = $false

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-OrganizationConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-OrganizationConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228370 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228370
        STIG ID    : EX16-MB-000170
        Rule ID    : SV-228370r612748_rule
        CCI ID     : CCI-001749
        Rule Name  : SRG-APP-000131
        Rule Title : Exchange Local machine policy must require signed scripts.
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
    $Setting = "ExecutionPolicy"
    $ExpectedValue = "RemoteSigned"

    $Result = Get-ExecutionPolicy

    If ($Result -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result)" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "$($Setting):`t$($Result) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228371 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228371
        STIG ID    : EX16-MB-000180
        Rule ID    : SV-228371r612748_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : The Exchange Internet Message Access Protocol 4 (IMAP4) service must be disabled.
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
    $Service = "MSExchangeIMAP4"
    $ExpectedValue = "Disabled"

    $Result = Get-Service $Service
    If ($Result.StartType -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "Service:`t`t$($Service)" | Out-String
        $FindingDetails += "StartType:`t$($Result.StartType)" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Service:`t`t$($Service)" | Out-String
        $FindingDetails += "StartType:`t$($Result.StartType) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228372 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228372
        STIG ID    : EX16-MB-000190
        Rule ID    : SV-228372r612748_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : The Exchange Post Office Protocol 3 (POP3) service must be disabled.
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
    $Service = "MSExchangePOP3"
    $ExpectedValue = "Disabled"

    $Result = Get-Service $Service
    If ($Result.StartType -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "Service:`t`t$($Service)" | Out-String
        $FindingDetails += "StartType:`t$($Result.StartType)" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Service:`t`t$($Service)" | Out-String
        $FindingDetails += "StartType:`t$($Result.StartType) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228374 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228374
        STIG ID    : EX16-MB-000210
        Rule ID    : SV-228374r612748_rule
        CCI ID     : CCI-001178
        Rule Name  : SRG-APP-000213
        Rule Title : Exchange Internet-facing Send connectors must specify a Smart Host.
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
    $Prop1 = "SmartHosts"
    $ExpectedValue1 = 1
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SendConnector
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SendConnector}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            If (($Item.$($Prop1) | Measure-Object).Count -ge $ExpectedValue1) {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Prop1):`t$($Item.$($Prop1) -join ', ')" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Prop1):`tNULL [Expected IP address(s)]" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $FindingDetails += "No Send Connectors are configured." | Out-String
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

Function Get-V228375 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228375
        STIG ID    : EX16-MB-000220
        Rule ID    : SV-228375r612748_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219
        Rule Title : Exchange internal Receive connectors must require encryption.
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
    $Setting = "AuthMechanism"
    $ExpectedValue = "Tls"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($ExpectedValue -in ($Item.$($Setting) -split (",\s*"))) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Missing $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228376 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228376
        STIG ID    : EX16-MB-000270
        Rule ID    : SV-228376r612748_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231
        Rule Title : Exchange Mailboxes must be retained until backups are complete.
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
    $Setting = "RetainDeletedItemsUntilBackup"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-MailboxDatabase -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-MailboxDatabase -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228377 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228377
        STIG ID    : EX16-MB-000290
        Rule ID    : SV-228377r612748_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231
        Rule Title : Exchange email forwarding must be restricted.
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
    $Setting = "ForwardingSmtpAddress"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-Mailbox -Server $env:COMPUTERNAME | Where-Object $Setting -NE $null
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-Mailbox -Server $env:COMPUTERNAME | Where-Object $Setting -ne " + '$null}'
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "No mailboxes have '$($Setting)' configured." | Out-String
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

Function Get-V228378 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228378
        STIG ID    : EX16-MB-000300
        Rule ID    : SV-228378r612748_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231
        Rule Title : Exchange email-forwarding SMTP domains must be restricted.
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
    $Setting = "AutoForwardEnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RemoteDomain
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RemoteDomain}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228379 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228379
        STIG ID    : EX16-MB-000310
        Rule ID    : SV-228379r612748_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246
        Rule Title : Exchange Mail quota settings must not restrict receiving mail.
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
    $Setting = "ProhibitSendReceiveQuota"
    $Prop1 = "IsUnlimited"
    $ExpectedValue = $true
    $Prop2 = "Value"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-MailboxDatabase -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-MailboxDatabase -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting).$($Prop1) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop1):`t$($Item.$($Setting).$($Prop1))" | Out-String
            $FindingDetails += "$($Prop2):`t`t$($Item.$($Setting).$($Prop2))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop1):`t$($Item.$($Setting).$($Prop1)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "$($Prop2):`t`t$($Item.$($Setting).$($Prop2))" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228380 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228380
        STIG ID    : EX16-MB-000320
        Rule ID    : SV-228380r612748_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246
        Rule Title : Exchange Mail Quota settings must not restrict receiving mail.
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
    $Setting = "ProhibitSendQuota"
    $Prop1 = "IsUnlimited"
    $Prop2 = "Value"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-MailboxDatabase -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-MailboxDatabase -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        $FindingDetails += "$($Item.Name)" | Out-String
        $FindingDetails += "$($Setting)" | Out-String
        $FindingDetails += "$($Prop1):`t$($Item.$($Setting).$($Prop1))" | Out-String
        $FindingDetails += "$($Prop2):`t`t$($Item.$($Setting).$($Prop2))" | Out-String
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

Function Get-V228381 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228381
        STIG ID    : EX16-MB-000340
        Rule ID    : SV-228381r612748_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246
        Rule Title : Exchange Mailbox Stores must mount at startup.
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
    $Setting = "MountAtStartup"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-MailboxDatabase -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-MailboxDatabase -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228382 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228382
        STIG ID    : EX16-MB-000350
        Rule ID    : SV-228382r612748_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Message size restrictions must be controlled on Receive connectors.
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
    $Setting = "MaxMessageSize"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        $FindingDetails += "$($Item.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
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

Function Get-V228383 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228383
        STIG ID    : EX16-MB-000360
        Rule ID    : SV-228383r612748_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Receive connectors must control the number of recipients per message.
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
    $Setting = "MaxRecipientsPerMessage"
    $ExpectedValue = "5000"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228384 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228384
        STIG ID    : EX16-MB-000380
        Rule ID    : SV-228384r612748_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Receive Connector Maximum Hop Count must be 60.
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
    $Setting = "MaxHopCount"
    $ExpectedValue = "60"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228385 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228385
        STIG ID    : EX16-MB-000410
        Rule ID    : SV-228385r612748_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Message size restrictions must be controlled on Send connectors.
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
    $Setting = "MaxMessageSize"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SendConnector
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SendConnector}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "No Send Connectors are configured." | Out-String
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

Function Get-V228386 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228386
        STIG ID    : EX16-MB-000420
        Rule ID    : SV-228386r612748_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Send connector connections count must be limited.
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
    $Setting = "MaxOutboundConnections"
    $ExpectedValue = "1000"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportService -Identity $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportService -Identity $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228387 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228387
        STIG ID    : EX16-MB-000430
        Rule ID    : SV-228387r612748_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange global inbound message size must be controlled.
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
    $Setting = "MaxReceiveSize"
    $Prop1 = "IsUnlimited"
    $ExpectedValue1 = $false
    $Prop2 = "Value"
    $ExpectedValue2 = "10 MB (10,485,760 bytes)"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting).$($Prop1) -eq $ExpectedValue1 -and $Result.$($Setting).$($Prop2) -eq $ExpectedValue2) {
        $FindingDetails += "$($Setting)" | Out-String
        $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1))" | Out-String
        $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2))" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Setting)" | Out-String
        If ($Result.$($Setting).$($Prop1) -eq $ExpectedValue1) {
            $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1))" | Out-String
        }
        Else {
            $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1)) [Expected $($ExpectedValue1)]" | Out-String
        }
        If ($Result.$($Setting).$($Prop2) -eq $ExpectedValue2) {
            $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2))" | Out-String
        }
        Else {
            $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2)) [Expected $($ExpectedValue2)]" | Out-String
        }
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

Function Get-V228388 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228388
        STIG ID    : EX16-MB-000440
        Rule ID    : SV-228388r612748_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange global outbound message size must be controlled.
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
    $Setting = "MaxSendSize"
    $Prop1 = "IsUnlimited"
    $ExpectedValue1 = $false
    $Prop2 = "Value"
    $ExpectedValue2 = "10 MB (10,485,760 bytes)"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting).$($Prop1) -eq $ExpectedValue1 -and $Result.$($Setting).$($Prop2) -eq $ExpectedValue2) {
        $FindingDetails += "$($Setting)" | Out-String
        $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1))" | Out-String
        $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2))" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Setting)" | Out-String
        If ($Result.$($Setting).$($Prop1) -eq $ExpectedValue1) {
            $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1))" | Out-String
        }
        Else {
            $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1)) [Expected $($ExpectedValue1)]" | Out-String
        }
        If ($Result.$($Setting).$($Prop2) -eq $ExpectedValue2) {
            $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2))" | Out-String
        }
        Else {
            $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2)) [Expected $($ExpectedValue2)]" | Out-String
        }
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

Function Get-V228389 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228389
        STIG ID    : EX16-MB-000450
        Rule ID    : SV-228389r612748_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Outbound Connection Limit per Domain Count must be controlled.
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
    $Setting = "MaxPerDomainOutboundConnections"
    $ExpectedValue = "20"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportService -Identity $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportService -Identity $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V228390 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228390
        STIG ID    : EX16-MB-000460
        Rule ID    : SV-228390r612748_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Outbound Connection Timeout must be 10 minutes or less.
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
    $Setting = "ConnectionInactivityTimeOut"
    $ExpectedValue = (New-TimeSpan -Minutes 10)
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SendConnector
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SendConnector}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            If ($Result.$($Setting) -eq $ExpectedValue) {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Setting):`t$($Item.$($Setting).ToString())" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Setting):`t$($Item.$($Setting).ToString()) [Expected $($ExpectedValue.ToString())]" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $FindingDetails += "No Send Connectors are configured." | Out-String
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

Function Get-V228391 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228391
        STIG ID    : EX16-MB-000470
        Rule ID    : SV-228391r766722_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange Internal Receive connectors must not allow anonymous connections.
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
    $Setting = "PermissionGroups"
    $ExpectedValue = "AnonymousUsers"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($ExpectedValue -notin ($Item.$($Setting) -split (",\s*"))) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Found $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228392 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228392
        STIG ID    : EX16-MB-000480
        Rule ID    : SV-228392r612748_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange external/Internet-bound automated response messages must be disabled.
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
    $Setting = "AllowedOOFType"
    $ExpectedValue = "InternalLegacy"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RemoteDomain
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RemoteDomain}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228393 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228393
        STIG ID    : EX16-MB-000490
        Rule ID    : SV-228393r612748_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have anti-spam filtering installed.
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
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ContentFilterConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ContentFilterConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "Enabled:`t$($Result.Enabled)" | Out-String
    }
    Else {
        $FindingDetails += "No Content Filter is configured." | Out-String
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

Function Get-V228394 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228394
        STIG ID    : EX16-MB-000500
        Rule ID    : SV-228394r612748_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have anti-spam filtering enabled.
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
    $Setting = "Enabled"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = New-Object System.Collections.Generic.List[System.Object]
        $Commands = @("Get-ContentFilterConfig | Select-Object Name,Enabled", "Get-SenderFilterConfig | Select-Object Name,Enabled", "Get-SenderIDConfig | Select-Object Name,Enabled", "Get-SenderReputationConfig | Select-Object Name,Enabled")
        ForEach ($Command in $Commands) {
            $Ouput = Invoke-Expression $Command
            $NewObj = [PSCustomObject]@{
                Name    = $($Ouput.Name)
                Enabled = $($Ouput.Enabled)
            }
            $Result.Add($NewObj)
        }
    }
    Else {
        $PSCommand = 'PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; $Result = New-Object System.Collections.Generic.List[System.Object]; $Commands = @("Get-ContentFilterConfig | Select-Object Name,Enabled", "Get-SenderFilterConfig | Select-Object Name,Enabled", "Get-SenderIDConfig | Select-Object Name,Enabled", "Get-SenderReputationConfig | Select-Object Name,Enabled"); ForEach ($Command in $Commands) {$Ouput = Invoke-Expression $Command; $NewObj = [PSCustomObject]@{Name = $($Ouput.Name); Enabled = $($Ouput.Enabled)}; $Result.Add($NewObj)}; Return $Result}'
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228395 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228395
        STIG ID    : EX16-MB-000510
        Rule ID    : SV-228395r612748_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have anti-spam filtering configured.
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
    $Setting = "InternalSmtpServers"
    $Prop = "Expression"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting)) {
        $FindingDetails += "$($Setting):" | Out-String
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Prop):`t$($Item.$($Setting).$($Prop))" | Out-String
        }
    }
    Else {
        $FindingDetails += "No internal SMTP servers are configured." | Out-String
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

Function Get-V228396 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228396
        STIG ID    : EX16-MB-000520
        Rule ID    : SV-228396r612748_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must not send automated replies to remote domains.
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
    $Setting = "AutoReplyEnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RemoteDomain
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RemoteDomain}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue -or $Item.DomainName -like "*.mil" -or $Item.DomainName -like "*.gov") {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228398 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228398
        STIG ID    : EX16-MB-000540
        Rule ID    : SV-228398r612748_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Global Recipient Count Limit must be set.
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
    $Setting = "MaxRecipientEnvelopeLimit"
    $Prop1 = "IsUnlimited"
    $ExpectedValue1 = $false
    $Prop2 = "Value"
    $ExpectedValue2 = "5000"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting).$($Prop1) -eq $ExpectedValue1 -and $Result.$($Setting).$($Prop2) -eq $ExpectedValue2) {
        $FindingDetails += "$($Setting)" | Out-String
        $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1))" | Out-String
        $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2))" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Setting)" | Out-String
        If ($Result.$($Setting).$($Prop1) -eq $ExpectedValue1) {
            $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1))" | Out-String
        }
        Else {
            $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1)) [Expected $($ExpectedValue1)]" | Out-String
        }
        If ($Result.$($Setting).$($Prop2) -eq $ExpectedValue2) {
            $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2))" | Out-String
        }
        Else {
            $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2)) [Expected $($ExpectedValue2)]" | Out-String
        }
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

Function Get-V228399 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228399
        STIG ID    : EX16-MB-000550
        Rule ID    : SV-228399r612748_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295
        Rule Title : The Exchange Receive connector timeout must be limited.
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
    $Setting = "ConnectionTimeout"
    $ExpectedValue = (New-TimeSpan -Minutes 10)
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting).ToString())" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting).ToString()) [Expected $($ExpectedValue.ToString())]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228403 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228403
        STIG ID    : EX16-MB-000600
        Rule ID    : SV-228403r612748_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383
        Rule Title : Exchange services must be documented and unnecessary services must be removed or disabled.
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
    ForEach ($Item in Get-Service) {
        $FindingDetails += "ServiceName:`t$($Item.Name)" | Out-String
        $FindingDetails += "Displayname:`t$($Item.DisplayName)" | Out-String
        $FindingDetails += "Status:`t`t$($Item.Status)" | Out-String
        $FindingDetails += "StartType:`t$($Item.StartType)" | Out-String
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

Function Get-V228404 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228404
        STIG ID    : EX16-MB-000610
        Rule ID    : SV-228404r612748_rule
        CCI ID     : CCI-001953
        Rule Name  : SRG-APP-000391
        Rule Title : Exchange Outlook Anywhere clients must use NTLM authentication to access email.
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
    $Settings = @("InternalClientAuthenticationMethod", "ExternalClientAuthenticationMethod")
    $ExpectedValue = "Ntlm"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-OutlookAnywhere -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-OutlookAnywhere -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Identity)" | Out-String
            ForEach ($Setting in $Settings) {
                If ($Item.$($Setting) -eq $ExpectedValue) {
                    $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
                }
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

Function Get-V228406 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228406
        STIG ID    : EX16-MB-000630
        Rule ID    : SV-228406r612748_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange must not send delivery reports to remote domains.
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
    $Setting = "DeliveryReportEnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RemoteDomain
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RemoteDomain}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228407 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228407
        STIG ID    : EX16-MB-000640
        Rule ID    : SV-228407r684255_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange must not send nondelivery reports to remote domains.
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
    $Setting = "NDREnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RemoteDomain
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RemoteDomain}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228408 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228408
        STIG ID    : EX16-MB-000650
        Rule ID    : SV-228408r612748_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : The Exchange SMTP automated banner response must not reveal server details.
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
    $Setting = "Banner"
    $ExpectedValue = "220 SMTP Server Ready"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228409 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228409
        STIG ID    : EX16-MB-000660
        Rule ID    : SV-228409r612748_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange Internal Send connectors must use an authentication level.
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
    $Setting = "TlsAuthLevel"
    $ExpectedValue = "DomainValidation"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SendConnector
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SendConnector}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            If ($Item.$($Setting) -eq $ExpectedValue) {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $FindingDetails += "No Send Connectors are configured." | Out-String
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

Function Get-V228410 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228410
        STIG ID    : EX16-MB-000670
        Rule ID    : SV-228410r766720_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange must provide Mailbox databases in a highly available and redundant configuration.
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
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-DatabaseAvailabilityGroup
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-DatabaseAvailabilityGroup}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "Servers:`t`t$($Item.Servers -join ', ')" | Out-String
            $FindingDetails += "WitnessServer:`t$($Item.WitnessServer)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "No Database Availability Groups are configured." | Out-String
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

Function Get-V228411 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228411
        STIG ID    : EX16-MB-000680
        Rule ID    : SV-228411r612748_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : Exchange must have the most current, approved service pack installed.
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
    $Setting = "AdminDisplayVersion"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ExchangeServer -Identity $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ExchangeServer -Identity $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        $FindingDetails += "$($Item.Name)" | Out-String
        $FindingDetails += "AdminDisplayVersion:`t$($Item.$($Setting))" | Out-String
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

Function Get-V228412 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228412
        STIG ID    : EX16-MB-002870
        Rule ID    : SV-228412r612748_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : The application must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.
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
        $Result = Get-WebSite | Where-Object Name -NE "Exchange Back End"
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite | Where-Object Name -ne 'Exchange Back End'}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Name)" | Out-String
            ForEach ($Binding in $Item.bindings.Collection) {
                If ($Binding.protocol -in @("http", "https")) {
                    $Port = $Binding.bindingInformation -split ":"
                    If ($Port -contains "80" -or $Port -contains "443") {
                        $FindingDetails += "Binding:`t$($Binding.protocol) ($($Binding.bindingInformation))" | Out-String
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Binding:`t$($Binding.protocol) ($($Binding.bindingInformation)) [Expected port 80 or 443]" | Out-String
                    }
                }
                Else {
                    $FindingDetails += "Binding:`t$($Binding.protocol) ($($Binding.bindingInformation))" | Out-String
                }
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

Function Get-V228413 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228413
        STIG ID    : EX16-MB-002880
        Rule ID    : SV-228413r612748_rule
        CCI ID     : CCI-001242
        Rule Name  : SRG-APP-000278
        Rule Title : The applications built-in Malware Agent must be disabled.
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
    $Setting = "Malware Agent"
    $Prop = "Enabled"
    $ExpectedValue = $false

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportAgent $Setting
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportAgent $Setting}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        If ($Result.$($Prop) -eq $ExpectedValue) {
            $Status = "NotAFinding"
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop):`t$($Result.$($Prop))" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop):`t$($Result.$($Prop)) [Expected $($ExpectedValue)]" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Transport Agent $($Setting) is not detected." | Out-String
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

Function Get-V228415 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228415
        STIG ID    : EX16-MB-002900
        Rule ID    : SV-228415r612748_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014
        Rule Title : Exchange must use encryption for RPC client access.
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
    $Setting = "EncryptionRequired"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RpcClientAccess -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RpcClientAccess -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Server)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Server)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228416 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228416
        STIG ID    : EX16-MB-002910
        Rule ID    : SV-228416r684257_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014
        Rule Title : Exchange must use encryption for Outlook Web App (OWA) access.
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
    $Settings = @("InternalUrl", "ExternalUrl")
    $Prop = "Scheme"
    $ExpectedValue = "https"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-OwaVirtualDirectory -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-OwaVirtualDirectory -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        ForEach ($Setting in $Settings) {
            If ($Item.$($Setting).$($Prop)) {
                If ($Item.$($Setting).$($Prop) -eq $ExpectedValue) {
                    $FindingDetails += "$($Item.Name)" | Out-String
                    $FindingDetails += "$($Setting):`t$($Item.$($Setting).AbsoluteUri)" | Out-String
                    $FindingDetails += "" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Item.Server)" | Out-String
                    $FindingDetails += "$($Setting):`t$($Item.$($Setting).AbsoluteUri) [Expected $($ExpectedValue)]" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
            Else {
                $FindingDetails += "$($Setting) is not configured." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
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

Function Get-V228417 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228417
        STIG ID    : EX16-MB-002920
        Rule ID    : SV-228417r766723_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014
        Rule Title : Exchange must have forms-based authentication disabled.
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
    $Setting = "FormsAuthentication"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-OwaVirtualDirectory -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-OwaVirtualDirectory -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Server)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Server)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V228418 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228418
        STIG ID    : EX16-MB-002930
        Rule ID    : SV-228418r612748_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033
        Rule Title : Exchange must have authenticated access set to Integrated Windows Authentication only.
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
    $Setting = "WindowsAuthentication"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-OwaVirtualDirectory -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-OwaVirtualDirectory -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Server)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Server)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAUqUiETmKVUKRu
# PnRBzOrmWwfT+8uiOH7sVBWKe47Bu6CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCmQqAJ8n9+Xwe/A3Imir9IMGda2wny
# BjqzDE3Rfy24OzANBgkqhkiG9w0BAQEFAASCAQChCJfAc2VyczWp/rfriuKB025f
# aiKFa+BKiwVGqdgcenZEnY0+sqSnbsZ3+4PruE3+RzAbLlG3aIeG0Xx1JPE0igDY
# pnn9VVWm63nO6eRNBSef4zcYu8oKkHPHqSuTTByXu4GVVZGKSZkuExd4nLsbm188
# fmBmrInFpg6edgH0+e/CRE2VJQFd/oLpqhMvRkPM/2dtlPS8kc3hrokOIrIvfAeh
# QppBrRFx7UxgmMSEjoT8mLourKOvdBojteu20k6/KEBb2KOPENwCCfKkGX/fQLIZ
# OdzSEpQyRYXw5O78vhqOJ+gZUWrwQuZ9Zv2dlBCKPyM+OkRDGWy/L8DBqQoT
# SIG # End signature block
