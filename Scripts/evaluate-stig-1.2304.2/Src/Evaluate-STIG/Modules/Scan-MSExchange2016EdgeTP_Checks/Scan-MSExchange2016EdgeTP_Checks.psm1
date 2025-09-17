##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft Exchange 2016 Edge Transport Server
# Version:  V2R4
# Class:    UNCLASSIFIED
# Updated:  4/25/2023
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V221202 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221202
        STIG ID    : EX16-ED-000010
        Rule ID    : SV-221202r612603_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001
        Rule Title : Exchange must limit the Receive connector timeout.
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
    $ExpectedValue = (New-TimeSpan -Minutes 5)
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

Function Get-V221203 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221203
        STIG ID    : EX16-ED-000020
        Rule ID    : SV-221203r612603_rule
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
        $FindingDetails += "CertificateDomains:`t$($Item.CertificateDomains -join ", ")" | Out-String
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

Function Get-V221204 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221204
        STIG ID    : EX16-ED-000030
        Rule ID    : SV-221204r612603_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-APP-000038
        Rule Title : Exchange must have accepted domains configured.
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
    $Setting = "Default"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-AcceptedDomain
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-AcceptedDomain}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            If ($Item.$($Setting) -eq $ExpectedValue) {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "DomainName:`t$($Item.DomainName)" | Out-String
                $FindingDetails += "$($Setting):`t`t$($Item.$($Setting))" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "DomainName:`t$($Item.DomainName)" | Out-String
                $FindingDetails += "$($Setting):`t`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $FindingDetails += "No Accepted Domains configured." | Out-String
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

Function Get-V221205 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221205
        STIG ID    : EX16-ED-000040
        Rule ID    : SV-221205r612603_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-APP-000038
        Rule Title : Exchange must have auto-forwarding of email to remote domains disabled or restricted.
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

Function Get-V221206 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221206
        STIG ID    : EX16-ED-000050
        Rule ID    : SV-221206r612603_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-APP-000038
        Rule Title : Exchange external Receive connectors must be domain secure-enabled.
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
    $Setting = "DomainSecureEnabled"
    $ExpectedValue = $true
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

Function Get-V221207 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221207
        STIG ID    : EX16-ED-000060
        Rule ID    : SV-221207r612603_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : The Exchange email Diagnostic log level must be set to the lowest level.
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

Function Get-V221208 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221208
        STIG ID    : EX16-ED-000070
        Rule ID    : SV-221208r612603_rule
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

Function Get-V221210 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221210
        STIG ID    : EX16-ED-000090
        Rule ID    : SV-221210r612603_rule
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

Function Get-V221212 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221212
        STIG ID    : EX16-ED-000110
        Rule ID    : SV-221212r612603_rule
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

Function Get-V221216 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221216
        STIG ID    : EX16-ED-000150
        Rule ID    : SV-221216r612603_rule
        CCI ID     : CCI-001749
        Rule Name  : SRG-APP-000131
        Rule Title : The Exchange local machine policy must require signed scripts.
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

Function Get-V221217 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221217
        STIG ID    : EX16-ED-000160
        Rule ID    : SV-221217r612603_rule
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
    $Prop2 = "DNSRoutingEnabled"
    $ExpectedValue2 = $false
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
            If (($Item.$($Prop1) | Measure-Object).Count -ge $ExpectedValue1 -and $Item.$($Prop2) -eq $ExpectedValue2) {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Prop1):`t`t`t$($Item.$($Prop1) -join ', ')" | Out-String
                $FindingDetails += "$($Prop2):`t$($Item.$($Prop2))" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Item.Name)" | Out-String
                If (($Item.$($Prop1) | Measure-Object).Count -ge $ExpectedValue1) {
                    $FindingDetails += "$($Prop1):`t`t`t$($Item.$($Prop1) -join ', ')" | Out-String
                }
                Else {
                    $FindingDetails += "$($Prop1):`t`t`tNULL [Expected IP address(s)]" | Out-String
                }
                If ($Item.$($Prop2) -eq $ExpectedValue2) {
                    $FindingDetails += "$($Prop2):`t$($Item.$($Prop2)) [Expected $($ExpectedValue2)]" | Out-String
                }
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

Function Get-V221218 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221218
        STIG ID    : EX16-ED-000170
        Rule ID    : SV-221218r811174_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219
        Rule Title : Exchange internal Send connectors must use domain security (mutual authentication Transport Layer Security).
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
    $Prop2 = "DomainSecureEnabled"
    $ExpectedValue2 = $false
    $Prop3 = "DNSRoutingEnabled"
    $ExpectedValue3 = $false
    $Prop4 = "RequireTLS"
    $ExpectedValue4 = $true
    $Prop5 = "TlsAuthLevel"
    $ExpectedValue5 = "DomainValidation"
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
            If (($Item.$($Prop1) | Measure-Object).Count -lt $ExpectedValue1) {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Prop1):`t`t`tNULL" | Out-String
                If ($Item.$($Prop2) -eq $true) {
                    $FindingDetails += "$($Prop2):`t$($Item.$($Prop2))" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Prop2):`t$($Item.$($Prop2)) [Expected True]" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
            Else {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Prop1):`t`t`t$($Item.$($Prop1) -join ', ')" | Out-String
                # Prop2
                If ($Item.$($Prop2) -eq $ExpectedValue2) {
                    $FindingDetails += "$($Prop2):`t$($Item.$($Prop2))" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Prop2):`t$($Item.$($Prop2)) [Expected $($ExpectedValue2)]" | Out-String
                }

                # Prop3
                If ($Item.$($Prop3) -eq $ExpectedValue3) {
                    $FindingDetails += "$($Prop3):`t$($Item.$($Prop3))" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Prop3):`t$($Item.$($Prop3)) [Expected $($ExpectedValue3)]" | Out-String
                }

                # Prop4
                If ($Item.$($Prop4) -eq $ExpectedValue4) {
                    $FindingDetails += "$($Prop4):`t`t`t$($Item.$($Prop4))" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Prop4):`t`t`t$($Item.$($Prop4)) [Expected $($ExpectedValue4)]" | Out-String
                }

                # Prop5
                If ($Item.$($Prop5) -eq $ExpectedValue5) {
                    $FindingDetails += "$($Prop5):`t`t`t$($Item.$($Prop5))" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Prop5):`t`t`t$($Item.$($Prop5)) [Expected $($ExpectedValue5)]" | Out-String
                }
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

Function Get-V221219 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221219
        STIG ID    : EX16-ED-000180
        Rule ID    : SV-221219r612603_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219
        Rule Title : Exchange Internet-facing Receive connectors must offer Transport Layer Security (TLS) before using basic authentication.
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
    $ExpectedValue = "Tls, BasicAuth, BasicAuthRequireTLS"
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

Function Get-V221220 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221220
        STIG ID    : EX16-ED-000190
        Rule ID    : SV-221220r612603_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Outbound Connection Timeout must be 10 minutes or less.
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

Function Get-V221221 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221221
        STIG ID    : EX16-ED-000200
        Rule ID    : SV-221221r612603_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Outbound Connection Limit per Domain Count must be controlled.
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

Function Get-V221222 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221222
        STIG ID    : EX16-ED-000230
        Rule ID    : SV-221222r612603_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Send connector connections count must be limited.
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

Function Get-V221223 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221223
        STIG ID    : EX16-ED-000240
        Rule ID    : SV-221223r612603_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange message size restrictions must be controlled on Send connectors.
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

Function Get-V221224 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221224
        STIG ID    : EX16-ED-000250
        Rule ID    : SV-221224r612603_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Send connectors delivery retries must be controlled.
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
    $Setting = "TransientFailureRetryCount"
    $ExpectedValue = "10"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportService -Identity $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportService -Identity $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -le $ExpectedValue) {
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

Function Get-V221225 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221225
        STIG ID    : EX16-ED-000260
        Rule ID    : SV-221225r612603_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Send connectors must be clearly named.
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
    $Setting = "Identity"

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

Function Get-V221226 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221226
        STIG ID    : EX16-ED-000270
        Rule ID    : SV-221226r612603_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Receive connector Maximum Hop Count must be 60.
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

Function Get-V221227 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221227
        STIG ID    : EX16-ED-000280
        Rule ID    : SV-221227r612603_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Receive connectors must be clearly named.
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
    $Setting = "Identity"

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

Function Get-V221228 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221228
        STIG ID    : EX16-ED-000290
        Rule ID    : SV-221228r612603_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Receive connectors must control the number of recipients chunked on a single message.
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
    $Setting = "ChunkingEnabled"
    $ExpectedValue = $true
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

Function Get-V221229 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221229
        STIG ID    : EX16-ED-000300
        Rule ID    : SV-221229r612603_rule
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

Function Get-V221230 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221230
        STIG ID    : EX16-ED-000310
        Rule ID    : SV-221230r612603_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Internet Receive connector connections count must be set to default.
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
    $Setting = "MaxInboundConnection"
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

Function Get-V221231 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221231
        STIG ID    : EX16-ED-000320
        Rule ID    : SV-221231r612603_rule
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

Function Get-V221232 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221232
        STIG ID    : EX16-ED-000330
        Rule ID    : SV-221232r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange messages with a blank sender field must be rejected.
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
        $Setting = "Action"
        $ExpectedValue = "Reject"

        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
            $Result = Get-SenderFilterConfig
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderFilterConfig}"
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

Function Get-V221233 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221233
        STIG ID    : EX16-ED-000340
        Rule ID    : SV-221233r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange messages with a blank sender field must be filtered.
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
        $Setting = "BlankSenderBlockingEnabled"
        $ExpectedValue = $true

        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
            $Result = Get-SenderFilterConfig
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderFilterConfig}"
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

Function Get-V221234 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221234
        STIG ID    : EX16-ED-000350
        Rule ID    : SV-221234r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange filtered messages must be archived.
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
    $Setting = "QuarantineMailbox"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ContentFilterConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ContentFilterConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting)) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`tNULL [Exepected SMTP address]" | Out-String
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

Function Get-V221235 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221235
        STIG ID    : EX16-ED-000360
        Rule ID    : SV-221235r836314_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Sender filter must block unaccepted domains.
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
    $Prop1 = "BlockedDomains"
    $Prop2 = "BlockedDomainsAndSubdomains"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SenderFilterConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ContentFilterConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    $FindingDetails += "$($Prop1):`t`t`t`t$($Result.$($Prop1) -join ', ')" | Out-String
    $FindingDetails += "$($Prop2):`t$($Result.$($Prop2) -join ', ')" | Out-String
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

Function Get-V221236 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221236
        STIG ID    : EX16-ED-000370
        Rule ID    : SV-221236r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange nonexistent recipients must not be blocked.
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
    $Setting = "RecipientValidationEnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RecipientFilterConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RecipientFilterConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221237 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221237
        STIG ID    : EX16-ED-000380
        Rule ID    : SV-221237r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Sender Reputation filter must be enabled.
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
        $Result = Get-SenderReputationConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderReputationConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221238 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221238
        STIG ID    : EX16-ED-000390
        Rule ID    : SV-221238r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Sender Reputation filter must identify the spam block level.
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
    $Setting = "SrlBlockThreshold"
    $ExpectedValue = 6
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SenderReputationConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderReputationConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221239 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221239
        STIG ID    : EX16-ED-000400
        Rule ID    : SV-221239r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange Attachment filtering must remove undesirable attachments by file type.
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
        $Result = Get-AttachmentFilterEntry
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-AttachmentFilterEntry}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "Type:`t$($Item.Type)" | Out-String
            $FindingDetails += "Identity:`t$($Item.Identity)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "No Attachment Filters are configured." | Out-String
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

Function Get-V221240 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221240
        STIG ID    : EX16-ED-000410
        Rule ID    : SV-221240r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Spam Evaluation filter must be enabled.
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
        $Result = Get-ContentFilterConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ContentFilterConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221241 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221241
        STIG ID    : EX16-ED-000420
        Rule ID    : SV-221241r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Block List service provider must be identified.
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
    $Prop1 = "Name"
    $Prop2 = "GUID"
    $Prop3 = "LookupDomain"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            If ($null -ne $Result.$($Prop1) -and $null -ne $Result.$($Prop2) -and $null -ne $Result.$($Prop3)) {
                $FindingDetails += "$($Prop1):`t`t`t$($Item.$($Prop1))" | Out-String
                $FindingDetails += "$($Prop2):`t`t`t$($Item.$($Prop2))" | Out-String
                $FindingDetails += "$($Prop3):`t$($Item.$($Prop3))" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                If ($null -ne $Result.$($Prop1)) {
                    $FindingDetails += "$($Prop1):`t`t`t$($Item.$($Prop1))" | Out-String
                }
                Else {
                    $FindingDetails += "$($Prop1):`t`t`t$($Item.$($Prop1)) [Not Configured]" | Out-String
                }
                If ($null -ne $Result.$($Prop2)) {
                    $FindingDetails += "$($Prop2):`t`t`t$($Item.$($Prop2))" | Out-String
                }
                Else {
                    $FindingDetails += "$($Prop2):`t`t`t$($Item.$($Prop2)) [Not Configured]" | Out-String
                }
                If ($null -ne $Result.$($Prop3)) {
                    $FindingDetails += "$($Prop3):`t$($Item.$($Prop3))" | Out-String
                }
                Else {
                    $FindingDetails += "$($Prop3):`t$($Item.$($Prop3)) [Not Configured]" | Out-String
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
    Else {
        $Status = "Not_Applicable"
        $FindingDetails += "No service providers configured so this requirement is NA." | Out-String
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

Function Get-V221242 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221242
        STIG ID    : EX16-ED-000430
        Rule ID    : SV-221242r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange messages with a malformed From address must be rejected.
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
    $Setting = "SpoofedDomainAction"
    $ExpectedValue = "Reject"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SenderIdConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderIdConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221243 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221243
        STIG ID    : EX16-ED-000470
        Rule ID    : SV-221243r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Recipient filter must be enabled.
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
        $Result = Get-RecipientFilterConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RecipientFilterConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221244 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221244
        STIG ID    : EX16-ED-000480
        Rule ID    : SV-221244r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange tarpitting interval must be set.
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
    $Setting = "TarpitInterval"
    $ExpectedValue = (New-TimeSpan -Seconds 5)
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
        If ($Item.$($Setting) -ge $ExpectedValue) {
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

Function Get-V221245 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221245
        STIG ID    : EX16-ED-000490
        Rule ID    : SV-221245r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange internal Receive connectors must not allow anonymous connections.
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

Function Get-V221246 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221246
        STIG ID    : EX16-ED-000500
        Rule ID    : SV-221246r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange Simple Mail Transfer Protocol (SMTP) IP Allow List entries must be empty.
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
        $Result = Get-IPAllowListEntry -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-IPAllowListEntry -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        $Compliant = $false
        ForEach ($Item in $Result) {
            $FindingDetails += "Identity:`t$($Item.Identity)" | Out-String
            $FindingDetails += "IPRange:`t$($Item.IPRange)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "No entries configured in the SMTP IP Allow List." | Out-String
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

Function Get-V221247 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221247
        STIG ID    : EX16-ED-000510
        Rule ID    : SV-221247r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Simple Mail Transfer Protocol (SMTP) IP Allow List Connection filter must be enabled.
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
        $Result = Get-IPAllowListConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-IPAllowListConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221248 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221248
        STIG ID    : EX16-ED-000520
        Rule ID    : SV-221248r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Simple Mail Transfer Protocol (SMTP) Sender filter must be enabled.
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
        $Setting = "Enabled"
        $ExpectedValue = $true
        $Compliant = $true

        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
            $Result = Get-SenderFilterConfig
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderFilterConfig}"
            $Result = Invoke-Expression $PSCommand
        }

        If ($Result.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Result.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Result.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }

        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
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

Function Get-V221249 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221249
        STIG ID    : EX16-ED-000530
        Rule ID    : SV-221249r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have antispam filtering installed.
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

Function Get-V221250 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221250
        STIG ID    : EX16-ED-000540
        Rule ID    : SV-221250r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have antispam filtering enabled.
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

Function Get-V221252 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221252
        STIG ID    : EX16-ED-000560
        Rule ID    : SV-221252r612603_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange Sender Identification Framework must be enabled.
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
        $Result = Get-SenderIdConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderIdConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221253 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221253
        STIG ID    : EX16-ED-000570
        Rule ID    : SV-221253r811176_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must render hyperlinks from email sources from non-.mil domains as unclickable.
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

Function Get-V221256 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221256
        STIG ID    : EX16-ED-000610
        Rule ID    : SV-221256r612603_rule
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

Function Get-V221258 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221258
        STIG ID    : EX16-ED-000630
        Rule ID    : SV-221258r612603_rule
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

Function Get-V221259 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221259
        STIG ID    : EX16-ED-000660
        Rule ID    : SV-221259r612603_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange must provide redundancy.
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
    $Result = Get-TransportService
    If (($Result | Measure-Object).Count -gt 1) {
        $Status = "NotAFinding"
        $FindingDetails += "Multiple Edge servers detected." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Multiple Edge servers NOT detected." | Out-String
        $FindingDetails += "" | Out-String
    }

    ForEach ($Item in $Result) {
        $FindingDetails += "$($Item.Name)" | Out-String
        $FindingDetails += "ExchangeVersion:`t$($Item.ExchangeVersion)" | Out-String
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

Function Get-V221260 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221260
        STIG ID    : EX16-ED-000670
        Rule ID    : SV-221260r612603_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange internal Send connectors must use an authentication level.
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

Function Get-V221261 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221261
        STIG ID    : EX16-ED-000680
        Rule ID    : SV-221261r612603_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439
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

Function Get-V221262 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221262
        STIG ID    : EX16-ED-000690
        Rule ID    : SV-221262r811179_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439
        Rule Title : Exchange internal Send connectors must require encryption.
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
    $Prop1 = "TlsDomain"
    $ExpectedValue1 = 1
    $Prop2 = "DomainSecureEnabled"
    $Prop3 = "SmartHosts"
    $ExpectedValue3 = 1
    $Prop4 = "RequireTLS"
    $ExpectedValue4 = $true
    $Prop5 = "TlsAuthLevel"
    $ExpectedValue5 = "DomainValidation"
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
            $FindingDetails += "$($Item.Name)" | Out-String
            If ($Item.$($Prop1)) {
                $FindingDetails += "$($Prop1):`t$($Item.$($Prop1))" | Out-String
                $FindingDetails += "$($Prop2):`t$($Item.$($Prop2))" | Out-String
                If ($Item.$($Prop2) -eq $true) {
                    If (($Item.$($Prop3) | Measure-Object).Count -ge $ExpectedValue3) {
                        $FindingDetails += "$($Prop3):`t$($Item.$($Prop3))" | Out-String
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "$($Prop3):`t$($Item.$($Prop3)) [Expected SmartHost(s)]" | Out-String
                    }
                }
                Else {
                    $FindingDetails += "$($Prop3):`t$($Item.$($Prop3))" | Out-String
                    If (($Item.$($Prop3) | Measure-Object).Count -ge $ExpectedValue3) {
                        $FindingDetails += "$($Prop3):`t$($Item.$($Prop3) -join ', ')" | Out-String
                        If ($Item.$($Prop4) -eq $ExpectedValue4) {
                            $FindingDetails += "$($Prop4):`t$($Item.$($Prop4))" | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "$($Prop4):`t$($Item.$($Prop4)) [Expected $($ExpectedValue4)]" | Out-String
                        }
                        If ($Item.$($Prop5) -eq $ExpectedValue5) {
                            $FindingDetails += "$($Prop5):`t$($Item.$($Prop5))" | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "$($Prop5):`t$($Item.$($Prop5)) [Expected $($ExpectedValue5)]" | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Prop1):`t$($Item.$($Prop1)) [Expected SMTP Domain]" | Out-String
            }
            $FindingDetails += "" | Out-String
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

Function Get-V221263 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221263
        STIG ID    : EX16-ED-000700
        Rule ID    : SV-221263r612603_rule
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

Function Get-V221264 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221264
        STIG ID    : EX16-ED-000720
        Rule ID    : SV-221264r612603_rule
        CCI ID     : CCI-001241
        Rule Name  : SRG-APP-000277
        Rule Title : The application must configure malicious code protection mechanisms to perform periodic scans of the information system every seven days.
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

Function Get-V221266 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221266
        STIG ID    : EX16-ED-000750
        Rule ID    : SV-221266r612603_rule
        CCI ID     : CCI-001243
        Rule Name  : SRG-APP-000279
        Rule Title : The application must be configured to block and quarantine malicious code upon detection, then send an immediate alert to appropriate individuals.
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

Function Get-V221268 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221268
        STIG ID    : EX16-ED-002400
        Rule ID    : SV-221268r612603_rule
        CCI ID     : CCI-001240
        Rule Name  : SRG-APP-000276
        Rule Title : The application must update malicious code protection mechanisms whenever new releases are available in accordance with organizational configuration management policy and procedures.
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

Function Get-V221270 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221270
        STIG ID    : EX16-ED-003010
        Rule ID    : SV-221270r612603_rule
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDTUfue5ajYyHkH
# Y7EO8ekGUSYPvzQPltDZTaOcTH1Ko6CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDuCy2LgS9OQrnB5jZWP8tPTpZG7Ms7
# nSQwZnnooUmi9jANBgkqhkiG9w0BAQEFAASCAQADcTwZkrkG+97dPBxh1DztuIv+
# DAcPV9nLerwGtMM/MUv+2Kw8cgrfqCWcSyXiRlKhXsUU5yd+/ztm/Y7SVbV9fz74
# SiCeR8v1t1koX7mRQL7P2xPqq2xWHrPU9VrBPrvDGFqooCO+b/CQaqShxzrkkhMo
# gVk1PcLElgIPkN43kp1gGT8GPFNPQGTW8VI4+J2Fb3Sv+wksBVSKC6OIcQEQEZY6
# /gaUQwKsECJNKajcBLFha8TaTXfq82LJwaTIMBogj3d9kb8yHrgiQ9Xfm4GGk9Bk
# +d5couapxdawEihtAr1n92u5AezMlW8gPCMdAxGA8kwlqeZfEwOoCi8x24U1
# SIG # End signature block
