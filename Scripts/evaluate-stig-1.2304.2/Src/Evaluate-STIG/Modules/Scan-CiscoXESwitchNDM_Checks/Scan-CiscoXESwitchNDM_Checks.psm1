##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS XE Switch NDM
# Version:  V2R6
# Class:    UNCLASSIFIED
# Updated:  5/19/2023
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V220518 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220518
        STIG ID    : CISC-ND-000010
        Rule ID    : SV-220518r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-NDM-000200
        Rule Title : The Cisco switch must be configured to limit the number of concurrent management sessions to an organization-defined number.
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
    $OpenFinding = $False
    $HttpServer = $ShowRunningConfig | Select-String -Pattern "^no ip http"
    $LineVtys = $ShowRunningConfig | Select-String -Pattern "line vty"
    IF ($HttpServer -like "no ip http server" -AND $HttpServer -like "no ip http secure-server") {
        $FindingDetails += "IP Http Server Settings:" | Out-String
        $FindingDetails += "http\https servers are disabled, https requirements are not applicable" | Out-String
        $FindingDetails += ($HttpServer | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $HttpMaxConnections = $ShowRunningConfig | Select-String -Pattern "ip http max-connections"
        IF ($HttpMaxConnections) {
            $FindingDetails += "IP http Server Settings:" | Out-String
            $FindingDetails += ($HttpMaxConnections | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "" | Out-String
            IF (!((($HttpMaxConnections | Out-String).Trim()).Split([char[]]"")[3] -le "2")) {
                $OpenFinding = $True
            }
        }
        Else {
            $IPHttpServerConf = $ShowRunningConfig | Select-String -Pattern "^ip http"
            IF ($IPHttpServerConf -like "ip http server" -or $IPHttpServerConf -like "ip http secure-server") {
                $OpenFinding = $True
                $FindingDetails += "IP Http Server Settings:" | Out-String
                $FindingDetails += "The router is not configured to limit the number of concurrent management sessions (https)" | Out-String
                $FindingDetails += ($IPHttpServerConf | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $FindingDetails += "Https server is not enabled, https requirements is not applicable" | Out-String
                $FindingDetails += ($IPHttpServerConf | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }

    IF (!($LineVtys[0] | Select-String -Pattern "0\s1")) {
        $SessionLimit = Get-Section $ShowRunningConfig $LineVtys[0].ToString() | Select-String -Pattern "session-limit"
        IF ($SessionLimit) {
            IF (!(($SessionLimit | Out-String).Trim().Split([char[]]"")[1] -le 2)) {
                $OpenFinding = $True
            }
        }
        Else {
            $OpenFinding = $True
        }
    }
    IF (!(Get-Section $ShowRunningConfig $LineVtys[0] | Select-String -Pattern "transport input ssh")) {
        $OpenFinding = $True
    }

    if ($LineVtys[1]) {
        IF (!($LineVtys[1] | Select-String -Pattern "2\s4")) {
            $OpenFinding = $True
        }
    }

    $LineVtys | Select-Object -Skip 1 | ForEach-Object {IF (!(Get-Section $ShowRunningConfig $_ | Select-String -Pattern "transport input none")) {
            $OpenFinding = $True
        }}

    ForEach ($vty in $LineVtys) {
        $FindingDetails += ($vty | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += " " + (Get-Section $ShowRunningConfig $vty.ToString() | Select-String -Pattern "transport input" | Out-String).Trim()
        IF (Get-Section $ShowRunningConfig $Vty.ToString() | Select-String -Pattern "session-limit") {
            $FindingDetails += " " + (Get-Section $ShowRunningConfig $Vty.ToString() | Select-String -Pattern "session-limit" | Out-String).Trim()
        }
        $FindingDetails += "" | Out-String
    }

    IF ($OpenFinding) {
        $Status = "Open"
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

Function Get-V220519 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220519
        STIG ID    : CISC-ND-000090
        Rule ID    : SV-220519r879525_rule
        CCI ID     : CCI-000018
        Rule Name  : SRG-APP-000026-NDM-000208
        Rule Title : The Cisco switch must be configured to automatically audit account creation.
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V220520 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220520
        STIG ID    : CISC-ND-000100
        Rule ID    : SV-220520r879526_rule
        CCI ID     : CCI-001403
        Rule Name  : SRG-APP-000027-NDM-000209
        Rule Title : The Cisco switch must be configured to automatically audit account modification.
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V220521 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220521
        STIG ID    : CISC-ND-000110
        Rule ID    : SV-220521r879527_rule
        CCI ID     : CCI-001404
        Rule Name  : SRG-APP-000028-NDM-000210
        Rule Title : The Cisco switch must be configured to automatically audit account disabling actions.
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V220522 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220522
        STIG ID    : CISC-ND-000120
        Rule ID    : SV-220522r879528_rule
        CCI ID     : CCI-001405
        Rule Name  : SRG-APP-000029-NDM-000211
        Rule Title : The Cisco switch must be configured to automatically audit account removal actions.
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V220523 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220523
        STIG ID    : CISC-ND-000140
        Rule ID    : SV-220523r879533_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-APP-000038-NDM-000213
        Rule Title : The Cisco switch must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.
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
    $LineVtys = $ShowRunningConfig | Select-String -Pattern "line vty"

    $AccessClass = Get-Section $ShowRunningConfig $LineVtys[0].ToString() | Select-String -Pattern "access-class .* in"
    IF (!$AccessClass) {
        $FindingDetails += ($LineVtys[0] | Out-String).Trim() + " - No inbound access-class set" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += (Get-Section $ShowRunningConfig $LineVtys[0] | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    Else {
        $AccessGroup = (($AccessClass | Out-String).Trim()).Split([char[]]"")[1]
        $SectionName = $ShowRunningConfig | Select-String -Pattern "ip access-list .* $AccessGroup"
        $FindingDetails += ($LineVtys[0] | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += (Get-Section $ShowRunningConfig $LineVtys[0].ToString() | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += "" | Out-String
        IF ($SectionName) {
            $IPAccessList = (Get-Section $ShowRunningConfig $SectionName | Out-String).Trim()
            $FindingDetails += ($SectionName | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($IPAccessList | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        Else {
            $FindingDetails += "An IP Access List for $AccessGroup is not configured" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $LineVtys | Select-Object -Skip 1 | ForEach-Object {
        IF (!(Get-Section $ShowRunningConfig $_ | Select-String -Pattern "transport input none")) {
            $AccessClass = Get-Section $ShowRunningConfig $_ | Select-String -Pattern "access-class .* in"
            IF (!$AccessClass) {
                $FindingDetails += ($_ | Out-String).Trim() + " - No inbound access-class set" | Out-String
                $FindingDetails += (Get-Section $ShowRunningConfig $_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
            Else {
                $AccessGroup = (($AccessClass | Out-String).Trim()).Split([char[]]"")[1]
                $SectionName = $ShowRunningConfig | Select-String -Pattern "ip access-list .* $AccessGroup"
                $IPAccessList = (Get-Section $ShowRunningConfig $SectionName | Out-String).Trim()
                $FindingDetails += ($_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += (Get-Section $ShowRunningConfig $_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += ($SectionName | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += ($IPAccessList | Out-String).Trim()
                $FindingDetails += "" | Out-String
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

Function Get-V220524 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220524
        STIG ID    : CISC-ND-000150
        Rule ID    : SV-220524r879546_rule
        CCI ID     : CCI-000044
        Rule Name  : SRG-APP-000065-NDM-000214
        Rule Title : The Cisco switch must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.
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
    $OpenFinding = $False
    $LogonAttemptsConf = $ShowRunningConfig | Select-String -Pattern "login block-for"
    IF (!$LogonAttemptsConf) {
        $FindingDetails += "Logon attempts are not limited" | Out-String
        $OpenFinding = $True
    }
    Else {
        [INT]$LoginAttempts = (($LogonAttemptsConf | Out-String).Trim()).Split([char[]]"")[4]
        [INT]$LockOut = (($LogonAttemptsConf | Out-String).Trim()).Split([char[]]"")[2]
        IF ($LoginAttempts -gt "3") {
            $OpenFinding = $True
        }
        IF ($LockOut -lt "900") {
            $OpenFinding = $True
        }
        $FindingDetails += ($LogonAttemptsConf | Out-String).Trim()
    }
    IF ($OpenFinding) {
        $Status = "Open"
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

Function Get-V220525 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220525
        STIG ID    : CISC-ND-000160
        Rule ID    : SV-220525r879547_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-APP-000068-NDM-000215
        Rule Title : The Cisco switch must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.
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
    $BannerStartSTR = ($ShowRunningConfig | Select-String -Pattern "^banner login \^C.*" | Out-String).Trim()
    IF ($BannerStartSTR) {
        $BannerEndSTR = "^\^C"
        $BannerStartIndex = $ShowRunningConfig.indexof($BannerStartSTR) + 1
        $BannerEndIndex = $BannerStartIndex + ((($ShowRunningConfig | Select-Object -Index ($BannerStartIndex..$ShowRunningConfig.Count) | Select-String $BannerEndSTR)[0]).LineNumber - 2)
        $RTRBanner = $ShowRunningConfig | Select-Object -Index ($BannerStartIndex..$BannerEndIndex) | Out-String
        $RTRBanner_CharArray = (($RTRBanner -replace "\s+", "" | Out-String).Trim()).Replace("`n", "").ToLower().ToCharArray()
        ForEach ($Char in $RTRBanner_CharArray) {
            $RTRBannerHex = $RTRBannerHex + [System.String]::Format("{0:X2}", [System.Convert]::ToUInt32($Char))
        }
        $DoDConsentBanner = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.`r`nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:`r`n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.`r`n-At any time, the USG may inspect and seize data stored on this IS.`r`n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.`r`n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.`r`n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
        $DoDConsentBanner_CharArray = (($DoDConsentBanner -replace "\s+", "" | Out-String).Trim()).Replace("`n", "").ToLower().ToCharArray()
        ForEach ($Char in $DoDConsentBanner_CharArray) {
            $DoDConsentBannerHex = $DoDConsentBannerHex + [System.String]::Format("{0:X2}", [System.Convert]::ToUInt32($Char))
        }
        $FindingDetails += ($RTRBanner | Out-String).Trim()
        IF ($RTRBannerHex -eq $DoDConsentBannerHex) {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "Cisco router is not configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device" | Out-String
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

Function Get-V220526 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220526
        STIG ID    : CISC-ND-000210
        Rule ID    : SV-220526r879554_rule
        CCI ID     : CCI-000166, CCI-000172, CCI-002234
        Rule Name  : SRG-APP-000080-NDM-000220
        Rule Title : The Cisco device must be configured to audit all administrator activity.
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
    $HostName = $ShowRunningConfig | Select-String -Pattern "hostname"
    $LoggingUserinfo = $ShowRunningConfig | Select-String -Pattern "logging userinfo"
    IF (!$LoggingUserinfo) {
        $FindingDetails += ($HostName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += "Logging userinfo is not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += ($HostName | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($LoggingUserinfo | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += ($ArchiveSettings | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += ($HostName | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($LoggingUserinfo | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "archive" | Out-String
            $FindingDetails += ($ArchiveSettings | Out-String).Trim()
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

Function Get-V220528 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220528
        STIG ID    : CISC-ND-000280
        Rule ID    : SV-220528r879564_rule
        CCI ID     : CCI-000131
        Rule Name  : SRG-APP-000096-NDM-000226
        Rule Title : The Cisco switch must produce audit records containing information to establish when (date and time) the events occurred.
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
    $TimeStamp = $ShowRunningConfig | Select-String -Pattern "service timestamps log datetime"
    IF (!$TimeStamp) {
        $FindingDetails += "Date and Time timestamps are not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $FindingDetails += ($TimeStamp | Out-String).Trim()
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

Function Get-V220529 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220529
        STIG ID    : CISC-ND-000290
        Rule ID    : SV-220529r879565_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-APP-000097-NDM-000227
        Rule Title : The Cisco switch must produce audit records containing information to establish where the events occurred.
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
    $OpenFinding = $False
    $IPAccessListSectionNames = $ShowRunningConfig | Select-String -Pattern "ip access-list" | Where-Object {$_ -notlike "*CoPP*"}
    IF ($IPAccessListSectionNames) {
        ForEach ($SectionName in $IPAccessListSectionNames) {
            $DenyACL = Get-Section $ShowRunningConfig $SectionName | Select-String -Pattern "deny" | Where-Object {$_ -notmatch "remark"}
            $FindingDetails += ($SectionName | Out-String).Trim()
            $FindingDetails += "" | Out-String
            IF (!$DenyACL) {
                $OpenFinding = $True
                $FindingDetails += ("Deny statement not configured" | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
            Else {
                ForEach ($Deny in $DenyACL) {
                    IF (!($Deny -like "*log-input*")) {
                        $OpenFinding = $True
                    }
                    $FindingDetails += ($Deny | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
            }
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $OpenFinding = $True
        $FindingDetails += "IP Access Lists are not configured" | Out-String
        $FindingDetails += "" | Out-String
    }
    IF ($OpenFinding) {
        $Status = "Open"
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

Function Get-V220530 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220530
        STIG ID    : CISC-ND-000330
        Rule ID    : SV-220530r879569_rule
        CCI ID     : CCI-000135
        Rule Name  : SRG-APP-000101-NDM-000231
        Rule Title : The Cisco switch must be configured to generate audit records containing the full-text recording of privileged commands.
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V220531 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220531
        STIG ID    : CISC-ND-000380
        Rule ID    : SV-220531r879577_rule
        CCI ID     : CCI-000163
        Rule Name  : SRG-APP-000119-NDM-000236
        Rule Title : The Cisco switch must be configured to protect audit information from unauthorized modification.
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
    $LoggingPersistent = $ShowRunningConfig | Select-String -Pattern "^logging persistent"
    IF (!$LoggingPersistent) {
        $FindingDetails += "Logging persistent not found, this requirement is not applicable" | Out-String
        $Status = "Not_Applicable"
    }
    Else {
        $FilePrivilege = $ShowRunningConfig | Select-String -Pattern "file privilege"
        IF (!$FilePrivilege) {
            $FindingDetails += "File privilege configuration was not found" | Out-String
            $FindingDetails += "File privilege 15 configuration is assumed" | Out-String
            $FindingDetails += "Please verify settings on router" | Out-String
        }
        Else {
            $FindingDetails += ($FilePrivilege | Out-String).Trim()
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

Function Get-V220532 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220532
        STIG ID    : CISC-ND-000390
        Rule ID    : SV-220532r879578_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-APP-000120-NDM-000237
        Rule Title : The Cisco switch must be configured to protect audit information from unauthorized deletion.
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
    $LoggingPersistent = $ShowRunningConfig | Select-String -Pattern "^logging persistent"
    IF (!$LoggingPersistent) {
        $FindingDetails += "Logging persistent not found, this requirement is not applicable" | Out-String
        $Status = "Not_Applicable"
    }
    Else {
        $FilePrivilege = $ShowRunningConfig | Select-String -Pattern "file privilege"
        IF (!$FilePrivilege) {
            $FindingDetails += "File privilege configuration was not found" | Out-String
            $FindingDetails += "File privilege 15 configuration is assumed" | Out-String
            $FindingDetails += "Please verify settings on router" | Out-String
        }
        Else {
            $FindingDetails += ($FilePrivilege | Out-String).Trim()
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

Function Get-V220533 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220533
        STIG ID    : CISC-ND-000460
        Rule ID    : SV-220533r879586_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-NDM-000244
        Rule Title : The Cisco switch must be configured to limit privileges to change the software resident within software libraries.
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
    $LoggingPersistent = $ShowRunningConfig | Select-String -Pattern "^logging persistent"
    IF (!$LoggingPersistent) {
        $FindingDetails += "Logging persistent not found, this requirement is not applicable" | Out-String
        $Status = "Not_Applicable"
    }
    Else {
        $FilePrivilege = $ShowRunningConfig | Select-String -Pattern "file privilege"
        IF (!$FilePrivilege) {
            $FindingDetails += "File privilege configuration was not found" | Out-String
            $FindingDetails += "File privilege 15 configuration is assumed" | Out-String
            $FindingDetails += "Please verify settings on router" | Out-String
        }
        Else {
            $FindingDetails += ($FilePrivilege | Out-String).Trim()
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

Function Get-V220534 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220534
        STIG ID    : CISC-ND-000470
        Rule ID    : SV-220534r892403_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-NDM-000245
        Rule Title : The Cisco switch must be configured to prohibit the use of all unnecessary and nonsecure functions and services.
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
    $OpenFinding = $False
    $DisallowedCommands = @(
        "boot network",
        "ip boot server",
        "ip bootp server",
        "ip dns server",
        "ip identd",
        "ip finger",
        "ip http server",
        "ip rcmd rcp-enable",
        "ip rcmd rsh-enable",
        "service config",
        "service finger",
        "service tcp-small-servers",
        "service udp-small-servers",
        "service pad",
        "service call-home"
    )
    ForEach ($Command in $DisallowedCommands) {
        $CommandCheck = $ShowRunningConfig | Select-String -Pattern "^\s*$Command"
        IF ([Bool]$CommandCheck) {
            $OpenFinding = $True
            $FindingDetails += ([STRING]"$CommandCheck Found").ToUpper() | Out-String
        }
        Else {
            $FindingDetails += "$Command not found" | Out-String
        }
    }
    IF ($OpenFinding) {
        $Status = "Open"
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

Function Get-V220535 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220535
        STIG ID    : CISC-ND-000490
        Rule ID    : SV-220535r879589_rule
        CCI ID     : CCI-001358, CCI-002111
        Rule Name  : SRG-APP-000148-NDM-000346
        Rule Title : The Cisco switch must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.
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
    $OpenFinding = $False
    $NR = $False
    $AllUsers = $ShowRunningConfig | Select-String -Pattern "^username"
    $Users = @()
    $AAAGroupServer = $ShowRunningConfig | Select-String -Pattern "^aaa group server"
    $AAALoginMethod = $ShowRunningConfig | Select-String -Pattern "^aaa authentication login"

    #This removes pwd from variable
    ForEach ($User in $AllUsers) {
        $PwdHash = (($User | Out-String).Trim()).Split([char[]]"") | Select-Object -Last 1
        $Users += (($User | Out-String).Trim()).Replace("$PwdHash", "<pwd removed>")
    }

    $FindingDetails += "Accounts" | Out-String
    $FindingDetails += ($Users | Out-String).Trim()
    $FindingDetails += "" | Out-String

    IF ($Allusers.Count -gt "1") {
        $OpenFinding = $True
    }
    Else {
        [INT]$PrivLvl = (-Split $AllUsers)[3]
        if (!($PrivLvl -eq "15")) {
            $NR = $True
            $FindingDetails += "Verify that a local account for last resort has been configured with a privilege level that will enable the administrator to troubleshoot connectivity to the authentication server." | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    IF (!$AAAGroupServer) {
        $OpenFinding = $True; $FindingDetails += ("Authentication Group Server:" | Out-String).Trim(); $FindingDetails += ("AAA Group Server(s) not configured" | Out-String).Trim()
    }
    Else {
        $AllowedAuthServers = @("tacacs+", "radius")
        foreach ($GroupServer in $AAAGroupServer) {
            $AAAAuthSrvrGroupName = ( -Split ($GroupServer | Out-String).Trim().Replace("aaa group server ", ""))[1]
            $AllowedAuthServers += $AAAAuthSrvrGroupName
        }

        IF (!$AAALoginMethod) {
            $OpenFinding = $True; $FindingDetails += "AAA authentication login method not configured"
        }
        Else {
            $FindingDetails += "AAA Login Method:"
            $FindingDetails += "" | Out-String
            ForEach ($LoginMethod in $AAALoginMethod) {
                $AAALoginAuthServer = ( -Split ($LoginMethod | Out-String).Trim().Replace("aaa authentication login ", ""))
                IF ($AAALoginAuthServer[2]) {
                    IF (!($AAALoginAuthServer[2] -in $AllowedAuthServers -AND $AAALoginAuthServer[3] -eq "local")) {
                        $OpenFinding = $True
                    }
                    $FindingDetails += ($LoginMethod | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
                Else {
                    $OpenFinding = $True
                    $FindingDetails += ($LoginMethod | Out-String).Trim() + " " + "- local is not defined after radius or tacas+ in the authentication order."
                    $FindingDetails += "" | Out-String
                }
            }
        }
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        IF (!$NR) {
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

Function Get-V220537 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220537
        STIG ID    : CISC-ND-000550
        Rule ID    : SV-220537r879601_rule
        CCI ID     : CCI-000205
        Rule Name  : SRG-APP-000164-NDM-000252
        Rule Title : The Cisco switch must be configured to enforce a minimum 15-character password length.
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
    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -contains "min-length 15") {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($PwdPolicySettings | Out-String).Trim()
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

Function Get-V220538 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220538
        STIG ID    : CISC-ND-000570
        Rule ID    : SV-220538r879603_rule
        CCI ID     : CCI-000192
        Rule Name  : SRG-APP-000166-NDM-000254
        Rule Title : The Cisco switch must be configured to enforce password complexity by requiring that at least one upper-case character be used.
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
    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -contains "upper-case 1") {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($PwdPolicySettings | Out-String).Trim()
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

Function Get-V220539 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220539
        STIG ID    : CISC-ND-000580
        Rule ID    : SV-220539r879604_rule
        CCI ID     : CCI-000193
        Rule Name  : SRG-APP-000167-NDM-000255
        Rule Title : The Cisco switch must be configured to enforce password complexity by requiring that at least one lower-case character be used.
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
    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -contains "lower-case 1") {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($PwdPolicySettings | Out-String).Trim()
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

Function Get-V220540 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220540
        STIG ID    : CISC-ND-000590
        Rule ID    : SV-220540r879605_rule
        CCI ID     : CCI-000194
        Rule Name  : SRG-APP-000168-NDM-000256
        Rule Title : The Cisco switch must be configured to enforce password complexity by requiring that at least one numeric character be used.
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
    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -contains "numeric-count 1") {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($PwdPolicySettings | Out-String).Trim()
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

Function Get-V220541 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220541
        STIG ID    : CISC-ND-000600
        Rule ID    : SV-220541r879606_rule
        CCI ID     : CCI-001619
        Rule Name  : SRG-APP-000169-NDM-000257
        Rule Title : The Cisco switch must be configured to enforce password complexity by requiring that at least one special character be used.
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
    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -contains "special-case 1") {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($PwdPolicySettings | Out-String).Trim()
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

Function Get-V220542 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220542
        STIG ID    : CISC-ND-000610
        Rule ID    : SV-220542r879607_rule
        CCI ID     : CCI-000195
        Rule Name  : SRG-APP-000170-NDM-000329
        Rule Title : The Cisco switch must be configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password.
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
    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -contains "char-changes 8") {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($PwdPolicySettings | Out-String).Trim()
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

Function Get-V220543 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220543
        STIG ID    : CISC-ND-000620
        Rule ID    : SV-220543r879608_rule
        CCI ID     : CCI-000196
        Rule Name  : SRG-APP-000171-NDM-000258
        Rule Title : The Cisco switch must only store cryptographic representations of passwords.
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
    $OpenFinding = $False
    $PWDEncryption = $ShowRunningConfig | Select-String -Pattern "^service password-encryption"
    $SecretEnabled = $ShowRunningConfig | Select-String -Pattern "^enable secret"
    IF ($PWDEncryption) {
        $FindingDetails += ($PWDEncryption | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    Else {
        $FindingDetails += "service password-encryption not configured" | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    IF ($SecretEnabled) {
        $PwdHash = (($SecretEnabled | Out-String).Trim()).Split([char[]]"") | Select-Object -Last 1
        $SecretEnabled = (($SecretEnabled | Out-String).Trim()).Replace("$PwdHash", "<pwd removed>")
        $FindingDetails += ($SecretEnabled | Out-String).Trim()
    }
    Else {
        $FindingDetails += "Enable secret is not configured" | Out-String
        $OpenFinding = $True
    }
    IF ($OpenFinding) {
        $Status = "Open"
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

Function Get-V220544 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220544
        STIG ID    : CISC-ND-000720
        Rule ID    : SV-220544r916301_rule
        CCI ID     : CCI-001133
        Rule Name  : SRG-APP-000190-NDM-000267
        Rule Title : The Cisco switch must be configured to terminate all network connections associated with device management after five minutes of inactivity.
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
    $OpenFinding = $False
    $NR = $False
    $HttpServer = $ShowRunningConfig | Select-String -Pattern "^no ip http"
    $LineConTimeOut = Get-Section $ShowRunningConfig "line con 0" | Where-Object {$_ -like "exec-timeout*"}
    $LineVtys = $ShowRunningConfig | Select-String -Pattern "^line vty"

    IF ($HttpServer -like "no ip http server" -AND $HttpServer -like "no ip http secure-server") {
        $FindingDetails += "IP HTTP Timeout Settings" | Out-String
        $FindingDetails += ($HttpServer | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += "http\https servers are disabled, http\https requirements are not applicable" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $HttpTimeout = $ShowRunningConfig | Select-String -Pattern "^ip http timeout"
        IF ($HttpTimeout) {
            IF ((($HttpTimeout | Out-String).Trim()).Split([char[]]"")[4] -le "600") {
                $FindingDetails += "IP HTTP Timeout Settings" | Out-String
                $FindingDetails += ($HttpTimeout | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
            Else {
                $OpenFinding = $True
                $FindingDetails += "IP HTTP Timeout Settings" | Out-String
                $FindingDetails += ($HttpTimeout | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }

        }
        Else {
            $OpenFinding = $True
            $FindingDetails += "IP HTTP Timeout Settings are not configured" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    IF ($LineConTimeOut) {
        IF (!([INT]$LineConTimeOut.Split([char[]]"")[1] -le "5")) {
            $OpenFinding + $True
        }
        $FindingDetails += "Console Port Timeout Settings" | Out-String
        $FindingDetails += "line con 0" | Out-String
        $FindingDetails += " " + ($LineConTimeOut | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    Else {
        IF (Get-Section $ShowRunningConfig "line con 0") {
            $OpenFinding + $True
            $FindingDetails += "line con 0" | Out-String
            $FindingDetails += (Get-Section $ShowRunningConfig "line con 0" | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "line con 0 exec-timeout is not configured. Default value of 10 is assumed" | Out-String
            $FindingDetails += "Confirm value is correctly configured by checking against 'show running-config all' configuration file" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $FindingDetails += "Console Port Line Configuration not configured" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    IF ($LineVtys) {
        $FindingDetails += "Line VTY Timeout Settings"
        $VTYTimeout = Get-Section $ShowRunningConfig $LineVtys[0] | Where-Object {$_ -like "exec-timeout*"}
        IF ($VTYTimeout) {
            IF (!([INT]$VTYTimeout.Split([char[]]"")[1] -le "5")) {
                $OpenFinding = $True
            }
            $FindingDetails += ($LineVtys[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += " " + ($VTYTimeout | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        Else {
            $OpenFinding = $True
            $FindingDetails += ($LineVtys[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += (Get-Section $ShowRunningConfig $LineVtys[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($LineVtys[0] | Out-String).Trim() + " " + "exec-timeout is not configured. Default value of 10 is assumed" | Out-String
            $FindingDetails += "Confirm value is correctly configured by checking against 'show running-config all' configuration file" | Out-String
            $FindingDetails += "" | Out-String
        }

        $LineVtys | Select-Object -Skip 1 | ForEach-Object {
            $VTYTimeout = Get-Section $ShowRunningConfig $_ | Where-Object {$_ -like "exec-timeout*"}
            IF ($VTYTimeout) {
                IF (!([INT]$VTYTimeout.Split([char[]]"")[1] -le "5")) {
                    $OpenFinding = $True
                }
                $FindingDetails += ($_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += " " + ($VTYTimeout | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
            Else {
                $OpenFinding = $True
                $FindingDetails += ($_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += (Get-Section $ShowRunningConfig $_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += ($_ | Out-String).Trim() + " " + "exec-timeout is not configured. Default value of 10 is assumed" | Out-String
                $FindingDetails += "Confirm value is correctly configured by checking against 'show running-config all' configuration file" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $OpenFinding + $True
        $FindingDetails += "Line VTY Timeout Settings not set" | Out-String
        $FindingDetails += ""
    }
    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        IF (!$NR) {
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

Function Get-V220545 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220545
        STIG ID    : CISC-ND-000880
        Rule ID    : SV-220545r879696_rule
        CCI ID     : CCI-002130
        Rule Name  : SRG-APP-000319-NDM-000283
        Rule Title : The Cisco switch must be configured to automatically audit account enabling actions.
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V220547 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220547
        STIG ID    : CISC-ND-000980
        Rule ID    : SV-220547r879730_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-NDM-000293
        Rule Title : The Cisco switch must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.
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
    $LoggingBuffer = $ShowRunningConfig | Select-String -Pattern "^logging buffered"
    IF ($LoggingBuffer) {
        $LoggingBuffer -match "\d+" | Out-Null
        $BufferSize = $Matches[0]
        $FindingDetails += "Logging buffer size: $BufferSize" | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Logging buffer size is not configured" | Out-String
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

Function Get-V220548 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220548
        STIG ID    : CISC-ND-001000
        Rule ID    : SV-220548r879733_rule
        CCI ID     : CCI-001858
        Rule Name  : SRG-APP-000360-NDM-000295
        Rule Title : The Cisco switch must be configured to generate an alert for all audit failure events.
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
    $LoggingTrap = $ShowRunningConfig | Select-String -Pattern "^logging trap"
    IF ($LoggingTrap) {
        $FindingDetails += ($LoggingTrap | Out-String).Trim()
        $Status = "NotAFinding"
    }
    Else {
        IF ($ShowRunningConfig | Select-String -Pattern "^no logging trap") {
            $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^no logging trap" | Out-String).Trim()
            $Status = "Open"
        }
        Else {
            $ShowLoggingStartStr = "------------------ show logging ------------------"
            $ShowLoggingEndStr = "------------------ show pnp tech-support ------------------"
            $ShowLoggingstartIndex = $ShowTech.indexof($ShowLoggingStartStr) + 1
            $ShowLoggingendIndex = $ShowTech.indexof($ShowLoggingEndStr) - 1
            $ShowLoggingConfig = $ShowTech | Select-Object -Index ($ShowLoggingstartIndex..$ShowLoggingendIndex)
            $FindingDetails += ($ShowLoggingConfig | Select-String -Pattern "\sTrap logging.*" | Out-String).Trim()
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

Function Get-V220549 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220549
        STIG ID    : CISC-ND-001030
        Rule ID    : SV-220549r879746_rule
        CCI ID     : CCI-001889, CCI-001890, CCI-001893
        Rule Name  : SRG-APP-000373-NDM-000298
        Rule Title : The Cisco switch must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.
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
    $NTPServers = $ShowRunningConfig | Select-String -Pattern "^ntp server"
    IF ($NTPServers) {
        IF ($NTPServers.Count -gt "1") {
            $NTPServerPrimary = $NTPServers[0] -match "\d+\.\d+\.\d+\.\d+" | ForEach-Object {$Matches[0]}
            $NTPServerBackup = $NTPServers[1] -match "\d+\.\d+\.\d+\.\d+" | ForEach-Object {$Matches[0]}
            IF ($NTPServerPrimary -ne $NTPServerBackup) {
                $FindingDetails += ($NTPServers | Out-String).Trim()
                $Status = "NotAFinding"
            }
            Else {
                $FindingDetails += "Primary and Backup NTP server are set to the same IP Address" | Out-String
                $FindingDetails += "Redundant NTP Server not configured" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += ($NTPServers | Out-String).Trim()
                $Status = "Open"
            }
        }
        Else {
            $FindingDetails += "Redundant NTP Server not configured" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += ($NTPServers | Out-String).Trim()
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "NTP servers not configured" | Out-String
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

Function Get-V220552 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220552
        STIG ID    : CISC-ND-001130
        Rule ID    : SV-220552r879768_rule
        CCI ID     : CCI-001967
        Rule Name  : SRG-APP-000395-NDM-000310
        Rule Title : The Cisco switch must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
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
    $FindingDetails += "Requires information not provide by show tech or show running configuration file" | Out-String
    $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^snmp-server" | Out-String).Trim()
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V220553 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220553
        STIG ID    : CISC-ND-001140
        Rule ID    : SV-220553r879768_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000395-NDM-000310
        Rule Title : The Cisco switch must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.
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
    $FindingDetails += "Requires information not provide by show tech or show running configuration file" | Out-String
    $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^snmp-server" | Out-String).Trim()
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V220554 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220554
        STIG ID    : CISC-ND-001150
        Rule ID    : SV-220554r879768_rule
        CCI ID     : CCI-001967
        Rule Name  : SRG-APP-000395-NDM-000347
        Rule Title : The Cisco switch must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.
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
    $NTPInfo = $ShowRunningConfig | Select-String -Pattern "^ntp"
    IF ($NTPInfo) {
        IF ([BOOL]($NTPInfo | Where-Object {$_ -like "*md5*"})) {
            $FindingDetails += ($NTPInfo | Out-String).Trim()
            $Status = "NotAFinding"
        }
        Else {
            $FindingDetails += ($NTPInfo | Out-String).Trim()
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "NTP authenitcation is not configured" | Out-String
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

Function Get-V220555 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220555
        STIG ID    : CISC-ND-001200
        Rule ID    : SV-220555r879784_rule
        CCI ID     : CCI-001941, CCI-002890
        Rule Name  : SRG-APP-000411-NDM-000330
        Rule Title : The Cisco switch must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.
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
    $OpenFinding = $False
    $IPSSHServer = $ShowRunningConfig | Select-String -Pattern "^ip ssh version 2"

    IF ($IPSSHServer) {
        $IPSSHSrvrEncAlgorithm = $ShowRunningConfig | Select-String -Pattern "^ip ssh server algorithm mac(?: hmac-sha2-512 | hmac-sha2-256)"
        IF ($IPSSHSrvrEncAlgorithm) {
            $FindingDetails += ($IPSSHSrvrEncAlgorithm | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        Else {
            $OpenFinding = $True
            $FindingDetails += "SSH Server Algorithm is not configured per STIG check guidelines" | Out-String
            $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^ip ssh" | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $OpenFinding = $True
        $FindingDetails += "SSH server is not configured per STIG check guidelines" | Out-String
        $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^ip ssh" | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    IF ($OpenFinding) {
        $Status = "Open"
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

Function Get-V220556 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220556
        STIG ID    : CISC-ND-001210
        Rule ID    : SV-220556r879785_rule
        CCI ID     : CCI-003123
        Rule Name  : SRG-APP-000412-NDM-000331
        Rule Title : The Cisco switch must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
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
    $IPSSHSrvrEncAlgorithm = $ShowRunningConfig | Select-String -Pattern "^ip ssh server algorithm encryption(?: aes128-ctr| aes192-ctr| aes256-ctr)"
    IF (!$IPSSHSrvrEncAlgorithm) {
        IF ($null -eq ($ShowRunningConfig | Select-String -Pattern "^ip ssh server algorithm encryption")) {
            $FindingDetails += "ip ssh server algorithm encryption not configured" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^ip ssh server algorithm encryption" | Out-String).Trim()
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += ($IPSSHSrvrEncAlgorithm | Out-String).Trim()
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

Function Get-V220559 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220559
        STIG ID    : CISC-ND-001250
        Rule ID    : SV-220559r879870_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000499-NDM-000319
        Rule Title : The Cisco switch must be configured to generate log records when administrator privileges are deleted.
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V220560 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220560
        STIG ID    : CISC-ND-001260
        Rule ID    : SV-220560r879874_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000503-NDM-000320
        Rule Title : The Cisco switch must be configured to generate audit records when successful/unsuccessful logon attempts occur.
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
    $OpenFinding = $False
    $LoginFailure = $ShowRunningConfig | Select-String -Pattern "login on-failure log"
    $LoginSuccess = $ShowRunningConfig | Select-String -Pattern "login on-success log"
    IF (!$LoginFailure) {
        $LoginFailure = "login on-failure not configured" | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    IF (!$LoginSuccess) {
        $LoginSuccess = "login on-success not configured" | Out-String
        $OpenFinding = $True
    }
    $FindingDetails += ($LoginFailure | Out-String).Trim()
    $FindingDetails += "" | Out-String
    $FindingDetails += ($LoginSuccess | Out-String).Trim()
    IF ($OpenFinding) {
        $Status = "Open"
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

Function Get-V220561 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220561
        STIG ID    : CISC-ND-001270
        Rule ID    : SV-220561r879875_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-NDM-000321
        Rule Title : The Cisco switch must be configured to generate log records for privileged activities.
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V220566 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220566
        STIG ID    : CISC-ND-001410
        Rule ID    : SV-220566r916221_rule
        CCI ID     : CCI-000366, CCI-000537
        Rule Name  : SRG-APP-000516-NDM-000340
        Rule Title : The Cisco switch must be configured to support organizational requirements to conduct backups of the configuration when changes occur.
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
    $FindingDetails = @()
    $EventManager = $ShowRunningConfig | Select-String -Pattern "^event manager applet"
    IF ($EventManager) {
        ForEach ($BackupConfig in $EventManager) {
            $FindingDetails += ($BackupConfig | Out-String).Trim()
            $FindingDetails += (Get-Section $ShowRunningConfig $BackupConfig | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "Cisco router is not configured to conduct backups of the configuration when changes occur" | Out-String
        $Status = "Open"
    } #<--------------------------------------------------------- Might be able to dermine full status in the future, however I would need configuration files that are properly configured to test against.
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V220567 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220567
        STIG ID    : CISC-ND-001440
        Rule ID    : SV-220567r879887_rule
        CCI ID     : CCI-000366, CCI-001159
        Rule Name  : SRG-APP-000516-NDM-000344
        Rule Title : The Cisco switch must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.
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
    $OpenFinding = $False
    $Trustpoint = $ShowRunningConfig | Select-String -Pattern "^crypto pki trustpoint"
    IF ($Trustpoint) {
        ForEach ($Point in $Trustpoint) {
            $Enrollment = Get-Section $ShowRunningConfig $Point.ToString() | Select-String -Pattern "enrollment"
            IF ($Enrollment) {
                If ($Enrollment -like "*url*") {
                    $FindingDetails += ($Point | Out-String).Trim() + " - ensure url is from a trusted CA." | Out-String
                    $FindingDetails += ($Point | Out-String).Trim()
                    $FindingDetails += " " + ($Enrollment | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
                Else {
                    $OpenFinding = $True
                    $FindingDetails += ($Point | Out-String).Trim() + " is not configured for url enrollment" | Out-String
                    $FindingDetails += ($Point | Out-String).Trim()
                    $FindingDetails += " " + ($Enrollment | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
            }
            Else {
                $OpenFinding = $True
                $FindingDetails += "There is no enrollment configuration configured for: " + ($Point | Out-String).Trim()
                $FindingDetails += ($Point | Out-String).Trim()
                $FindingDetails += (Get-Section $ShowRunningConfig $Point.ToString() | Out-String).Trim()
            }
        }
    }
    Else {
        $FindingDetails += "PKI trust point have not been configured" | Out-String
    }
    IF ($OpenFinding) {
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

Function Get-V220568 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220568
        STIG ID    : CISC-ND-001450
        Rule ID    : SV-220568r916114_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-APP-000516-NDM-000350
        Rule Title : The Cisco switch must be configured to send log data to at least two central log servers for the purpose of forwarding alerts to the administrators and the information system security officer (ISSO).
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
    $OpenFinding = $False
    $LoggingHost = $ShowRunningConfig | Select-String -Pattern "^logging host"
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $RouterIPs = @()
    ForEach ($Interface in $Interfaces) {
        $IP = (((Get-Section $ShowRunningConfig $Interface | Select-String -Pattern "ip address" | Out-String).Trim()).Replace("ip address ", "")).Split([char[]]"")[0]
        IF ($IP -match "\d+\.\d+\.\d+\.\d+") {
            $RouterIPs += $IP
        }
    }
    IF ($LoggingHost) {
        foreach ($SysLogServer in $LoggingHost) {
            $SysLogServer = (($SysLogServer | Out-String).Trim()).Replace("logging host ", "")
            IF ($SysLogServer -in $RouterIPs) {
                $OpenFinding = $True
                $FindingDetails += "The switch is not configured to off-load log records onto a different system." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        $FindingDetails += ($LoggingHost | Out-String).Trim()
    }
    Else {
        $FindingDetails += "The switch is not configured to send log data to the syslog server, this is a finding." | Out-String
        $OpenFinding = $True
    }

    If ($LoggingHost -and ($LoggingHost | Measure-Object).Count -lt 2) {
        $OpenFinding = $True
        $FindingDetails += "" | Out-String
        $FindingDetails += "A minimum of two syslog servers are required." | Out-String
    }

    IF ($OpenFinding) {
        $Status = "Open"
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

Function Get-V220569 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220569
        STIG ID    : CISC-ND-001470
        Rule ID    : SV-220569r879887_rule
        CCI ID     : CCI-000366, CCI-002605
        Rule Name  : SRG-APP-000516-NDM-000351
        Rule Title : The Cisco switch must be running an IOS release that is currently supported by Cisco Systems.
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
    $FindingDetails += "Check with vendor for support status of the device" | Out-String
    $FindingDetails += "Device Info:" | Out-String
    $FindingDetails += ($DeviceInfo | Out-String).Trim()
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBFV9GL2GRVfWRp
# lEZpQJ4oS7zRvDzqTIwnRcMQSwC7gaCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBMUv6JOGFkvH5WQZT/S93P59vU6m3p
# Jyd+4nb4ScZbVTANBgkqhkiG9w0BAQEFAASCAQAiEblWHIycwJzW0JkqW0bv+vbl
# 4GNE9dKjFOvZrTco6as5256AWixE6ri+m9barooqQljOaiQ1CoBH13iBmASf12d9
# YNcphsdtDkM/PCiunyfcbmwDKV/Jqyt0QzKfOeO6coUxT7+gfMfPSx/PJbu4k4Xe
# 0CaGf4loF5b9RouHhDp1GE0x3f2c0dMOvS+tOtpwBNGhqQfCYQrkwsqgsi0zx+t6
# 7c+YH+N79GFKpJ1P3wWSfj33SOTFEWVq9O/mI1GBVVdz9GjERBiBO2GwgoVDALjg
# PebCb6T4z+WHf9SN6rlZ2iCkOQaThfIwdM6Oj2KBfexXDmXB9/hQzL+n7jFm
# SIG # End signature block
