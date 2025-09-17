##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS XE Switch L2S
# Version:  V2R3
# Class:    UNCLASSIFIED
# Updated:  4/25/2023
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V220649 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220649
        STIG ID    : CISC-L2-000020
        Rule ID    : SV-220649r863283_rule
        CCI ID     : CCI-000778, CCI-001958
        Rule Name  : SRG-NET-000148-L2S-000015
        Rule Title : The Cisco switch must uniquely identify and authenticate all network-connected endpoint devices before establishing any connection.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $CompliantInt = @()
    $NonCompliantInt = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        #This section checks Step 2 of STIG check
        $Radius = $ShowRunningConfig | Select-String -Pattern "^aaa group server radius .*"
        $FindingDetails += "Radius Server" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        IF ($Radius) {
            $RadiusServer = ($Radius | Out-String).Trim().Split([char[]]"")[4]
        }
        Else {
            $OpenFinding = $True
            $RadiusServer = "Not Configured"
        }
        $FindingDetails += "$RadiusServer" | Out-String
        $FindingDetails += "" | Out-String

        $dot1xAuthentication = $ShowRunningConfig | Select-String -Pattern "^aaa authentication dot1x default group"
        IF ($dot1xAuthentication) {
            $dot1xAuthenticationServer = ($dot1xAuthentication | Out-String).Trim().Split([char[]]"")[5]
        }
        Else {
            $OpenFinding = $True
            $dot1xAuthenticationServer = "Not Configured"
        }
        $FindingDetails += "802.1x default group" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += "$dot1xAuthenticationServer" | Out-String
        $FindingDetails += "" | Out-String

        $dot1xSysAuthCtrl = $ShowRunningConfig | Select-String -Pattern "^dot1x system-auth-control"
        IF (!$dot1xSysAuthCtrl) {
            $OpenFinding = $True
            $dot1xSysAuthCtrl = "Not Configured"
        }
        $FindingDetails += "dot1x system-auth-control" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += "$dot1xSysAuthCtrl" | Out-String
        $FindingDetails += "" | Out-String

        IF (!($RadiusServer -eq $dot1xAuthenticationServer)) {
            $OpenFinding = $True
        }

        #This section checks Step 1
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -contains "dot1x pae authenticator" -or $InterfaceConfig -contains "mab" -AND ($InterfaceConfig | Where-Object {$_ -like "authentication host-mode*"} | Out-String).Trim().Split([char[]]"")[2] -ne "multi-host") {
                $CompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "mab") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "mab"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "switchport mode access") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "switchport access vlan*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticator"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "authentication port-control*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "authentication port-control*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "authentication host-mode*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "authentication host-mode*"} | Out-String).Trim()
                }
                $CompliantInt += " "
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "mab") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "mab"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "switchport mode access") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "switchport access vlan*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticator"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "authentication port-control*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "authentication port-control*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "authentication host-mode*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "authentication host-mode*"} | Out-String).Trim()
                }
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Review switch configuration below." | Out-String
            $FindingDetails += "If 802.1x authentication or MAB is not configured on all access switch ports connecting to LAN outlets or devices not located in the telecom room, wiring closets, or equipment rooms, this is a finding." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF (!($OpenFinding)) {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220655 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220655
        STIG ID    : CISC-L2-000090
        Rule ID    : SV-220655r863267_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000021
        Rule Title : The Cisco switch must have Root Guard enabled on all switch ports connecting to access layer switches.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $CompliantInt = @()
    $NonCompliantInt = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -like "switchport*") {
            IF ($InterfaceConfig -contains "spanning-tree guard root") {
                $CompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "switchport*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "spanning-tree guard root") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "spanning-tree guard root"} | Out-String).Trim()
                }
                $CompliantInt += " "
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += "spanning-tree guard root is not configured"
                $NonCompliantInt += ""
            }
        }
    }

    IF ($CompliantInt) {
        $FindingDetails += "Compliant Interfaces" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $CompliantInt | Out-String
        $FindingDetails += "" | Out-String
    }

    IF ($NonCompliantInt) {
        $FindingDetails += "Review the switch topology as well as the switch configuration below to verify that Root Guard is enabled on all switch ports connecting to access layer switches." | Out-String
        $FindingDetails += "Interfaces without spanning-tree guard root configured" | Out-String
        $FindingDetails += "-------------------------------------------------------" | Out-String
        $FindingDetails += $NonCompliantInt | Out-String
        $FindingDetails += "" | Out-String
    }

    IF (!$OpenFinding) {
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

Function Get-V220656 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220656
        STIG ID    : CISC-L2-000100
        Rule ID    : SV-220656r856278_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000022
        Rule Title : The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $CompliantInt = @()
    $NonCompliantInt = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -contains "spanning-tree bpduguard enable") {
                $CompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "spanning-tree bpduguard enable") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "spanning-tree bpduguard enable"} | Out-String).Trim()
                }
                $CompliantInt += " "
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += "spanning-tree bpduguard enable is not configured"
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Review the switch configuration to verify that BPDU Guard is enabled on all user-facing or untrusted access switch ports:" | Out-String
            $FindingDetails += "Interfaces without BDPU guard enabled" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF (!($OpenFinding)) {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220657 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220657
        STIG ID    : CISC-L2-000110
        Rule ID    : SV-220657r856279_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000023
        Rule Title : The Cisco switch must have STP Loop Guard enabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $LoopGuard = $ShowRunningConfig | Select-String -Pattern "^spanning-tree loopguard default"
    $FindingDetails += "Spanning-tree loopguard" | Out-String
    $FindingDetails += "-----------------------------" | Out-String
    IF ($LoopGuard) {
        $FindingDetails += ($LoopGuard | Out-String).Trim()
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "spanning-tree loopguard not enabled" | Out-String
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

Function Get-V220658 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220658
        STIG ID    : CISC-L2-000120
        Rule ID    : SV-220658r856280_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000024
        Rule Title : The Cisco switch must have Unknown Unicast Flood Blocking (UUFB) enabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $CompliantInt = @()
    $NonCompliantInt = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -contains "switchport block unicast") {
                $CompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "switchport block unicast") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport block unicast"} | Out-String).Trim()
                }
                $CompliantInt += " "
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += "switchport block unicast is not configured"
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Non-Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220659 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220659
        STIG ID    : CISC-L2-000130
        Rule ID    : SV-220659r856281_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000025
        Rule Title : The Cisco switch must have DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $NonCompliantInt = @()
    $Non8021xInterfaces = @()
    $ActiveAccessSwitchPorts = @()
    $NAInterfaces = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -contains "dot1x pae authenticator")) {
                $Non8021xInterfaces += $Interface
            }

            IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                $NAInterfaces += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "switchport mode access") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "switchport access vlan*") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticator"})
                }
                $NAInterfaces += ""
            }
        }

        IF ($Non8021xInterfaces) {
            $DHCPSnooping = $ShowRunningConfig | Select-String -Pattern "^ip dhcp snooping`$"
            IF ($DHCPSnooping) {
                $DHCPSnoopingVLANs = ($ShowRunningConfig | Select-String -Pattern "^ip dhcp snooping vlan .*" | Out-String).Trim().Split([char[]]"").Split(",") | Select-Object -Skip 4
                IF ($DHCPSnoopingVLANs) {
                    $FindingDetails += "DHCP Snooping Vlans" | Out-String
                    $FindingDetails += "--------------------" | Out-String
                    $FindingDetails += $DHCPSnoopingVLANs -join "`n" | Out-String
                    $FindingDetails += "" | Out-String

                    $VLANs = @()
                    ForEach ($Vlan in $DHCPSnoopingVLANs) {
                        IF ($Vlan -like "*-*") {
                            $DashIndex = $Vlan.IndexOf("-")
                            $StartInt = $Vlan.Substring(0, $DashIndex)
                            $EndInt = $Vlan.Substring($DashIndex + 1)
                            $VLANs += $StartInt..$EndInt
                        }
                        Else {
                            $VLANs += $Vlan
                        }
                    }
                    ForEach ($Interface in $Non8021xInterfaces) {
                        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                        IF ($InterfaceConfig -like "switchport access vlan*") {
                            IF (($InterfaceConfig -like "switchport access vlan*" | Out-String).Trim().Split([char[]]"")[3] -notin $VLANs) {
                                $OpenFinding = $True
                                $NonCompliantInt += ($Interface | Out-String).Trim()
                                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                                $NonCompliantInt += ""
                            }
                            Else {
                                $CompliantInt += ($Interface | Out-String).Trim()
                                IF ($InterfaceConfig -like "description*") {
                                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                                }
                                IF ($InterfaceConfig -contains "switchport mode access") {
                                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
                                }
                                IF ($InterfaceConfig -like "switchport access vlan*") {
                                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
                                }
                                IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticat"})
                                }
                            }
                        }
                        Else {
                            $OpenFinding = $True
                            $NonCompliantInt += ($Interface | Out-String).Trim()
                            $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                            $NonCompliantInt += ""
                            $NonCompliantInt += "switchport access vlan not configured"
                            $NonCompliantInt += "$Interface will default to VLAN 1"
                        }
                    }

                    IF ($CompliantInt) {
                        $FindingDetails += "Compliant Interfaces" | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += $CompliantInt -join "`n" | Out-String
                        $FindingDetails += "" | Out-String
                    }

                    IF ($NonCompliantInt) {
                        $FindingDetails += "Review the switch configuration below and verify that interfaces do not contain user VLANs and make finding determinitation based on STIG check guidance:" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Interfaces" | Out-String
                        $FindingDetails += "---------------" | Out-String
                        $FindingDetails += $NonCompliantInt -join "`n" | Out-String
                    }

                    IF (!($OpenFinding)) {
                        $Status = "NotAFinding"
                    }
                }
                Else {
                    $FindingDetails += "DHCP Snooping Vlans Not Configured" | Out-String
                    $FindingDetails += "" | Out-String
                    ForEach ($Interface in $Non8021xInterfaces) {
                        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                        $NonCompliantInt += ($Interface | Out-String).Trim()
                        $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                        $NonCompliantInt += ""
                    }

                    $FindingDetails += "Review the switch configuration below and verify that interfaces do not contain user VLANs and make finding determinitation based on STIG check guidance:" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Interfaces" | Out-String
                    $FindingDetails += "---------------" | Out-String
                    $FindingDetails += $NonCompliantInt -join "`n" | Out-String
                }
            }
            Else {
                ForEach ($Interface in $Non8021xInterfaces) {
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                    IF ($InterfaceConfig -like "description*") {
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -contains "switchport mode access") {
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -like "switchport access vlan*") {
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticator"})
                    }
                    $NonCompliantInt += ""
                }

                $FindingDetails += "IP DHCP Snooping not configured" | Out-String
                $FindingDetails += "Review the switch configuration below and verify that interfaces do not contain user VLANs and make finding determinitation based on STIG check guidance:" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Interfaces" | Out-String
                $FindingDetails += "---------------" | Out-String
                $FindingDetails += $NonCompliantInt -join "`n" | Out-String
            }
        }
        Else {
            $FindingDetails += "All active switchport mode access VLANs are managed by 802.1x" | Out-String
            $FindingDetails += "For VLANs managed via 802.1x, this check is N/A." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Interfaces" | Out-String
            $FindingDetails += "-----------" | Out-String
            $FindingDetails += $NAInterfaces -join "`n" | Out-String
            $Status = "Not_Applicable"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220660 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220660
        STIG ID    : CISC-L2-000140
        Rule ID    : SV-220660r863269_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000026
        Rule Title : The Cisco switch must have IP Source Guard enabled on all user-facing or untrusted access switch ports.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $CompliantInt = @()
    $NonCompliantInt = @()
    $NAInterfaces = @()
    $Non8021xInterfaces = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -contains "dot1x pae authenticator")) {
                $Non8021xInterfaces += $Interface
            }

            IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                $NAInterfaces += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticator"} | Out-String).Trim()
                IF ($InterfaceConfig -contains "ip verify source") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "ip verify source"} | Out-String).Trim()
                }
                Else {
                    $NAInterfaces += " ip verify source is not configured"
                }
                $NAInterfaces += " "
            }
        }

        IF ($Non8021xInterfaces) {
            ForEach ($Interface in $Non8021xInterfaces) {
                $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                IF ($InterfaceConfig -contains "ip verify source") {
                    $CompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -contains "ip verify source") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "ip verify source"} | Out-String).Trim()
                    }
                    $CompliantInt += " "
                }
                Else {
                    $OpenFinding = $True
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                    $NonCompliantInt += "ip verify source is not configured"
                    $NonCompliantInt += ""
                }
            }

            IF ($CompliantInt) {
                $FindingDetails += "Compliant Interfaces" | Out-String
                $FindingDetails += "--------------------------" | Out-String
                $FindingDetails += $CompliantInt | Out-String
                $FindingDetails += "" | Out-String
            }

            IF ($NonCompliantInt) {
                $FindingDetails += "Review the switch configuration to verify that IP Source Guard is enabled on all user-facing or untrusted access switch ports:" | Out-String
                $FindingDetails += "Interfaces without IP Source Guard Enabled" | Out-String
                $FindingDetails += "------------------------------------------------" | Out-String
                $FindingDetails += $NonCompliantInt | Out-String
                $FindingDetails += "" | Out-String
            }

            IF (!($OpenFinding)) {
                $Status = "NotAFinding"
            }
        }
        Else {
            $FindingDetails += "All active switchport mode access VLANs are managed by 802.1x" | Out-String
            $FindingDetails += "For VLANs managed via 802.1x, this check is N/A." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Interfaces" | Out-String
            $FindingDetails += "-----------" | Out-String
            $FindingDetails += $NAInterfaces -join "`n" | Out-String
            $Status = "Not_Applicable"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220661 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220661
        STIG ID    : CISC-L2-000150
        Rule ID    : SV-220661r856283_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000027
        Rule Title : The Cisco switch must have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $NonCompliantInt = @()
    $Non8021xInterfaces = @()
    $NAInterfaces = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -contains "dot1x pae authenticator")) {
                $Non8021xInterfaces += $Interface
            }

            IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                $NAInterfaces += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "switchport mode access") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "switchport access vlan*") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticator"})
                }
                $NAInterfaces += ""
            }
        }

        IF ($Non8021xInterfaces) {
            $ARPInspectionVlans = ($ShowRunningConfig | Select-String -Pattern "^ip arp inspection vlan .*" | Out-String).Trim().Split([char[]]"").Split(",") | Select-Object -Skip 4
            IF ($ARPInspectionVlans) {
                $FindingDetails += "ARP Inspection Vlans" | Out-String
                $FindingDetails += "--------------------" | Out-String
                $FindingDetails += $ARPInspectionVlans -join "`n" | Out-String
                $FindingDetails += "" | Out-String

                $VLANs = @()
                ForEach ($Vlan in $ARPInspectionVlans) {
                    IF ($Vlan -like "*-*") {
                        $DashIndex = $Vlan.IndexOf("-")
                        $StartInt = $Vlan.Substring(0, $DashIndex)
                        $EndInt = $Vlan.Substring($DashIndex + 1)
                        $VLANs += $StartInt..$EndInt
                    }
                    Else {
                        $VLANs += $Vlan
                    }
                }

                ForEach ($Interface in $Non8021xInterfaces) {
                    $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                    IF ($InterfaceConfig -like "switchport access vlan*") {
                        IF (($InterfaceConfig -like "switchport access vlan*" | Out-String).Trim().Split([char[]]"")[3] -notin $VLANs) {
                            $OpenFinding = $True
                            $NonCompliantInt += ($Interface | Out-String).Trim()
                            $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                            $NonCompliantInt += ""
                        }
                        Else {
                            $CompliantInt += ($Interface | Out-String).Trim()
                            IF ($InterfaceConfig -like "description*") {
                                $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                            }
                            IF ($InterfaceConfig -contains "switchport mode access") {
                                $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
                            }
                            IF ($InterfaceConfig -like "switchport access vlan*") {
                                $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
                            }
                            IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                                $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticat"})
                            }
                            $CompliantInt += ""
                        }
                    }
                    Else {
                        $OpenFinding = $True
                        $NonCompliantInt += ($Interface | Out-String).Trim()
                        $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                        $NonCompliantInt += ""
                        $NonCompliantInt += "switchport access vlan not configured"
                        $NonCompliantInt += "$Interface will default to VLAN 1"
                    }
                }

                IF ($CompliantInt) {
                    $FindingDetails += "Compliant Interfaces" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += $CompliantInt -join "`n" | Out-String
                    $FindingDetails += "" | Out-String
                }

                IF ($NonCompliantInt) {
                    $FindingDetails += "Review the switch configuration below and verify that interfaces do not contain user VLANs and make finding determinitation based on STIG check guidance:" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Interfaces" | Out-String
                    $FindingDetails += "---------------" | Out-String
                    $FindingDetails += $NonCompliantInt -join "`n" | Out-String
                }

                IF (!($OpenFinding)) {
                    $Status = "NotAFinding"
                }
            }
            Else {
                $FindingDetails += "ARP Inspection Vlans Not Configured" | Out-String
                $FindingDetails += "" | Out-String
                ForEach ($Interface in $Non8021xInterfaces) {
                    $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                    $NonCompliantInt += ""
                }

                $FindingDetails += "Review the switch configuration below and verify that interfaces do not contain user VLANs and make finding determinitation based on STIG check guidance:" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Interfaces" | Out-String
                $FindingDetails += "---------------" | Out-String
                $FindingDetails += $NonCompliantInt -join "`n" | Out-String
            }
        }
        Else {
            $FindingDetails += "All active access switchports VLANs are managed by 802.1x" | Out-String
            $FindingDetails += "For VLANs managed via 802.1x, this check is N/A." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Interfaces" | Out-String
            $FindingDetails += "-----------" | Out-String
            $FindingDetails += $NAInterfaces -join "`n" | Out-String
            $Status = "Not_Applicable"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220662 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220662
        STIG ID    : CISC-L2-000160
        Rule ID    : SV-220662r648766_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000001
        Rule Title : The Cisco switch must have Storm Control configured on all host-facing switchports.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $CompliantInt = @()
    $NonCompliantInt = @()
    $GigabitRange = 10..1000 #<----------------------Range is in Megabits
    $TenGigabitRange = 10..10000 #<----------------------Range is in Megabits

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        IF ($Interface -like "*Gigabit*" -or $Interface -like "*tengigabitethernet") {
            IF ($Interface -like "*Gigabit*") {
                $Range = $GigabitRange
            }
            Else {
                $Range = $TenGigabitRange
            }
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -contains "shutdown")) {
                IF ($InterfaceConfig -like "storm-control unicast level bps*" -and $InterfaceConfig -like "storm-control broadcast level bps*") {
                    $StormCtrlUnicast = ($InterfaceConfig | Where-Object {$_ -like "storm-control unicast level bps*"} | Out-String).Trim().Split([char[]]"")[4]
                    $StormCtrlbroadcast = ($InterfaceConfig | Where-Object {$_ -like "storm-control broadcast level bps*"} | Out-String).Trim().Split([char[]]"")[4]

                    IF ($StormCtrlUnicast -is [INT]) {
                        $StormCtrlUnicast = $StormCtrlUnicast / 1000000
                    }
                    IF ($StormCtrlUnicast -like "*k") {
                        $StormCtrlUnicast = $StormCtrlUnicast.Replace("k", "") / 1000
                    }
                    IF ($StormCtrlUnicast -like "*m") {
                        $StormCtrlUnicast = $StormCtrlUnicast.Replace("m", "")
                    }
                    IF ($StormCtrlUnicast -like "*g") {
                        $StormCtrlUnicast = [DOUBLE]$StormCtrlUnicast.Replace("g", "") * 1000
                    }

                    IF ($StormCtrlbroadcast -is [INT]) {
                        $StormCtrlbroadcast = $StormCtrlbroadcast / 1000000
                    }
                    IF ($StormCtrlbroadcast -like "*k") {
                        $StormCtrlbroadcast = $StormCtrlbroadcast.Replace("k", "") / 1000
                    }
                    IF ($StormCtrlbroadcast -like "*m") {
                        $StormCtrlbroadcast = $StormCtrlbroadcast.Replace("m", "")
                    }
                    IF ($StormCtrlbroadcast -like "*g") {
                        $StormCtrlbroadcast = [DOUBLE]$StormCtrlbroadcast.Replace("g", "") * 1000
                    }

                    IF ($StormCtrlUnicast -in $Range) {
                        $CompliantInt += ($Interface | Out-String).Trim()
                        IF ($InterfaceConfig -like "description*") {
                            $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                        }
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control unicast level bps*"} | Out-String).Trim()
                        $CompliantInt += ""
                    }
                    Else {
                        $OpenFinding = $True
                        $NonCompliantInt += ($Interface | Out-String).Trim()
                        IF ($InterfaceConfig -like "description*") {
                            $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                        }
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control unicast level bps*"} | Out-String).Trim() + " - NON-COMPLIANT"
                        $NonCompliantInt += ""
                    }

                    IF ($StormCtrlbroadcast -in $Range) {
                        $CompliantInt += ($Interface | Out-String).Trim()
                        IF ($InterfaceConfig -like "description*") {
                            $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                        }
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control broadcast level bps*"} | Out-String).Trim()
                        $FindingDetails += "" | Out-String
                        $CompliantInt += ""
                    }
                    Else {
                        $OpenFinding = $True
                        $NonCompliantInt += ($Interface | Out-String).Trim()
                        IF ($InterfaceConfig -like "description*") {
                            $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                        }
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control broadcast level bps*"} | Out-String).Trim() + " - NON-COMPLIANT"
                        $NonCompliantInt += ""
                    }
                }
                Else {
                    $OpenFinding = $True
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    $StormCtrlUnicast = ($InterfaceConfig | Where-Object {$_ -like "storm-control unicast level bps*"} | Out-String).Trim().Split([char[]]"")[4]
                    $StormCtrlbroadcast = ($InterfaceConfig | Where-Object {$_ -like "storm-control broadcast level bps*"} | Out-String).Trim().Split([char[]]"")[4]

                    IF ($StormCtrlUnicast) {
                        IF ($StormCtrlUnicast -eq "62000000" -or $StormCtrlUnicast -eq "62000k" -or $StormCtrlUnicast -eq "62m" -or $StormCtrlUnicast -eq "0.062g") {
                            $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control unicast level bps*"} | Out-String).Trim()
                        }
                        Else {
                            $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control unicast level bps*"} | Out-String).Trim() + " - NON-COMPLIANT"
                        }
                    }
                    Else {
                        $NonCompliantInt += "storm-control unicast level NOT CONFIGURED"
                    }

                    IF ($StormCtrlbroadcast) {
                        IF ($StormCtrlbroadcast -eq "20000000" -or $StormCtrlbroadcast -eq "20000k" -or $StormCtrlbroadcast -eq "20m" -or $StormCtrlbroadcast -eq "0.02g") {
                            $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control broadcast level bps*"} | Out-String).Trim()
                            $NonCompliantInt += ""
                        }
                        Else {
                            $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control broadcast level bps*"} | Out-String).Trim() + " - NON-COMPLIANT"
                            $NonCompliantInt += ""
                        }
                    }
                    Else {
                        $NonCompliantInt += "storm-control broadcast level NOT CONFIGURED"
                        $NonCompliantInt += ""
                    }
                }
            }
        }
        Else {
            $OpenFinding = $True
            $NonCompliantInt += ($Interface | Out-String).Trim()
            IF ($InterfaceConfig -like "description*") {
                $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
            }
            $NonCompliantInt += "Interface is not supported"
            $NonCompliantInt += ""
        }
    }

    IF ($CompliantInt) {
        $FindingDetails += "Compliant Interfaces" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $CompliantInt -join "`n" | Out-String
        $FindingDetails += "" | Out-String
    }

    IF ($NonCompliantInt) {
        $FindingDetails += "Review the switch configuration below and verify that interfaces are not host facing, make finding determinitation based on STIG check guidance:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Interfaces" | Out-String
        $FindingDetails += "---------------" | Out-String
        $FindingDetails += $NonCompliantInt -join "`n" | Out-String
    }

    IF (!($OpenFinding)) {
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

Function Get-V220663 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220663
        STIG ID    : CISC-L2-000170
        Rule ID    : SV-220663r802438_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000002
        Rule Title : The Cisco switch must have IGMP or MLD Snooping configured on all VLANs.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $NonCompliantInt = @()
    $Non8021xInterfaces = @()
    $NAInterfaces = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -contains "dot1x pae authenticator")) {
                $Non8021xInterfaces += $Interface
            }

            IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                $NAInterfaces += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "switchport mode access") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "switchport access vlan*") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                    $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticator"})
                }
                $NAInterfaces += ""
            }
        }

        IF ($Non8021xInterfaces) {
            $NoIGMPSnooping = ($ShowRunningConfig | Select-String -Pattern "^no ip igmp snooping" | Out-String).Trim()
            IF ($NoIGMPSnooping) {
                $FindingDetails += "IGMP Snooping" | Out-String
                $FindingDetails += "---------------" | Out-String
                $FindingDetails += ($NoIGMPSnooping | Out-String).Trim()
                $FindingDetails += "" | Out-String
                ForEach ($Interface in $Non8021xInterfaces) {
                    $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    $NonCompliantInt += "" | Out-String
                    $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                    $NonCompliantInt += "" | Out-String
                }

                $FindingDetails += "Review the switch configuration below and verify that interfaces are not receiving IPv4 and IPv6 multicast traffic; make finding determinitation based on STIG check guidance:" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Interfaces" | Out-String
                $FindingDetails += "---------------" | Out-String
                $FindingDetails += $NonCompliantInt -join "`n" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                ForEach ($Interface in $Non8021xInterfaces) {
                    $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                    IF ($InterfaceConfig -like "no ip igmp snooping vlan*") {
                        $OpenFinding = $True
                        $NonCompliantInt += ($Interface | Out-String).Trim()
                        $NonCompliantInt += "" | Out-String
                        $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                        $NonCompliantInt += "" | Out-String
                    }
                    Else {
                        $CompliantInt += ($Interface | Out-String).Trim()
                        $CompliantInt += "" | Out-String
                        $CompliantInt += ($InterfaceConfig | Out-String).Trim()
                        $CompliantInt += "" | Out-String
                    }
                }

                IF ($CompliantInt) {
                    $FindingDetails += "Compliant Interfaces" | Out-String
                    $FindingDetails += "--------------------------" | Out-String
                    $FindingDetails += $CompliantInt -join "`n" | Out-String
                    $FindingDetails += "" | Out-String
                }

                IF ($NonCompliantInt) {
                    $FindingDetails += "Review the switch configuration below and verify that interfaces do not contain user VLANs and make finding determinitation based on STIG check guidance:" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Interfaces" | Out-String
                    $FindingDetails += "---------------" | Out-String
                    $FindingDetails += $NonCompliantInt -join "`n" | Out-String
                }

                IF (!($OpenFinding)) {
                    $Status = "NotAFinding"
                }
            }
        }
        Else {
            $FindingDetails += "All active switchport mode access VLANs are managed by 802.1x" | Out-String
            $FindingDetails += "For VLANs managed via 802.1x, this check is N/A." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Interfaces" | Out-String
            $FindingDetails += "-----------" | Out-String
            $FindingDetails += $NAInterfaces -join "`n" | Out-String
            $Status = "Not_Applicable"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220664 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220664
        STIG ID    : CISC-L2-000180
        Rule ID    : SV-220664r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000003
        Rule Title : The Cisco switch must implement Rapid STP where VLANs span multiple switches with redundant links.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails += "Spanning Tree Protocol" | Out-String
    $FindingDetails += "-----------------------" | Out-String
    $SpanningTreeMode = $ShowRunningConfig | Select-String -Pattern "^spanning-tree mode (?:rapid-pvst|mst)"
    IF ($SpanningTreeMode) {
        $FindingDetails += ($SpanningTreeMode | Out-String).Trim()
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Spanning Tree Protocol not configured" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Review switch configuration to determine if STP is required and make finding determination based on STIG check guidance." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V220665 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220665
        STIG ID    : CISC-L2-000190
        Rule ID    : SV-220665r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000004
        Rule Title : The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $GlobalUDLD = $ShowRunningConfig | Select-String -Pattern "^udld enable"
    IF ($GlobalUDLD) {
        $FindingDetails += "Unidirection Link Detection (UDLD)" | Out-String
        $FindingDetails += "----------------------------------" | Out-String
        $FindingDetails += "$GlobalUDLD" | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $CompliantInt = @()
        $NonCompliantInt = @()
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -contains "shutdown")) {
                IF ($InterfaceConfig -like "udld port*") {
                    $CompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -like "udld port*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "udld port*"} | Out-String).Trim()
                    }
                    $CompliantInt += " "
                }
                Else {
                    $OpenFinding = $True
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                    $NonCompliantInt += " Unidirectional Link Detection is not configured"
                    $NonCompliantInt += ""
                }
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Review interfaces below and ensure that none of the interfaces have fiber optic interconnections with neighbors; make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "UDLD Disabled Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF (!($OpenFinding)) {
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

Function Get-V220666 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220666
        STIG ID    : CISC-L2-000200
        Rule ID    : SV-220666r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000005
        Rule Title : The Cisco switch must have all trunk links enabled statically.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $CompliantInt = @()
    $NonCompliantInt = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    $ActiveTrunkSwitchPorts = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport mode trunk") {
            $ActiveTrunkSwitchPorts += $Interface
        }
    }

    IF ($ActiveTrunkSwitchPorts) {
        ForEach ($Interface in $ActiveTrunkSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -contains "switchport nonegotiate") {
                $CompliantInt += ($Interface | Out-String).Trim()
                $CompliantInt += " " + ($InterfaceConfig | Select-String -Pattern "^switchport mode trunk" | Out-String).Trim()
                $CompliantInt += " " + ($InterfaceConfig | Select-String -Pattern "^switchport nonegotiate" | Out-String).Trim()
                $CompliantInt += ""
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Non-Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active trunk switchports configured on this switch" | Out-String
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

Function Get-V220667 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220667
        STIG ID    : CISC-L2-000210
        Rule ID    : SV-220667r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000007
        Rule Title : The Cisco switch must have all disabled switch ports assigned to an unused VLAN.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $Non8021xInterfaces = @()
    $NAInterfaces = @()
    $AllTrunkVLANs = @()
    $InterfaceResults = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    $VlanStartString = "^VLAN\s+Name\s+Status\s+Ports"
    $VlanEndString = "^VLAN\s+Type\s+SAID\s+MTU\s+Parent RingNo\s+BridgeNo\s+Stp\s+BrdgMode\s+Trans1\s+Trans2"
    $VlanStartIndex = ($ShowTech | Select-String $VlanStartString).LineNumber
    $VlanEndIndex = ($ShowTech | Select-String $VlanEndString).LineNumber
    $ShowVlan = $ShowTech | Select-Object -Index (($VlanStartIndex + 1)..($VlanEndIndex - 3))
    $ShowVlanPSO = New-Object System.Collections.Generic.List[System.Object]
    $TrunkstartSTR = "^Port\s+Vlans\sallowed\son\strunk"
    $TrunkstartIndex = ($ShowTech | Select-String $TrunkstartSTR).LineNumber
    IF ($TrunkstartIndex) {
        $TrunkEndIndex = $TrunkstartIndex
        DO {
            $TrunkEndIndex++
        }Until($ShowTech[$TrunkEndIndex] -match "")
        $ShowInterfacesTrunk = $ShowTech | Select-Object -Index (($TrunkstartIndex - 1)..($TrunkEndIndex))

        ForEach ($Trunk in ($ShowInterfacesTrunk | Select-Object -Skip 1)) {
            if ($Trunk) {
                $Interface = (-split $Trunk)[0]
                $TrunkVlans = (-split $Trunk)[1].Split(",")

                ForEach ($TVlan in $TrunkVlans) {
                    IF ($TVlan -like "*-*") {
                        $DashIndex = $TVlan.IndexOf("-")
                        $StartInt = $TVlan.Substring(0, $DashIndex)
                        $EndInt = $TVlan.Substring($DashIndex + 1)
                        $AllTrunkVLANs += $StartInt..$EndInt
                    }
                    Else {
                        $AllTrunkVLANs += $TVlan
                    }
                }
            }

        }
    }

    ForEach ($Vlan in $ShowVLan) {
        IF (!(($Vlan -split '\s{2,}')[0])) {
            $Ports = $ShowVlanPSO[$ShowVlanPSO.Count - 1].Ports
            $AdditionalPorts = ($Vlan -split '\s{2,}')[1]
            $UpdatedPorts = $Ports + $AdditionalPorts
            $ShowVlanPSO[$ShowVlanPSO.Count - 1].Ports = $UpdatedPorts
        }
        Else {
            $NewVlanObj = [PSCustomObject]@{
                VLAN   = ($Vlan -split '\s+')[0]
                Name   = (($Vlan -split '\s+', 2)[1] -split '(?:act/lshut|sus/lshut|act/ishut|sus/ishut|active|suspend|act/unsup)')[0].Trim()
                Status = (($Vlan | Select-String '(?:act/lshut|sus/lshut|act/ishut|sus/ishut|active|suspend|act/unsup)').Matches).Value
                Ports  = ($Vlan -split '(?:act/lshut|sus/lshut|act/ishut|sus/ishut|active|suspend|act/unsup)')[1].Trim()
            }
            $ShowVlanPSO.Add($NewVlanObj)
        }
    }

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF ($InterfaceConfig -contains "shutdown" -AND $InterfaceConfig -match "switchport (mode)?\s?access" -AND !($InterfaceConfig -contains "dot1x pae authenticator")) {
            $Non8021xInterfaces += $Interface
        }

        IF ($InterfaceConfig -contains "shutdown" -AND $InterfaceConfig -match "switchport (mode)?\s?access" -AND $InterfaceConfig -contains "dot1x pae authenticator") {
            $NAInterfaces += ($Interface | Out-String).Trim()
            IF ($InterfaceConfig -like "description*") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
            }
            IF ($InterfaceConfig -contains "switchport mode access") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
            }
            IF ($InterfaceConfig -like "switchport access vlan*") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
            }
            IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticator"})
            }
            IF ($InterfaceConfig -like "shutdown*") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "shutdown*"} | Out-String).Trim()
            }
            $NAInterfaces += ""
        }
    }

    IF ($Non8021xInterfaces) {
        ForEach ($Interface in $Non8021xInterfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $InterfaceResults += ($Interface | Out-String).Trim()
            $InterfaceResults += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
            $VLAN = ( -split ($InterfaceConfig | Select-String -Pattern "^switchport access vlan.*" ))[3]
            IF (($ShowVlanPSO | Where-Object {$_.Vlan -eq $Vlan}).status -eq "act/lshut" -AND $Vlan -notin $AllTrunkVLANs) {
                $InterfaceResults += " " + ($InterfaceConfig | Select-String -Pattern "^switchport access vlan.*" | Out-String).Trim()
            }
            Else {
                $OpenFinding = $True
                $InterfaceResults += " " + ($InterfaceConfig | Select-String -Pattern "^switchport access vlan.*" | Out-String).Trim()
                IF (!(($ShowVlanPSO | Where-Object {$_.Vlan -eq $Vlan}).status -eq "act/lshut")) {
                    $InterfaceResults += "  VLAN Status For VLAN " + $VLAN + ": " + ($ShowVlanPSO | Where-Object {$_.Vlan -eq $Vlan}).status + " - NON-COMPLIANT"
                }
                IF ($Vlan -in $AllTrunkVLANs) {
                    $InterfaceResults += "  VLAN $VLAN is allowed on trunk links"
                }
            }
            $InterfaceResults += " " + ($InterfaceConfig | Select-String -patter "^shutdown$" | Out-String).Trim()
            $InterfaceResults += ""
        }

        $FindingDetails += "Inactive VLANs:" | Out-String
        $FindingDetails += ($ShowVlanPSO | Where-Object {$_.Status -ne "active"} | Select-Object VLAN, Name, STATUS | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += "Trunk Ports:" | Out-String
        $FindingDetails += IF ($ShowInterfacesTrunk) {
($ShowInterfacesTrunk | Out-String)
        }
        Else {
("Trunk ports not configured" | Out-String).Trim()
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "Shutdown Interfaces (without 802.1x)" | Out-String
        $FindingDetails += "-------------------------------------" | Out-String
        $FindingDetails += ($InterfaceResults | Out-String).Trim()
        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "All shutdown switchport mode access VLANs are managed by 802.1x" | Out-String
        $FindingDetails += "Switch ports configured for 802.1x are exempt from this requirement." | Out-String
        $FindingDetails += "" | Out-String
        if ($NAInterfaces) {
            $FindingDetails += "Interfaces" | Out-String
            $FindingDetails += "-----------" | Out-String
            $FindingDetails += $NAInterfaces -join "`n" | Out-String
        }
        $Status = "Not_Applicable"
    }
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V220668 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220668
        STIG ID    : CISC-L2-000220
        Rule ID    : SV-220668r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000008
        Rule Title : The Cisco switch must not have the default VLAN assigned to any host-facing switch ports.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $CompliantInt = @()
    $NonCompliantInt = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $SwitchPortVLAN = $InterfaceConfig | Select-String -Pattern "^switchport access .*"
            IF ($SwitchPortVLAN) {
                IF (($SwitchPortVLAN | Out-String).Trim().Split([char[]]"")[3] -eq "1") {
                    $OpenFinding = $True
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    $NonCompliantInt += " " + ($SwitchPortVLAN | Out-String).Trim()
                    $NonCompliantInt += ""
                }
                Else {
                    $CompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    $CompliantInt += " " + ($SwitchPortVLAN | Out-String).Trim()
                    $CompliantInt += ""
                }
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                $NonCompliantInt += "switch port access vlan not configured, switchport will default to VLAN 1"
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces " | Out-String
            $FindingDetails += "---------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Non-Compliant Interfaces " | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
        }

        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220669 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220669
        STIG ID    : CISC-L2-000230
        Rule ID    : SV-220669r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000009
        Rule Title : The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $CompliantInt = @()
    $NonCompliantInt = @()
    $startSTR = "Port\s+Vlans\s+allowed\s+on\s+trunk"
    $startIndex = ($ShowTech | Select-String $startSTR).LineNumber
    if ($startIndex) {
        $EndIndex = $startIndex
        DO {
            $EndIndex++
        }Until($ShowTech[$EndIndex] -match "")
        $ShowInterfacesTrunk = $ShowTech | Select-Object -Index ($startIndex..($EndIndex))
        ForEach ($Trunk in $ShowInterfacesTrunk) {
            if ($Trunk) {
                $Interface = (-split $Trunk)[0]
                $TrunkVlans = (-split $Trunk)[1].Split(",")
                $VLANs = @()
                ForEach ($Vlan in $TrunkVlans) {
                    IF ($Vlan -like "*-*") {
                        $DashIndex = $Vlan.IndexOf("-")
                        $StartInt = $Vlan.Substring(0, $DashIndex)
                        $EndInt = $Vlan.Substring($DashIndex + 1)
                        $VLANs += $StartInt..$EndInt
                    }
                    Else {
                        $VLANs += $Vlan
                    }
                }
                IF ($VLANs -contains "1") {
                    $OpenFinding = $True
                    $NonCompliantInt += $Trunk
                }
                Else {
                    $CompliantInt += $Trunk
                }
            }
        }
    }
    Else {
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport trunk allowed vlan.*") {
                $Trunk = ( -Split ($InterfaceConfig | Select-String -Pattern "^switchport trunk allowed vlan.*"))[4]
                if ($Trunk) {
                    $TrunkVlans = $Trunk.Split(",")
                    $VLANs = @()
                    ForEach ($Vlan in $TrunkVlans) {
                        IF ($Vlan -like "*-*") {
                            $DashIndex = $Vlan.IndexOf("-")
                            $StartInt = $Vlan.Substring(0, $DashIndex)
                            $EndInt = $Vlan.Substring($DashIndex + 1)
                            $VLANs += $StartInt..$EndInt
                        }
                        Else {
                            $VLANs += $Vlan
                        }
                    }
                    IF ($VLANs -contains "1") {
                        $OpenFinding = $True
                        $NonCompliantInt += ($Interface | Out-String).Trim()
                        $NonCompliantInt += ($InterfaceConfig | Select-String -Pattern "^switchport trunk allowed vlan.*" | Out-String).Trim()
                        $NonCompliantInt += ("" | Out-String).Trim()
                    }
                    Else {
                        $CompliantInt += ($Interface | Out-String).Trim()
                        $CompliantInt += ($InterfaceConfig | Select-String -Pattern "^switchport trunk allowed vlan.*" | Out-String).Trim()
                        $CompliantInt += ("" | Out-String).Trim()
                    }
                }


            }
        }
    }

    IF ($CompliantInt) {
        $FindingDetails += "Compliant Trunk Interfaces" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $CompliantInt | Out-String
        $FindingDetails += "" | Out-String
    }

    IF ($NonCompliantInt) {
        $FindingDetails += "Non-Compliant Trunk Interfaces" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $NonCompliantInt | Out-String
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

Function Get-V220670 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220670
        STIG ID    : CISC-L2-000240
        Rule ID    : SV-220670r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000010
        Rule Title : The Cisco switch must not use the default VLAN for management traffic.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Vlan1 = ($ShowRunningConfig | Select-String -Pattern "^Interface vlan1$" | Out-String).Trim()
    $DefaultVLan = Get-Section $ShowRunningConfig "$vlan1"
    IF ($DefaultVLan -contains "shutdown" -AND $DefaultVLan -contains "no ip address") {
        $FindingDetails += $Vlan1 | Out-String
        $FindingDetails += $DefaultVLan | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Review the switch configuration below and verify that the default VLAN is not used to access the switch for management." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $Vlan1 | Out-String
        $FindingDetails += $DefaultVLan | Out-String
    }
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V220671 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220671
        STIG ID    : CISC-L2-000250
        Rule ID    : SV-220671r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000011
        Rule Title : The Cisco switch must have all user-facing or untrusted ports configured as access switch ports.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $TrunkInterfaces = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown")) {
            IF ($InterfaceConfig -contains "switchport mode trunk") {
                $TrunkInterfaces += ($Interface | Out-String).Trim()
                $TrunkInterfaces += ($InterfaceConfig | Out-String).Trim()
                $TrunkInterfaces += ""
            }
        }
    }

    IF ($TrunkInterfaces) {
        $FindingDetails += "Review switch configuration below and determine if any interfaces are user-facing or untrusted switchports." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Trunk Interfaces" | Out-String
        $FindingDetails += "------------------------" | Out-String
        $FindingDetails += $TrunkInterfaces | Out-String
    }
    Else {
        $FindingDetails += "There are no trunk interfaces on this switch" | Out-String
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

Function Get-V220672 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220672
        STIG ID    : CISC-L2-000260
        Rule ID    : SV-220672r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000012
        Rule Title : The Cisco switch must have the native VLAN assigned to an ID other than the default VLAN for all 802.1q trunk links.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown")) {
            IF ($InterfaceConfig -contains "switchport trunk encapsulation dot1q") {
                IF ($InterfaceConfig | Where-Object {$_ -like "switchport trunk native vlan*"}) {
                    IF (($InterfaceConfig | Where-Object {$_ -like "switchport trunk native vlan*"} | Out-String).Trim().Split([char[]]"")[4] -eq "1") {
                        $OpenFinding = $True
                    }
                    IF (!$FindingDetails) {
                        $FindingDetails += "Trunk Interfaces" | Out-String
                        $FindingDetails += "------------------" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    $FindingDetails += ($Interface | Out-String).Trim()
                    $FindingDetails += " " + ($InterfaceConfig | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
                Else {
                    $OpenFinding = $True
                    IF (!$FindingDetails) {
                        $FindingDetails += "Trunk Interfaces" | Out-String
                        $FindingDetails += "------------------" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    $FindingDetails += ($Interface | Out-String).Trim()
                    $FindingDetails += " " + ($InterfaceConfig | Out-String).Trim()
                    $FindingDetails += "Swithport Native VLAN is not configured" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
        }
    }

    IF ($FindingDetails) {
        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FINDINGDETAILS += "No 802.1q trunk links are configured" | Out-String
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

Function Get-V220673 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220673
        STIG ID    : CISC-L2-000270
        Rule ID    : SV-220673r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000013
        Rule Title : The Cisco switch must not have any switchports assigned to the native VLAN.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $NativeVLANs = @()
    $ActiveAccessSwitchPorts = @()
    $CompliantInt = @()
    $NonCompliantInt = @()
    $NativeVLanstartSTR = "^Port\s+Mode\s+Encapsulation\s+Status\s+Native\s+vlan"
    $NativeVLANstartIndex = ($ShowTech | Select-String $NativeVLanstartSTR).LineNumber
    if ($NativeVLANstartIndex) {
        $NativeVLANEndIndex = $NativeVLANstartIndex
        DO {
            $NativeVLANEndIndex++
        }Until($ShowTech[$NativeVLANEndIndex] -match "")
        $ShowInterfacesTrunk = $ShowTech | Select-Object -Index (($NativeVLANstartIndex - 1)..($NativeVLANEndIndex))
    }
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        if ($ShowInterfacesTrunk) {
            ForEach ($Trunk in ($ShowInterfacesTrunk | Select-Object -Skip 1)) {
                IF ((-split $Trunk)[4] -notin $NativeVLANs) {
                    $NativeVLANs += (-split $Trunk)[4]
                }
            }
        }
        else {
            $NativeVLANs += $ShowRunningConfig | Select-String -Pattern "switchport trunk native vlan.*" | ForEach-Object {(-Split $_)[4]} | Get-Unique
        }
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -like "switchport access vlan*") {
                IF (($InterfaceConfig -like "switchport access vlan*" | Out-String).Trim().Split([char[]]"")[3] -in $NativeVLANs) {
                    $OpenFinding = $True
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                    $NonCompliantInt += ""
                }
                Else {
                    $CompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -contains "switchport mode access") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -like "switchport access vlan*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticat"})
                    }
                    $CompliantInt += ""
                }
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += ""
                $NonCompliantInt += "switchport access vlan not configured"
                $NonCompliantInt += "$Interface will default to VLAN 1"
            }
        }

        if ($ShowInterfacesTrunk) {
            $FindingDetails += $ShowInterfacesTrunk.Trim() | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "Native VLANs" | Out-String
            $FindingDetails += "---------------" | Out-String
            $FindingDetails += $NativeVLANs.Trim() | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt.Trim() | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Non-Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt.Trim() | Out-String
            $FindingDetails += "" | Out-String
        }


        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC55iU8cMHkNcYL
# QzPpM1LDq/mGBQxfhtnY1ubn2VZqOqCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD3ZlLo9ByLAupAPvI03r73ryHMpkHS
# sLhGkYYTNVBM8TANBgkqhkiG9w0BAQEFAASCAQCWPYg/o430+u4gZgkytQu+YaRy
# imtdnTaX4l6pOleZ8jMTX4OIuuiXVhiFuVDw2F4ZN1KV55rozRQaWs4wPa0fP9lz
# g79hIn4Qjtiq3NMpDRZ9Q5m5K2EPmVdPTbeMaT16GTgykGbqZrcNXfqUWxU3OZG4
# VoJx6MKDrTLV/AUP+wvx6rDafb2O7oyj3pR+aZzS8+oEtm2+lVdtjqVjs1rbTm+c
# zSSK0e7pbM26lwpoZTXz8YTS0WQ4nnekA5S0vJawf12FSGqGJ916BDFmYl5iVB/x
# WjYrQRlJoVr1voho+ppV287GNSIfmpGDF6kyAhNKiM8Kvlu49BO25eGwVJ37
# SIG # End signature block
