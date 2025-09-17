##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Red Hat Enterprise Linux 7
# Version:  V3R11
# Class:    UNCLASSIFIED
# Updated:  5/1/2023
# Author:   Daniel Frye
##########################################################################
$ErrorActionPreference = "Stop"

Function ConvertModeStringtoDigits {
    Param(
        [parameter (Mandatory = $true, position = 0, ParameterSetName = 'modestring')]
        [AllowNull()]
        $line
    )

    $Digits = ($line.substring(1)) -replace ".$" | sed -re 's/rwx/7/g' -e 's/rw-/6/g' -e 's/r-x/5/g' -e 's/r--/4/g' -e 's/-wx/3/g' -e 's/-w-/2/g' -e 's/--x/1/g' -e 's/---/0/g'

    return $Digits
}

Function FormatFinding {
    # Return string which is added at end of $FindingDetails by each V-XXXXX method.
    # Requires finding argument.
    Param(
        [parameter (Mandatory = $true, position = 0, ParameterSetName = 'finding')]
        [AllowNull()]
        $line
    )

    # insert separator line between $FindingMessage and $finding
    $BarLine = "------------------------------------------------------------------------"
    $FormattedFinding += $BarLine | Out-String

    # insert findings
    $FormattedFinding += $finding | Out-String

    return $FormattedFinding
}

Function Get-V204393 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204393
        STIG ID    : RHEL-07-010030
        Rule ID    : SV-204393r603261_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $finding = $(grep -s -ir ^banner-message-enable /etc/dconf/db/local.d/)
        $finding ?? $($finding = "Check text: No results found.")

        If (($finding | awk '{$2=$2};1').replace(" ", "").split(":")[1] -eq "banner-message-enable=true") {
            $Status = "NotAFinding"
            $FindingMessage = "The Standard Mandatory DoD Notice and Consent Banner text is displayed before granting local or remote access to the system via a graphical user logon."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Standard Mandatory DoD Notice and Consent Banner text is not displayed before granting local or remote access to the system via a graphical user logon."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204394 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204394
        STIG ID    : RHEL-07-010040
        Rule ID    : SV-204394r603261_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : The Red Hat Enterprise Linux operating system must display the approved Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $finding = $(grep -s -ir ^banner-message-text /etc/dconf/db/local.d/)

        if ($finding){
            If ((($finding.split("=")[1] | awk '{$2=$2};1')).replace(" ", "") -eq "'YouareaccessingaU.S.Government(USG)InformationSystem(IS)thatisprovidedforUSG-authorizeduseonly.\nByusingthisIS(whichincludesanydeviceattachedtothisIS),youconsenttothefollowingconditions:\n-TheUSGroutinelyinterceptsandmonitorscommunicationsonthisISforpurposesincluding,butnotlimitedto,penetrationtesting,COMSECmonitoring,networkoperationsanddefense,personnelmisconduct(PM),lawenforcement(LE),andcounterintelligence(CI)investigations.\n-Atanytime,theUSGmayinspectandseizedatastoredonthisIS.\n-Communicationsusing,ordatastoredon,thisISarenotprivate,aresubjecttoroutinemonitoring,interception,andsearch,andmaybedisclosedorusedforanyUSG-authorizedpurpose.\n-ThisISincludessecuritymeasures(e.g.,authenticationandaccesscontrols)toprotectUSGinterests--notforyourpersonalbenefitorprivacy.\n-Notwithstandingtheabove,usingthisISdoesnotconstituteconsenttoPM,LEorCIinvestigativesearchingormonitoringofthecontentofprivilegedcommunications,orworkproduct,relatedtopersonalrepresentationorservicesbyattorneys,psychotherapists,orclergy,andtheirassistants.Suchcommunicationsandworkproductareprivateandconfidential.SeeUserAgreementfordetails.'") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system displays the exact approved Standard Mandatory DoD Notice and Consent Banner text."
            }
            Else {
                $Status = "Open"
                $FindingMessage = "The operating system does not display the exact approved Standard Mandatory DoD Notice and Consent Banner text."
            }
        }
        else{
            $Status = "Open"
            $FindingMessage = "The operating system does not display any Banner text."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204395 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204395
        STIG ID    : RHEL-07-010050
        Rule ID    : SV-204395r603261_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /etc/issue)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = $((cat /etc/issue | awk '{$2=$2};1').replace(" ", "").replace('"','')) | tr -d "\n"
    $finding_2 ?? $($finding_2 = "Check text: No results found.")

    if ($finding_2 -eq "YouareaccessingaU.S.Government(USG)InformationSystem(IS)thatisprovidedforUSG-authorizeduseonly.ByusingthisIS(whichincludesanydeviceattachedtothisIS),youconsenttothefollowingconditions:-TheUSGroutinelyinterceptsandmonitorscommunicationsonthisISforpurposesincluding,butnotlimitedto,penetrationtesting,COMSECmonitoring,networkoperationsanddefense,personnelmisconduct(PM),lawenforcement(LE),andcounterintelligence(CI)investigations.-Atanytime,theUSGmayinspectandseizedatastoredonthisIS.-Communicationsusing,ordatastoredon,thisISarenotprivate,aresubjecttoroutinemonitoring,interception,andsearch,andmaybedisclosedorusedforanyUSG-authorizedpurpose.-ThisISincludessecuritymeasures(e.g.,authenticationandaccesscontrols)toprotectUSGinterests--notforyourpersonalbenefitorprivacy.-Notwithstandingtheabove,usingthisISdoesnotconstituteconsenttoPM,LEorCIinvestigativesearchingormonitoringofthecontentofprivilegedcommunications,orworkproduct,relatedtopersonalrepresentationorservicesbyattorneys,psychotherapists,orclergy,andtheirassistants.Suchcommunicationsandworkproductareprivateandconfidential.SeeUserAgreementfordetails.") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not display the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204396 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204396
        STIG ID    : RHEL-07-010060
        Rule ID    : SV-204396r880746_rule
        CCI ID     : CCI-000056
        Rule Name  : SRG-OS-000028-GPOS-00009
        Rule Title : The Red Hat Enterprise Linux operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $finding = $(grep -s -iR ^lock-enabled /etc/dconf/db/local.d/ | grep -v locks)
        $finding ?? $($finding = "Check text: No results found.")

        If (($finding | awk '{$2=$2};1').replace(" ", "").split(":")[1] -eq "lock-enabled=true") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system enables a user's session lock until that user re-establishes access using established identification and authentication procedures."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not enable a user's session lock until that user re-establishes access using established identification and authentication procedures."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204397 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204397
        STIG ID    : RHEL-07-010061
        Rule ID    : SV-204397r853879_rule
        CCI ID     : CCI-001948, CCI-001953, CCI-001954
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : The Red Hat Enterprise Linux operating system must uniquely identify and must authenticate users using multifactor authentication via a graphical user logon.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)
    $found = $false

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $systemdb = $(grep -s system-db /etc/dconf/profile/user)
        $finding = $systemdb
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $systemdb | ForEach-Object {
            $finding = $(grep -s -i ^[[:blank:]]*enable-smartcard-authentication /etc/dconf/db/$($_.split(":")[1]).d/*)
            $finding ?? $($Finding = "Check text did not return results for $($_.split(":")[1]).")

            If (($finding | awk '{$2=$2};1').replace(" ", "").split(":")[1] -eq "enable-smartcard-authentication=true") {
                $found = $True
            }

            $FindingDetails += $(FormatFinding $finding) | Out-String
        }

        if ($found) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system uniquely identifies and authenticates users using multifactor authentication via a graphical user logon."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not uniquely identify and authenticate users using multifactor authentication via a graphical user logon."
        }
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204398 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204398
        STIG ID    : RHEL-07-010070
        Rule ID    : SV-204398r880770_rule
        CCI ID     : CCI-000057
        Rule Name  : SRG-OS-000029-GPOS-00010
        Rule Title : The Red Hat Enterprise Linux operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $finding = $(grep -s -ir ^idle-delay /etc/dconf/db/local.d/*)
        $finding ?? $($finding = "Check text: No results found.")

        If ((($finding | awk '{$2=$2};1').replace(" ", "")).split(":")[1] -match "idle-delay=uint32") {
            if (($finding | awk '{$2=$2};1').replace(" ", "").split("uint32")[1] ?? 901 -le 900) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system initiates a screensaver after a 15-minute period of inactivity for graphical user interfaces."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system initiates a screensaver for graphical user interfaces, but greater than 15 minutes."
            }
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not initiates a screensaver for graphical user interfaces."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204399 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204399
        STIG ID    : RHEL-07-010081
        Rule ID    : SV-204399r880773_rule
        CCI ID     : CCI-000057
        Rule Name  : SRG-OS-000029-GPOS-00010
        Rule Title : The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver lock-delay setting for the graphical user interface.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)
    $found = $false

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $systemdb = $(grep -s system-db /etc/dconf/profile/user)
        $finding = $systemdb
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $systemdb | ForEach-Object {
            $finding = $(grep -s -ir lock-delay /etc/dconf/db/$($_.split(":")[1]).d/locks/)
            $finding ?? $($Finding = "Check text did not return results for $($_.split(":")[1]).")

            If ($finding.split(":")[1]) {
                If (($finding.split(":")[1]).startswith("/org/gnome/desktop/screensaver/lock-delay")) {
                    $found = $True
                }
            }

            $FindingDetails += $(FormatFinding $finding) | Out-String
        }

        If ($found) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system prevents a user from overriding a screensaver lock after a 15-minute period of inactivity for graphical user interfaces."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not prevent a user from overriding a screensaver lock after a 15-minute period of inactivity for graphical user interfaces."
        }
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204400 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204400
        STIG ID    : RHEL-07-010082
        Rule ID    : SV-204400r880776_rule
        CCI ID     : CCI-000057
        Rule Name  : SRG-OS-000029-GPOS-00010
        Rule Title : The Red Hat Enterprise Linux operating system must prevent a user from overriding the session idle-delay setting for the graphical user interface.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)
    $found = $false

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $systemdb = $(grep -s system-db /etc/dconf/profile/user)
        $finding = $systemdb
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $systemdb | ForEach-Object {
            $finding = $(grep -s -iR "session/idle-delay" /etc/dconf/db/$($_.split(":")[1]).d/locks/)
            $finding ?? $($Finding = "Check text did not return results for $($_.split(":")[1]).")

            If ($finding.split(":")[1]) {
                If (($finding.split(":")[1]).startswith("/org/gnome/desktop/session/idle-delay")) {
                    $found = $True
                }
            }

            $FindingDetails += $(FormatFinding $finding) | Out-String
        }

        If ($found) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system prevents a user from overriding session idle delay after a 15-minute period of inactivity for graphical user interfaces."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not prevent a user from overriding session idle delay after a 15-minute period of inactivity for graphical user interfaces. "
        }
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204402 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204402
        STIG ID    : RHEL-07-010100
        Rule ID    : SV-204402r880782_rule
        CCI ID     : CCI-000057
        Rule Name  : SRG-OS-000029-GPOS-00010
        Rule Title : The Red Hat Enterprise Linux operating system must initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $finding = $(grep -s -ir ^idle-activation-enabled /etc/dconf/db/local.d/)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').replace(" ", "").split(":")[1] -eq "idle-activation-enabled=true") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system initiates a session lock after a 15-minute period of inactivity for graphical user interfaces."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not initiate a session lock after a 15-minute period of inactivity for graphical user interfaces."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204403 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204403
        STIG ID    : RHEL-07-010101
        Rule ID    : SV-204403r880785_rule
        CCI ID     : CCI-000057
        Rule Name  : SRG-OS-000029-GPOS-00010
        Rule Title : The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver idle-activation-enabled setting for the graphical user interface.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)
    $found = $false

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $systemdb = $(grep -s system-db /etc/dconf/profile/user)
        $finding = $systemdb
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $systemdb | ForEach-Object {
            $finding = $(grep -s -iR idle-activation-enabled /etc/dconf/db/$($_.split(":")[1]).d/locks/)
            $finding ?? $($Finding = "Check text did not return results for $($_.split(":")[1]).")

            If ($finding.split(":")[1]) {
                If (($finding.split(":")[1]).StartsWith("/org/gnome/desktop/screensaver/idle-activation-enabled")) {
                    $found = $True
                }
            }

            $FindingDetails += $(FormatFinding $finding) | Out-String
        }

        If ($found) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system prevents a user from overriding the screensaver idle-activation-enabled setting for the graphical user interface. "
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not prevent a user from overriding the screensaver idle-activation-enabled setting for the graphical user interface. "
        }
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204404 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204404
        STIG ID    : RHEL-07-010110
        Rule ID    : SV-204404r880788_rule
        CCI ID     : CCI-000057
        Rule Name  : SRG-OS-000029-GPOS-00010
        Rule Title : The Red Hat Enterprise Linux operating system must initiate a session lock for graphical user interfaces when the screensaver is activated.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)
    $found = $false

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $finding = $(grep -s -ir ^lock-delay /etc/dconf/db/local.d/)

        If ($finding) {
            if (($finding | awk '{$2=$2};1').replace(" ", "").split("uint32")[1] ?? 6 -le 5) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system initiates a session lock a for graphical user interfaces when the screensaver is activated."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system initiates a session lock a for graphical user interfaces when the screensaver is activated but locks after 6 seconds or more."
            }
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not initiate a session lock a for graphical user interfaces when the screensaver is activated."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204405 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204405
        STIG ID    : RHEL-07-010118
        Rule ID    : SV-204405r603261_rule
        CCI ID     : CCI-000192
        Rule Name  : SRG-OS-000069-GPOS-00037
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that /etc/pam.d/passwd implements /etc/pam.d/system-auth when changing passwords.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /etc/pam.d/passwd | grep -s -i substack | grep -s -i system-auth)
    $finding ?? $($finding = "Check text: No results found.")

    If (($finding | awk '{$2=$2};1').StartsWith("password substack system-auth")) {
        $Status = "NotAFinding"
        $FindingMessage = "/etc/pam.d/passwd is configured to use /etc/pam.d/system-auth when changing passwords."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "/etc/pam.d/passwd is not configured to use /etc/pam.d/system-auth when changing passwords."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204406 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204406
        STIG ID    : RHEL-07-010119
        Rule ID    : SV-204406r902704_rule
        CCI ID     : CCI-000192
        Rule Name  : SRG-OS-000069-GPOS-00037
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, pwquality must be used.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /etc/pam.d/system-auth | grep -s pam_pwquality)
    $finding ?? $($finding = "Check text: No results found.")

    If (($finding.startswith("password")) -and ($finding.contains("pam_pwquality.so"))) {
        if ((($finding | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "retry" }).split("=")[1] -in 1..3) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system uses 'pwquality' to enforce the password complexity rules."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system uses 'pwquality' to enforce the password complexity rules, but allows more than 3 attempts."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not use 'pwquality' to enforce the password complexity rules."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204407 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204407
        STIG ID    : RHEL-07-010120
        Rule ID    : SV-204407r603261_rule
        CCI ID     : CCI-000192
        Rule Name  : SRG-OS-000069-GPOS-00037
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one upper-case character.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*ucredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If ((($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] ?? 0) -lt 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The value for 'ucredit' in '/etc/security/pwquality.conf' is negative."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for 'ucredit' in '/etc/security/pwquality.conf' is not negative."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Note: The value to require a number of upper-case characters to be set is expressed as a negative number in '/etc/security/pwquality.conf'."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204408 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204408
        STIG ID    : RHEL-07-010130
        Rule ID    : SV-204408r603261_rule
        CCI ID     : CCI-000193
        Rule Name  : SRG-OS-000070-GPOS-00038
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one lower-case character.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*lcredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If ((($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] ?? 0) -lt 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The value for 'lcredit' in '/etc/security/pwquality.conf' is negative."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for 'lcredit' in '/etc/security/pwquality.conf' is not negative."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Note: The value to require a number of lower-case characters to be set is expressed as a negative number in '/etc/security/pwquality.conf'."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204409 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204409
        STIG ID    : RHEL-07-010140
        Rule ID    : SV-204409r603261_rule
        CCI ID     : CCI-000194
        Rule Name  : SRG-OS-000071-GPOS-00039
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are assigned, the new password must contain at least one numeric character.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*dcredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If ((($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] ?? 0) -lt 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The value for 'dcredit' in '/etc/security/pwquality.conf' is negative."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for 'dcredit' in '/etc/security/pwquality.conf' is not negative."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Note: The value to require a number of lower-case characters to be set is expressed as a negative number in '/etc/security/pwquality.conf'."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204410 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204410
        STIG ID    : RHEL-07-010150
        Rule ID    : SV-204410r603261_rule
        CCI ID     : CCI-001619
        Rule Name  : SRG-OS-000266-GPOS-00101
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one special character.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*ocredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If ((($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] ?? 0) -lt 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The value for 'ocredit' in '/etc/security/pwquality.conf' is negative."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for 'ocredit' in '/etc/security/pwquality.conf' is not negative."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Note: The value to require a number of lower-case characters to be set is expressed as a negative number in '/etc/security/pwquality.conf'."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204411 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204411
        STIG ID    : RHEL-07-010160
        Rule ID    : SV-204411r603261_rule
        CCI ID     : CCI-000195
        Rule Name  : SRG-OS-000072-GPOS-00040
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed a minimum of eight of the total number of characters must be changed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*difok /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If ([int](($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]) -ge 8) {
        $Status = "NotAFinding"
        $FindingMessage = "The value for 'difok' in '/etc/security/pwquality.conf' is 8 or more."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for 'difok' in '/etc/security/pwquality.conf' is less than 8."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204412 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204412
        STIG ID    : RHEL-07-010170
        Rule ID    : SV-204412r603261_rule
        CCI ID     : CCI-000195
        Rule Name  : SRG-OS-000072-GPOS-00040
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed a minimum of four character classes must be changed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*minclass /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If ([int](($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]) -ge 4) {
        $Status = "NotAFinding"
        $FindingMessage = "The value for 'minclass' in '/etc/security/pwquality.conf' is 4 or more."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for 'minclass' in '/etc/security/pwquality.conf' is less than 4."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204413 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204413
        STIG ID    : RHEL-07-010180
        Rule ID    : SV-204413r603261_rule
        CCI ID     : CCI-000195
        Rule Name  : SRG-OS-000072-GPOS-00040
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed the number of repeating consecutive characters must not be more than three characters.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*maxrepeat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] ?? 4 -le 3) {
        $Status = "NotAFinding"
        $FindingMessage = "The value for 'maxrepeat' in '/etc/security/pwquality.conf' is 3 or less."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for 'maxrepeat' in '/etc/security/pwquality.conf' is more than 3."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204414 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204414
        STIG ID    : RHEL-07-010190
        Rule ID    : SV-204414r809186_rule
        CCI ID     : CCI-000195
        Rule Name  : SRG-OS-000072-GPOS-00040
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed the number of repeating characters of the same character class must not be more than four characters.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*maxclassrepeat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -in 1..4) {
        $Status = "NotAFinding"
        $FindingMessage = "The value for 'maxclassrepeat' in '/etc/security/pwquality.conf' is 4 or less."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for 'maxclassrepeat' in '/etc/security/pwquality.conf' is more than 4."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204415 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204415
        STIG ID    : RHEL-07-010200
        Rule ID    : SV-204415r880833_rule
        CCI ID     : CCI-000196
        Rule Name  : SRG-OS-000073-GPOS-00041
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the PAM system service is configured to store only encrypted representations of passwords.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s password /etc/pam.d/system-auth /etc/pam.d/password-auth)
    $finding ?? $($finding = "Check text: No results found.")
    $correct = 0

    $finding | ForEach-Object {
        If ($_.ToUpper() -match "SHA512") {
            $correct++
        }
    }
    If ($correct -eq 2) {
        $Status = "NotAFinding"
        $FindingMessage = "The PAM system service is configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The PAM system service is not configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204416 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204416
        STIG ID    : RHEL-07-010210
        Rule ID    : SV-204416r877397_rule
        CCI ID     : CCI-000196
        Rule Name  : SRG-OS-000073-GPOS-00041
        Rule Title : The Red Hat Enterprise Linux operating system must be configured to use the shadow file to store only encrypted representations of passwords.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*encrypt /etc/login.defs)
    $finding ?? $($finding = "Check text: No results found.")

    If (($Finding | awk '{$2=$2};1').ToUpper() -eq "ENCRYPT_METHOD SHA512") {
        $Status = "NotAFinding"
        $FindingMessage = "The system's shadow file is configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The system's shadow file is not configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204417 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204417
        STIG ID    : RHEL-07-010220
        Rule ID    : SV-204417r877397_rule
        CCI ID     : CCI-000196
        Rule Name  : SRG-OS-000073-GPOS-00041
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that user and group account administration utilities are configured to store only encrypted representations of passwords.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i sha512 /etc/libuser.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If ($Finding.StartsWith("crypt_style")) {
        if (($finding | awk '{$2=$2};1').replace(" ", "").split("=").Tolower() -eq "sha512") {
            $check_default = $(sed -n '/\[defaults\]/,/\[/p' /etc/libuser.conf | grep -s crypt_style )
            if ($check_default) {
                $Status = "NotAFinding"
                $FindingMessage = "The user and group account administration utilities are configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The user and group account administration utilities are configured to store only encrypted representations of passwords but not in the defaults section. The strength of encryption that must be used to hash passwords for all accounts is SHA512."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The user and group account administration utilities are configured to store only encrypted representations of passwords but does not use SHA512 encryption. The strength of encryption that must be used to hash passwords for all accounts is SHA512."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The user and group account administration utilities are not configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204418 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204418
        STIG ID    : RHEL-07-010230
        Rule ID    : SV-204418r603261_rule
        CCI ID     : CCI-000198
        Rule Name  : SRG-OS-000075-GPOS-00043
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that passwords for new users are restricted to a 24 hours/1 day minimum lifetime.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*pass_min_days /etc/login.defs)
    $finding ?? $($finding = "Check text: No results found.")

    If ([int](($finding | awk '{$2=$2};1').split(" ")[1]) -ge 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system enforces 24 hours/1 day as the minimum password lifetime for new user accounts."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not enforce 24 hours/1 day as the minimum password lifetime for new user accounts."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204419 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204419
        STIG ID    : RHEL-07-010240
        Rule ID    : SV-204419r603261_rule
        CCI ID     : CCI-000198
        Rule Name  : SRG-OS-000075-GPOS-00043
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that passwords are restricted to a 24 hours/1 day minimum lifetime.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $userlist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $userlist = "Unable to create temp file to process check."
        $finding = $userlist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    $command = @'
awk -F: '$3>=1000 && $3!=65534 {print $1}' /etc/passwd
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $localusers = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $localusers = "Unable to create temp file to process check."
        $finding = $localusers
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    $found = 0

    $userlist | ForEach-Object {
        if ($_.split(" ")[0] -in $localusers) {
            $finding = $_
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    if ($found -gt 0) {
        $Status = "Open"
        $FindingMessage = "The operating system's minimum time period between password changes for each user account is not one day or greater for non-system accounts."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system'sminimum time period between password changes for each user account is one day or greater for non-system accounts."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204420 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204420
        STIG ID    : RHEL-07-010250
        Rule ID    : SV-204420r603261_rule
        CCI ID     : CCI-000199
        Rule Name  : SRG-OS-000076-GPOS-00044
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that passwords for new users are restricted to a 60-day maximum lifetime.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*pass_max_days /etc/login.defs)
    $finding ?? $($finding = "Check text: No results found.")

    If (($finding | awk '{$2=$2};1').split(" ")[1] -le 60) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system enforces a 60-day maximum password lifetime restriction for new user accounts."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not enforce a 60-day maximum password lifetime restriction for new user accounts."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204421 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204421
        STIG ID    : RHEL-07-010260
        Rule ID    : SV-204421r603261_rule
        CCI ID     : CCI-000199
        Rule Name  : SRG-OS-000076-GPOS-00044
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that existing passwords are restricted to a 60-day maximum lifetime.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $userlist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $userlist = "Unable to create temp file to process check."
        $finding = $userlist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    $command = @'
awk -F: '$3>=1000 && $3!=65534 {print $1}' /etc/passwd
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $localusers = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $localusers = "Unable to create temp file to process check."
        $finding = $localusers
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    $found = 0

    $userlist | ForEach-Object {
        if ($_.split(" ")[0] -in $localusers) {
            $finding = $_
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    if ($found -gt 0) {
        $Status = "Open"
        $FindingMessage = "The operating system's maximum time period for existing passwords is not restricted to 60 days for non-system accounts."
    }
    else{
        $Status = "NotAFinding"
        $FindingMessage = "The operating system's maximum time period for existing passwords is restricted to 60 days for non-system accounts."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204422 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204422
        STIG ID    : RHEL-07-010270
        Rule ID    : SV-204422r880836_rule
        CCI ID     : CCI-000200
        Rule Name  : SRG-OS-000077-GPOS-00045
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that passwords are prohibited from reuse for a minimum of five generations.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth)
    $finding ?? $($finding = "Check text: No results found.")

    $system_auth = $(grep -s -i remember /etc/pam.d/system-auth | grep -s pam_pwhistory.so)
    if (!($system_auth)) { $system_auth = "Check text: No results found." }
    $authpass = $false
    $password_auth = $(grep -s -i remember /etc/pam.d/password-auth | grep -s pam_pwhistory.so)
    if (!($password_auth)) { $password_auth = "Check text: No results found." }
    $passwordpass = $false

    $FindingMessage = "Checking system-auth for correct settings:"
    $FindingMessage += "`r`n"

    If (($system_auth.split(":")).startswith("password") -and ($system_auth -match "remember")) {
        if ([int]((($system_auth | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "remember" }).split("=")[1]) -ge 5) {
            $authpass = $True
            $FindingMessage += "The system-auth prohibits password reuse for a minimum of five generations."
        }
        else {
            $FindingMessage += "The system-auth prohibits password reuse for a minimum of five generations, but remembers less than 5 generations."
        }
    }
    Else {
        $FindingMessage += "The system-auth does not prohibit password reuse for a minimum of five generations."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Checking password-auth for correct settings:"
    $FindingMessage += "`r`n"

    If (($password_auth.split(":")).startswith("password") -and ($password_auth -match "remember")) {
        if ([int]((($password_auth | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "remember" }).split("=")[1]) -ge 5) {
            $passwordpass = $True
            $FindingMessage += "The password-auth prohibits password reuse for a minimum of five generations."
        }
        else {
            $FindingMessage += "The password-auth prohibits password reuse for a minimum of five generations, but remembers less than 5 generations."
        }
    }
    Else {
        $FindingMessage += "The password-auth does not prohibit password reuse for a minimum of five generations."
    }

    if ($authpass -and $passwordpass) {
        $Status = "NotAFinding"
    }
    else {
        $Status = "Open"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204423 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204423
        STIG ID    : RHEL-07-010280
        Rule ID    : SV-204423r603261_rule
        CCI ID     : CCI-000205
        Rule Name  : SRG-OS-000078-GPOS-00046
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that passwords are a minimum of 15 characters in length.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*minlen /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If ((($finding | awk '{$2=$2};1').replace(" ", "").split("="))[1] ?? 16 -le 15) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system enforces a minimum 15-character password length."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not enforce a minimum 15-character password length."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204424 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204424
        STIG ID    : RHEL-07-010290
        Rule ID    : SV-204424r880839_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not allow accounts configured with blank or null passwords.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s nullok /etc/pam.d/system-auth /etc/pam.d/password-auth)

    If ($finding) {
        $Status = "Open"
        $FindingMessage = "Null passwords can be used."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "Null passwords cannot be used."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204425 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204425
        STIG ID    : RHEL-07-010300
        Rule ID    : SV-204425r603261_rule
        CCI ID     : CCI-000766
        Rule Name  : SRG-OS-000106-GPOS-00053
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using an empty password.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*PermitEmptyPasswords /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    If ((($finding | awk '{$2=$2};1').split(" ")).ToLower() -eq "no") {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon's 'PermitEmptyPasswords' option is set to not allow empty passwords."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon's 'PermitEmptyPasswords' option is set to allow empty passwords."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204426 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204426
        STIG ID    : RHEL-07-010310
        Rule ID    : SV-204426r809190_rule
        CCI ID     : CCI-000795
        Rule Name  : SRG-OS-000118-GPOS-00060
        Rule Title : The Red Hat Enterprise Linux operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*inactive /etc/default/useradd)
    $finding ?? $($finding = "Check text: No results found.")

    If (($finding).split("=")[1] -in 0..35) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system disables account identifiers (individuals, groups, roles, and devices) after the password expires."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not disable account identifiers (individuals, groups, roles, and devices) after the password expires."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204427 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204427
        STIG ID    : RHEL-07-010320
        Rule ID    : SV-204427r880842_rule
        CCI ID     : CCI-000044, CCI-002236, CCI-002237, CCI-002238
        Rule Name  : SRG-OS-000329-GPOS-00128
        Rule Title : The Red Hat Enterprise Linux operating system must be configured to lock accounts for a minimum of 15 minutes after three unsuccessful logon attempts within a 15-minute timeframe.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s pam_faillock.so /etc/pam.d/password-auth)
    $finding ?? $($finding = "Check text: No results found.")

    $password_auth_preauth = $(grep -s -i "pam_faillock.so.*preauth" /etc/pam.d/password-auth)
    $passwordpreauthpass = $false
    $password_auth_authfail = $(grep -s -i "pam_faillock.so.*authfail" /etc/pam.d/password-auth)
    $passwordauthfailpass = $false

    $FindingMessage = "Checking password-auth for correct settings:"
    $FindingMessage += "`r`n"

    if ($password_auth_preauth){
        if ($password_auth_preauth.startswith("auth")) {
            if ((($password_auth_preauth | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "^deny" }).split("=")[1] -in 1..3) {
                if (($password_auth_preauth | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "even_deny_root" }) {
                    if ((($password_auth_preauth | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "fail_interval" }).split("=")[1] -notin 0..899) {
                        if ((($password_auth_preauth | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "unlock_time" }).split("=")[1] -notin 0..899) {
                            $passwordpreauthpass = $true
                            $FindingMessage = "The system's password-auth preauth locks an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
                        }
                        else {
                            $FindingMessage += "The system's password-auth preauth locks an account for less than 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
                        }
                    }
                    else {
                        $FindingMessage += "The system's password-auth preauth locks an account after three unsuccessful logon attempts but allows a period of less than 15 minutes."
                    }
                }
                else {
                    $FindingMessage += "The system's password-auth preauth does not lock the root account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
                }
            }
            else {
                $FindingMessage += "The system's password-auth preauth does not lock an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
            }
        }
        else {
            $FindingMessage += "The system's password-auth preauth does not lock an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
        }
    }
    else{
        $FindingMessage += "The system's password-auth preauth does not lock an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
    }

    $FindingMessage += "`r`n"

    if ($password_auth_authfail){
        if ($password_auth_authfail.startswith("auth")) {
            if ((($password_auth_authfail | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "^deny" }).split("=")[1] -in 1..3) {
                if (($password_auth_authfail | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "even_deny_root" }) {
                    if ((($password_auth_authfail | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "fail_interval" }).split("=")[1] -notin 0..899 ) {
                        if ((($password_auth_authfail | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "unlock_time" }).split("=")[1] -notin 0..899) {
                            $passwordauthfailpass = $true
                            $FindingMessage += "The system's password-auth authfail locks an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
                        }
                        else {
                            $FindingMessage += "The system's password-auth authfail locks an account for less than 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
                        }
                    }
                    else {
                        $FindingMessage += "The system's password-auth authfail locks an account after three unsuccessful logon attempts but allows a period of less than 15 minutes."
                    }
                }
                else {
                    $FindingMessage += "The system's password-auth authfail does not lock the root account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
                }
            }
            else {
                $FindingMessage += "The system's password-auth authfail does not lock an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
            }
        }
        else {
            $FindingMessage += "The system's password-auth authfail does not lock an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
        }
    }
    else {
        $FindingMessage += "The system's password-auth authfail does not lock an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
    }

    $finding_2 = $(grep -s pam_faillock.so /etc/pam.d/password-auth)
    $finding_2 ?? $($finding_2 = "Check text: No results found.")

    $system_auth_preauth = $(grep -s -i "pam_faillock.so.*preauth" /etc/pam.d/system-auth)
    $systempreauthpass = $false
    $system_auth_authfail = $(grep -s -i "pam_faillock.so.*authfail" /etc/pam.d/system-auth)
    $systemauthfailpass = $false

    $FindingMessage += "`r`n"
    $FindingMessage += "Checking system-auth for correct settings:"
    $FindingMessage += "`r`n"

    if ($system_auth_preauth){
        if ($system_auth_preauth.startswith("auth")) {
            if ((($system_auth_preauth | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "^deny" }).split("=")[1] -in 1..3) {
                if (($system_auth_preauth | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "even_deny_root" }) {
                    if ((($system_auth_preauth | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "fail_interval" }).split("=")[1] -notin 0..899) {
                        if ((($system_auth_preauth | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "unlock_time" }).split("=")[1] -notin 0..899) {
                            $systempreauthpass = $true
                            $FindingMessage += "The system's system-auth preauth locks an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
                        }
                        else {
                            $FindingMessage += "The system's system-auth preauth locks an account for less than 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
                        }
                    }
                    else {
                        $FindingMessage += "The system's system-auth preauth locks an account after three unsuccessful logon attempts but allows a period of less than 15 minutes."
                    }
                }
                else {
                    $FindingMessage += "The system's system-auth preauth does not lock the root account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
                }
            }
            else {
                $FindingMessage += "The system's system-auth preauth does not lock an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
            }
        }
        else {
            $FindingMessage += "The system's system-auth preauth does not lock an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
        }
    }
    else {
        $FindingMessage += "The system's system-auth preauth does not lock an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
    }

    $FindingMessage += "`r`n"

    if ($system_auth_authfail){
        if ($system_auth_authfail.startswith("auth")) {
            if ((($system_auth_authfail | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "^deny" }).split("=")[1] -in 1..3) {
                if (($system_auth_authfail | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "even_deny_root" }) {
                    if ((($system_auth_authfail | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "fail_interval" }).split("=")[1] -notin 0..899) {
                        if ((($system_auth_authfail | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "unlock_time" }).split("=")[1] -notin 0..899) {
                            $systemauthfailpass = $true
                            $FindingMessage += "The system's system-auth authfail locks an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
                        }
                        else {
                            $FindingMessage += "The system's system-auth authfail locks an account for less than 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
                        }
                    }
                    else {
                        $FindingMessage += "The system's system-auth authfail locks an account after three unsuccessful logon attempts but allows a period of less than 15 minutes."
                    }
                }
                else {
                    $FindingMessage += "The system's system-auth authfail does not lock the root account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
                }
            }
            else {
                $FindingMessage += "The system's system-auth authfail does not lock an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
            }
        }
        else {
            $FindingMessage += "The system's system-auth authfail does not lock an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
        }
    }
    else {
        $FindingMessage += "The system's system-auth authfail does not lock an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes."
    }

    If ($passwordpreauthpass -and $passwordauthfailpass -and $systempreauthpass -and $systemauthfailpass) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204428 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204428
        STIG ID    : RHEL-07-010330
        Rule ID    : SV-204428r880845_rule
        CCI ID     : CCI-002238
        Rule Name  : SRG-OS-000329-GPOS-00128
        Rule Title : The Red Hat Enterprise Linux operating system must lock the associated account after three unsuccessful root logon attempts are made within a 15-minute period.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s pam_faillock.so /etc/pam.d/password-auth /etc/pam.d/system-auth)
    $correct = 0

    if ($finding) {
        $finding | ForEach-Object {
            if ((($_.split(":")[1]).StartsWith("auth")) -and ($_ -match "even_deny_root")) {
                $correct++
            }
        }
    }
    else {
        $Finding = "Check text: No results found."
    }

    If ($correct -eq 4) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system automatically locks the root account until it is released by an administrator when three unsuccessful logon attempts in 15 minutes are made."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not automatically lock the root account until it is released by an administrator when three unsuccessful logon attempts in 15 minutes are made."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204429 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204429
        STIG ID    : RHEL-07-010340
        Rule ID    : SV-204429r861003_rule
        CCI ID     : CCI-002038
        Rule Name  : SRG-OS-000373-GPOS-00156
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that users must provide a password for privilege escalation.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -ir nopasswd /etc/sudoers /etc/sudoers.d/)
    $commented = 0

    If ($finding) {
        $finding | ForEach-Object {
            If (($_.split(":")[1]).StartsWith("#")) {
                $commented++
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system requires users to supply a password for privilege escalation."
    }

    if ($finding.count -ne $commented) {
        $Status = "Open"
        $FindingMessage = "The operating system does not require users to supply a password for privilege escalation."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system requires users to supply a password for privilege escalation."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204430 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204430
        STIG ID    : RHEL-07-010350
        Rule ID    : SV-204430r853885_rule
        CCI ID     : CCI-002038
        Rule Name  : SRG-OS-000373-GPOS-00156
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that users must re-authenticate for privilege escalation.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -ir "!authenticate" /etc/sudoers /etc/sudoers.d/)
    $commented = 0

    If ($finding) {
        $finding | ForEach-Object {
            If (($_.split(":")[1]).StartsWith("#")) {
                $commented++
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system requires users to reauthenticate for privilege escalation."
    }

    if ($finding.count -ne $commented) {
        $Status = "Open"
        $FindingMessage = "The operating system does not require users to reauthenticate for privilege escalation."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system requires users to reauthenticate for privilege escalation."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204431 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204431
        STIG ID    : RHEL-07-010430
        Rule ID    : SV-204431r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00226
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the delay between logon prompts following a failed console logon attempt is at least four seconds.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*fail_delay /etc/login.defs)
    $finding ?? $($finding = "Check text: No results found.")

    If ([int](($finding | awk '{$2=$2};1').split(" ")[1]) -ge 4) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system enforces a delay of at least four seconds between console logon prompts following a failed logon attempt."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not enforce a delay of at least four seconds between console logon prompts following a failed logon attempt."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204432 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204432
        STIG ID    : RHEL-07-010440
        Rule ID    : SV-204432r877377_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00229
        Rule Title : The Red Hat Enterprise Linux operating system must not allow an unattended or automatic logon to the system via a graphical user interface.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    else {
        $finding = $(grep -s -i ^[[:blank:]]*automaticloginenable /etc/gdm/custom.conf)
        $finding ?? $($finding = "Check text: No results found.")

        If (($finding.ToLower() | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq "false") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system does not allow an unattended or automatic logon to the system via a graphical user interface."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system allows an unattended or automatic logon to the system via a graphical user interface."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204433 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204433
        STIG ID    : RHEL-07-010450
        Rule ID    : SV-204433r877377_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00229
        Rule Title : The Red Hat Enterprise Linux operating system must not allow an unrestricted logon to the system.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    else {
        $finding = $(grep -s -i ^[[:blank:]]*timedloginenable /etc/gdm/custom.conf)
        $finding ?? $($finding = "Check text: No results found.")

        If (($finding.ToLower() | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq "false") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system does not allow an unrestricted logon to the system via a graphical user interface."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system allows an unrestricted logon to the system via a graphical user interface."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204434 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204434
        STIG ID    : RHEL-07-010460
        Rule ID    : SV-204434r877377_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00229
        Rule Title : The Red Hat Enterprise Linux operating system must not allow users to override SSH environment variables.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*permituserenvironment /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    If ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "no") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system does not allow users to override environment variables to the SSH daemon."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system allows users to override environment variables to the SSH daemon."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204435 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204435
        STIG ID    : RHEL-07-010470
        Rule ID    : SV-204435r877377_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00229
        Rule Title : The Red Hat Enterprise Linux operating system must not allow a non-certificate trusted host SSH logon to the system.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*hostbasedauthentication /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    If ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "no") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system does not allow a non-certificate trusted host SSH logon to the system."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system allows a non-certificate trusted host SSH logon to the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204437 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204437
        STIG ID    : RHEL-07-010481
        Rule ID    : SV-204437r603261_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080-GPOS-00048
        Rule Title : The Red Hat Enterprise Linux operating system must require authentication upon booting into single-user and maintenance modes.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i execstart /usr/lib/systemd/system/rescue.service | grep -s -i sulogin)
    $finding ?? $($finding = "Check text: No results found.")

    If ($Finding -match "/usr/sbin/sulogin") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system must require authentication upon booting into single-user and maintenance modes."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not require authentication upon booting into single-user and maintenance modes."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204438 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204438
        STIG ID    : RHEL-07-010482
        Rule ID    : SV-204438r744095_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080-GPOS-00048
        Rule Title : Red Hat Enterprise Linux operating systems version 7.2 or newer with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(Test-Path /boot/efi/EFI/centos/grub.cfg)
    $release = $(cat /etc/redhat-release)

    If ($finding) {
        $Status = "Not_Applicable"
        $FindingMessage = "This is only applicable on systems that use a basic Input/Output System BIOS."
    }
    elseif ($release.split(" ")[3] -le 7.2) {
        $finding = $release
        $Status = "Not_Applicable"
        $FindingMessage = "This is only applicable on systems running CentOS 7.2 or newer."
    }
    Else {
        $finding = $(grep -s -iw grub2_password /boot/grub2/user.cfg)
        $finding ?? $($finding = "Check text: No results found.")

        If (((($finding | awk '{$2=$2};1').replace(" ", "").split("=")).ToLower()).StartsWith("grub.pbkdf2.sha512")) {
            $Status = "NotAFinding"
            $FindingMessage = "An encrypted root password is set for booting into single-user and maintenance mode."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "An encrypted root password is not set for booting into single-user and maintenance mode."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204440 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204440
        STIG ID    : RHEL-07-010491
        Rule ID    : SV-204440r744098_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080-GPOS-00048
        Rule Title : Red Hat Enterprise Linux operating systems version 7.2 or newer using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(Test-Path /boot/efi/EFI/centos/grub.cfg)
    $release = $(cat /etc/redhat-release)

    If ($finding) {
        if ($release.split(" ")[3] -le 7.2) {
            $finding = $release
            $Status = "Not_Applicable"
            $FindingMessage = "This is only applicable on systems running CentOS 7.2 or newer."
        }
        Else {
            $finding = $(grep -s -iw grub2_password /boot/efi/EFI/centos/user.cfg)
            $finding ?? $($finding = "Check text: No results found.")

            If (((($finding | awk '{$2=$2};1').replace(" ", "").split("=")).ToLower()).StartsWith("grub.pbkdf2.sha512")) {
                $Status = "NotAFinding"
                $FindingMessage = "An encrypted root password is set for booting into single-user and maintenance mode."
            }
            Else {
                $Status = "Open"
                $FindingMessage = "An encrypted root password is not set for booting into single-user and maintenance mode."
            }
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "This is only applicable on systems that use UEFI."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204441 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204441
        STIG ID    : RHEL-07-010500
        Rule ID    : SV-204441r818813_rule
        CCI ID     : CCI-000766
        Rule Name  : SRG-OS-000104-GPOS-00051
        Rule Title : The Red Hat Enterprise Linux operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multifactor authentication.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(authconfig --test | grep -s -i "pam_pkcs11 is enabled")
    $finding_2 = $(authconfig --test | grep -s -i "smartcard removal action")
    $finding_3 = $(authconfig --test | grep -s -i "smartcard module")

    If ($Finding) {
        if (($finding_2 | awk '{$2=$2};1').split("=")[1]) {
            if (($finding_3 | awk '{$2=$2};1').split("=")[1]) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system requires multifactor authentication to uniquely identify organizational users using multifactor authentication."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not require multifactor authentication to uniquely identify organizational users using multifactor authentication as a smartcard module is missing."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not require multifactor authentication to uniquely identify organizational users using multifactor authentication as a smartcard removal action is missing."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not require multifactor authentication to uniquely identify organizational users using multifactor authentication."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204442 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204442
        STIG ID    : RHEL-07-020000
        Rule ID    : SV-204442r603261_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095-GPOS-00049
        Rule Title : The Red Hat Enterprise Linux operating system must not have the rsh-server package installed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa rsh-server)

    If ($Finding) {
        $Status = "Open"
        $FindingMessage = "The rsh-server package is installed."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The rsh-server package is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204443 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204443
        STIG ID    : RHEL-07-020010
        Rule ID    : SV-204443r603261_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095-GPOS-00049
        Rule Title : The Red Hat Enterprise Linux operating system must not have the ypserv package installed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa ypserv)

    If ($Finding) {
        $Status = "Open"
        $FindingMessage = "The ypserv package is installed."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The ypserv package is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204444 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204444
        STIG ID    : RHEL-07-020020
        Rule ID    : SV-204444r877392_rule
        CCI ID     : CCI-002165, CCI-002235
        Rule Name  : SRG-OS-000324-GPOS-00125
        Rule Title : The Red Hat Enterprise Linux operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(semanage login -l)

    $Status = "Not_Reviewed"
    $FindingMessage = "Verify the operating system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures."
    $FindingMessage += "`r`n"
    $FindingMessage += "Get a list of authorized users (other than System Administrator and guest accounts) for the system and check the list against the system."

    $FindingMessage += "`r`n"
    $FindingMessage += "Per OPORD 16-0080, the preferred endpoint security tool is Endpoint Security for Linux (ENSL) in conjunction with SELinux."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204445 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204445
        STIG ID    : RHEL-07-020030
        Rule ID    : SV-204445r902698_rule
        CCI ID     : CCI-001744
        Rule Name  : SRG-OS-000363-GPOS-00150
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that a file integrity tool verifies the baseline operating system configuration at least weekly.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa aide)
    $finding_2 = $(ls -al /etc/cron.*)
    $finding_3 = $(cat /etc/crontab)
    $finding_4 = $(cat /var/spool/cron/root)

    If ($Finding) {
        $FindingMessage = "AIDE is installed."
    }
    Else {
        $FindingMessage = "AIDE is not installed, ask the SA how file integrity checks are performed on the system."
    }

    $Status = "Not_Reviewed"

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_4
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204446 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204446
        STIG ID    : RHEL-07-020040
        Rule ID    : SV-204446r902701_rule
        CCI ID     : CCI-001744
        Rule Name  : SRG-OS-000363-GPOS-00150
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that designated personnel are notified if baseline configurations are changed in an unauthorized manner.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa aide)
    $finding_2 = $(ls -al /etc/cron.*)
    $finding_3 = $(cat /etc/crontab)
    $finding_4 = $(cat /var/spool/cron/root)

    If ($Finding) {
        $FindingMessage = "AIDE is installed."
    }
    Else {
        $FindingMessage = "AIDE is not installed, ask the SA how file integrity checks are performed on the system."
    }

    $Status = "Not_Reviewed"

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_4
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204447 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204447
        STIG ID    : RHEL-07-020050
        Rule ID    : SV-204447r877463_rule
        CCI ID     : CCI-001749
        Rule Name  : SRG-OS-000366-GPOS-00153
        Rule Title : The Red Hat Enterprise Linux operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*gpgcheck /etc/yum.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system prevents the installation of patches, service packs, device drivers, or operating system components from a repository without verification that they have been digitally signed using a certificate that is recognized and approved by the organization."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not prevent the installation of patches, service packs, device drivers, or operating system components from a repository without verification that they have been digitally signed using a certificate that is recognized and approved by the organization."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204448 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204448
        STIG ID    : RHEL-07-020060
        Rule ID    : SV-204448r877463_rule
        CCI ID     : CCI-001749
        Rule Name  : SRG-OS-000366-GPOS-00153
        Rule Title : The Red Hat Enterprise Linux operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*localpkg_gpgcheck /etc/yum.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system prevents the installation of patches, service packs, device drivers, or operating system components of local packages without verification that they have been digitally signed using a certificate that is recognized and approved by the organization."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not prevent the installation of patches, service packs, device drivers, or operating system components of local packages without verification that they have been digitally signed using a certificate that is recognized and approved by the organization."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204449 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204449
        STIG ID    : RHEL-07-020100
        Rule ID    : SV-204449r853891_rule
        CCI ID     : CCI-000366, CCI-000778, CCI-001958
        Rule Name  : SRG-OS-000114-GPOS-00059
        Rule Title : The Red Hat Enterprise Linux operating system must be configured to disable USB mass storage.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -r -v "^\s*#" /etc/modprobe.d/ | grep -s -i usb-storage | grep -s -i "/bin/true")
    $finding_2 = $(grep -s -r -v "^\s*#" /etc/modprobe.d/ | grep -s -i usb-storage | grep -s -i "blacklist")

    If (($finding | awk '{$2=$2};1') -eq "install usb-storage /bin/true") {
        $FindingMessage = "The operating system disables the ability to load the USB Storage kernel module."
    }
    Else {
        $FindingMessage = "The operating system does not disable the ability to load the USB Storage kernel module."
    }

    $FindingMessage += "`r`n"

    If (($finding_2 | awk '{$2=$2};1') -eq "blacklist usb-storage") {
        $FindingMessage += "The operating system disables the ability to use USB mass storage devices."
    }
    Else {
        $FindingMessage += "The operating system does not disable the ability to use USB mass storage devices."
    }

    if ($finding -and $finding_2) {
        $Status = "NotAFinding"
    }
    else {
        $status = "Open"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204450 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204450
        STIG ID    : RHEL-07-020101
        Rule ID    : SV-204450r853892_rule
        CCI ID     : CCI-001958
        Rule Name  : SRG-OS-000378-GPOS-00163
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the Datagram Congestion Control Protocol (DCCP) kernel module is disabled unless required.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -r -v "^\s*#" /etc/modprobe.d/ | grep -s -i dccp | grep -s -i "/bin/true")
    $finding_2 = $(grep -s -r -v "^\s*#" /etc/modprobe.d/ | grep -s -i dccp | grep -s -i "blacklist")

    If (($finding | awk '{$2=$2};1') -eq "install dccp /bin/true") {
        $FindingMessage = "The operating system disables the ability to load the DCCP kernel module."
    }
    Else {
        $FindingMessage = "The operating system does not disable the ability to load the DCCP kernel module."
    }

    $FindingMessage += "`r`n"

    If (($finding_2 | awk '{$2=$2};1') -eq "blacklist dccp") {
        $FindingMessage += "The operating system disables the ability to use the DCCP kernel module."
    }
    Else {
        $FindingMessage += "The operating system does not disable the ability to use the DCCP kernel module."
    }

    if ($finding -and $finding_2) {
        $Status = "NotAFinding"
    }
    else {
        $status = "Open"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204451 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204451
        STIG ID    : RHEL-07-020110
        Rule ID    : SV-204451r853893_rule
        CCI ID     : CCI-000366, CCI-000778, CCI-001958
        Rule Name  : SRG-OS-000114-GPOS-00059
        Rule Title : The Red Hat Enterprise Linux operating system must disable the file system automounter unless required.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl | grep autofs && systemctl status autofs)

    If ($finding -match "Active: active") {
        $Status = "Open"
        $FindingMessage = "The operating system does not disable the ability to automount devices."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system disables the ability to automount devices."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204452 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204452
        STIG ID    : RHEL-07-020200
        Rule ID    : SV-204452r853894_rule
        CCI ID     : CCI-002617
        Rule Name  : SRG-OS-000437-GPOS-00194
        Rule Title : The Red Hat Enterprise Linux operating system must remove all software components after updated versions have been installed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*clean_requirements_on_remove /etc/yum.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system removes all software components after updated versions have been installed."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not remove all software components after updated versions have been installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204453 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204453
        STIG ID    : RHEL-07-020210
        Rule ID    : SV-204453r853895_rule
        CCI ID     : CCI-002165, CCI-002696
        Rule Name  : SRG-OS-000445-GPOS-00199
        Rule Title : The Red Hat Enterprise Linux operating system must enable SELinux.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(getenforce)

    If ($finding -eq "Enforcing") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system verifies correct operation of all security functions."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not verify correct operation of all security functions."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Per OPORD 16-0080, the preferred endpoint security tool is Endpoint Security for Linux (ENSL) in conjunction with SELinux."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204454 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204454
        STIG ID    : RHEL-07-020220
        Rule ID    : SV-204454r853896_rule
        CCI ID     : CCI-002165, CCI-002696
        Rule Name  : SRG-OS-000445-GPOS-00199
        Rule Title : The Red Hat Enterprise Linux operating system must enable the SELinux targeted policy.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(sestatus)
    $finding_2 = $(grep -s -i "selinuxtype" /etc/selinux/config | grep -s -v '^#')
    $finding_2 ?? $($finding_2 = "Check text: No results found.")

    If (($finding | awk '{$2=$2};1') -match "Loaded policy name: targeted") {
        if (($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq "targeted") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system verifies correct operation of all security functions."
        }
        else {
            $Status = "Open"
            $FindingMessage = "'SELINUXTYPE' is not set to 'targeted'."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "'SELinux' is not enforcing the targeted policy."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Per OPORD 16-0080, the preferred endpoint security tool is Endpoint Security for Linux (ENSL) in conjunction with SELinux."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $Finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204455 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204455
        STIG ID    : RHEL-07-020230
        Rule ID    : SV-204455r833106_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled on the command line.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl status ctrl-alt-del.target)

    If ($finding -match "Loaded: masked") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed. ctrl-alt-del.target is not masked."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204456 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204456
        STIG ID    : RHEL-07-020231
        Rule ID    : SV-204456r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled in the Graphical User Interface.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    else {
        $finding = $(grep -s -ir ^logout /etc/dconf/db/local.d/)
        $finding ?? $($finding = "Check text: No results found.")

        If ((($finding | awk '{$2=$2};1').replace(" ", "").split(":")[1]).ToLower() -eq "logout=''") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204457 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204457
        STIG ID    : RHEL-07-020240
        Rule ID    : SV-204457r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00228
        Rule Title : The Red Hat Enterprise Linux operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*umask /etc/login.defs)
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').split(" ")[1] -eq "077") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not define default permissions for all authenticated users in such a way that the user can only read and modify their own files."
        if ((($finding | awk '{$2=$2};1').split(" ")[1] -eq "000")) {
            $FindingMessage += "`r`n"
            $FindingMessage += "The 'UMASK' variable is set to '000, therefore this is a finding with the severity raised to a CAT I."
            $Severity = "CAT_I"
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204458 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204458
        STIG ID    : RHEL-07-020250
        Rule ID    : SV-204458r744100_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be a vendor supported release.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /etc/redhat-release)

    If ($finding.split(" ")[3] -ge 7.9) {
        $Status = "NotAFinding"
        $FindingMessage = "The version of the operating system is vendor supported."
    }
    Else {
        $Status = "Not_Reviewed"
        $FindingMessage = "The version of the operating system is not 7.9 or greater."
        $FindingMessage += "`r`n"
        $FindingMessage += "Check if the release is not supported by the vendor."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204459 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204459
        STIG ID    : RHEL-07-020260
        Rule ID    : SV-204459r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system security patches and updates must be installed and up to date.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(yum history list)

    $Status = "Not_Reviewed"
    $FindingMessage = "Verify the operating system security patches and updates are installed and up to date."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204460 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204460
        STIG ID    : RHEL-07-020270
        Rule ID    : SV-204460r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not have unnecessary accounts.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /etc/passwd)

    $Status = "Not_Reviewed"
    $FindingMessage = "Verify all accounts on the system are assigned to an active system, application, or user account."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204461 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204461
        STIG ID    : RHEL-07-020300
        Rule ID    : SV-204461r603261_rule
        CCI ID     : CCI-000764
        Rule Name  : SRG-OS-000104-GPOS-00051
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all Group Identifiers (GIDs) referenced in the /etc/passwd file are defined in the /etc/group file.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(pwck -r)

    $Status = "Not_Reviewed"
    $FindingMessage = "Verify all GIDs referenced in the '/etc/passwd' file are defined in the '/etc/group' file."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204462 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204462
        STIG ID    : RHEL-07-020310
        Rule ID    : SV-204462r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the root account must be the only account having unrestricted access to the system.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
awk -F: '$3 == 0 {print $1}' /etc/passwd
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding -eq "root") {
        $Status = "NotAFinding"
        $FindingMessage = "No accounts other than root have a UID of '0'."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Accounts other than root have a UID of '0'."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204463 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204463
        STIG ID    : RHEL-07-020320
        Rule ID    : SV-204463r853897_rule
        CCI ID     : CCI-002165
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all files and directories have a valid owner.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(df -Tl | awk '(NR>1 && $2!="devtmpfs" && $2!="tmpfs" ){print $7}' | xargs -I% find "%" -xdev -not -path "/sys/*" -not -path "/proc/*" -not -path "/run/*" -nouser)

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "Accessible files and directories on the system do not have a valid owner."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "All accessible files and directories on the system have a valid owner."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204464 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204464
        STIG ID    : RHEL-07-020330
        Rule ID    : SV-204464r853898_rule
        CCI ID     : CCI-002165
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all files and directories have a valid group owner.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(df -Tl | awk '(NR>1 && $2!="devtmpfs" && $2!="tmpfs" ){print $7}' | xargs -I% find "%" -xdev -not -path "/sys/*" -not -path "/proc/*" -not -path "/run/*" -nogroup)

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "Accessible files and directories on the system do not have a valid group."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "Accessible files and directories on the system have a valid group."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204466 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204466
        STIG ID    : RHEL-07-020610
        Rule ID    : SV-204466r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all local interactive user accounts, upon creation, are assigned a home directory.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*create_home /etc/login.defs)
    $finding ?? $($finding = "Check text: No results found.")

    If ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "yes") {
        $Status = "NotAFinding"
        $FindingMessage = "All local interactive users on the system are assigned a home directory upon creation."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "All local interactive users on the system are not assigned a home directory upon creation."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204467 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204467
        STIG ID    : RHEL-07-020620
        Rule ID    : SV-204467r603826_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all local interactive users have a home directory assigned and defined in the /etc/passwd file.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }
    $finding_2 = (pwck -r)
    $found = 0

    $finding | ForEach-Object {
        if ($finding_2 -match ($_.split(":")[0])) {
            $found++
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "Local interactive users on the system have a home directory assigned and the directory exists."
    }
    else {
        $Status = "Open"
        $FindingMessage = "Local interactive users on the system do not have a home directory assigned and/or the directory does not exist."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204468 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204468
        STIG ID    : RHEL-07-020630
        Rule ID    : SV-204468r603828_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories have mode 0750 or less permissive.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $userlist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $userlist = "Unable to create temp file to process check."
        $finding = $userlist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    $finding = $(ls -ld $userlist)
    $found = 0

    $finding | ForEach-Object {
        if ((ConvertModeStringtoDigits $_.split(" ")[0]) -gt 750) {
            $found++
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The assigned home directory of all local interactive users has a mode of '0750' or less permissive."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The assigned home directory of all local interactive users does not have a mode of '0750' or less permissive."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204469 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204469
        STIG ID    : RHEL-07-020640
        Rule ID    : SV-204469r603830_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories are owned by their respective users.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $userpathlist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $userpathlist = "Unable to create temp file to process check."
        $finding = $userpathlist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    Foreach ($userpath in $userpathlist) {
        $finding = $(ls -ld $userpath)
        $found = 0

        $finding | ForEach-Object {
            if (($_ | awk '{$2=$2};1').split(" ")[2] -ne ((grep -s $userpath /etc/passwd).split(":")[0])) {
                $FindingDetails += $(FormatFinding $finding) | Out-String
                $found++
            }
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The assigned home directory of all local interactive are owned by the interactive user."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The assigned home directory of all local interactive are not owned by the interactive user."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204470 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204470
        STIG ID    : RHEL-07-020650
        Rule ID    : SV-204470r880764_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories are group-owned by the home directory owners primary group.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $userlist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $userlist = "Unable to create temp file to process check."
        $finding = $userlist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    $listing = $(ls -ld $userlist)

    $found = 0

    ($listing | awk '{$2=$2};1') | ForEach-Object {
        if ((((grep $(grep ($_.split(" ")[2]) /etc/passwd | awk -F: '{print $4}') /etc/group).split(":"))[0]) -ne $_.split(" ")[3]){
            $finding = $_
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The assigned home directory of all local interactive users is group-owned by that user's primary GID."
    }
    else {
        $finding = $finding_2
        $FindingDetails += $(FormatFinding $finding) | Out-String
        $Status = "Open"
        $FindingMessage = "The assigned home directory of all local interactive users is not group-owned by that user's primary GID."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204471 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204471
        STIG ID    : RHEL-07-020660
        Rule ID    : SV-204471r744105_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories have a valid owner.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $userlist = $(cut -d: -f 1,3,6 /etc/passwd | egrep -s -i ":[1-4][0-9]{3}")
    $found = 0

    Foreach ($user in $userlist) {
        if ($user.split(":")[2] -match "home") {
            $better_finding = $(ls -lLR $user.split(":")[2] | egrep -s -i "^d|^-")

            Foreach ($file in $better_finding) {
                if ($user.split(":")[0] -ne ($file | awk '{$2=$2};1').split(" ")[2]) {
                    $finding = $user
                    $FindingDetails += $(FormatFinding $finding) | Out-String
                    $finding = $file
                    $FindingDetails += $(FormatFinding $finding) | Out-String
                    $found++
                }
            }
        }
        else {
            $finding = $user
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $finding = "$user was skipped due to non-standard home directory path.  Manual verification required."
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "All files and directories in a local interactive user's home directory are owned."
    }
    else {
        $Status = "Open"
        $FindingMessage = "All files and directories in a local interactive user's home directory are not owned."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204472 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204472
        STIG ID    : RHEL-07-020670
        Rule ID    : SV-204472r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $userlist = $(cut -d: -f 1,3,6 /etc/passwd | egrep -s -i ":[1-4][0-9]{3}")
    $found = 0

    foreach ($user in $userlist) {
        if ($user.split(":")[2] -match "home") {
            $better_finding = $(ls -lLR $user.split(":")[2] | egrep -s -i "^d|^-")

            Foreach ($file in $better_finding) {
                $grouptest = $(getent group ($file | awk '{$2=$2};1').split(" ")[3])
                if ((!($grouptest | Select-String $user.split(":")[0]))){
                    if ($user.split(":")[0] -ne ($file | awk '{$2=$2};1').split(" ")[3]) {
                        $finding = $user
                        $FindingDetails += $(FormatFinding $finding) | Out-String
                        $finding = $file
                        $FindingDetails += $(FormatFinding $finding) | Out-String
                        $found++
                    }
                }
            }
        }
        else {
            $finding = $user
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $finding = "$user was skipped due to non-standard home directory path.  Manual verification required."
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "All files and directories in a local interactive user home directory are group-owned by a group the user is a member of."
    }
    else {
        $Status = "Open"
        $FindingMessage = "All files and directories in a local interactive user home directory are not group-owned by a group the user is a member of."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204473 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204473
        STIG ID    : RHEL-07-020680
        Rule ID    : SV-204473r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories have a mode of 0750 or less permissive.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $userlist = $(cut -d: -f 1,3,6 /etc/passwd | egrep -s -i ":[1-4][0-9]{3}")
    $found = 0

    foreach ($user in $userlist) {
        if ($user.split(":")[2] -match "home") {
            $better_finding = $(ls -lLR $user.split(":")[2] | egrep -s -i "^d|^-")

            Foreach ($file in $better_finding) {
                if ((ConvertModeStringtoDigits $file.split(" ")[0]) -gt 750) {
                    $finding = $file
                    $FindingDetails += $(FormatFinding $finding) | Out-String
                    $found++
                }
            }
        }
        else {
            $finding = $user
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $finding = "$user was skipped due to non-standard home directory path.  Manual verification required."
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "All files and directories contained in a local interactive user home directory, excluding local initialization files, have a mode of '0750' or less."
    }
    else {
        $Status = "Open"
        $FindingMessage = "All files and directories contained in a local interactive user home directory, excluding local initialization files, do not have a mode of '0750' or less."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204474 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204474
        STIG ID    : RHEL-07-020690
        Rule ID    : SV-204474r603834_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all local initialization files for interactive users are owned by the home directory user or root.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $userlist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $userlist = "Unable to create temp file to process check."
        $finding = $userlist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    $found = 0

    foreach ($user in $userlist) {
        $filelist = $(ls -lA $user.split(" ")[2]) | Where-Object {$_ -match "bash_profile|bashrc|profile|bash_login"}

        Foreach ($file in $filelist) {
            if (($file.split(" ")[3] -ne $user.split(" ")[3]) -or ($user.split(" ")[3] -eq "root")) {
                $finding = $file
                $FindingDetails += $(FormatFinding $finding) | Out-String
                $found++
            }
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The local initialization files of all local interactive users are owned by that user or root."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The local initialization files of all local interactive users are not owned by that user or root."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204475 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204475
        STIG ID    : RHEL-07-020700
        Rule ID    : SV-204475r603836_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all local initialization files for local interactive users are be group-owned by the users primary group or root.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
awk -F: '($4>=1000)&&($7 !~ /nologin/){print $1,$4,$6}' /etc/passwd
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $userlist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $userlist = "Unable to create temp file to process check."
        $finding = $userlist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    $found = 0

    foreach ($user in $userlist) {
        $better_finding = $(find $user.split(" ")[2] -xdev -maxdepth 1 -type f -name ".*") | Where-Object {$_ -match "bash_profile|bashrc|profile|bash_login"}
        $filelist = $better_finding | ForEach-Object { ls -Al $_  }

        Foreach ($file in $filelist) {
            $grouptest = $(getent group ($file | awk '{$2=$2};1').split(" ")[3])
            if (!($grouptest | Select-String $user.split(" ")[0])){
                if (($file | awk '{$2=$2};1').split(" ")[2] -ne ($file | awk '{$2=$2};1').split(" ")[3]) {
                    $finding = $user
                    $FindingDetails += $(FormatFinding $finding) | Out-String
                    $finding = $file
                    $FindingDetails += $(FormatFinding $finding) | Out-String
                    $found++
                }
            }
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The local initialization files of all local interactive users are group-owned by that user's primary Group Identifier (GID)."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The local initialization files of all local interactive users are not group-owned by that user's primary Group Identifier (GID)."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204476 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204476
        STIG ID    : RHEL-07-020710
        Rule ID    : SV-204476r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all local initialization files have mode 0740 or less permissive.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $userlist = $(cut -d: -f 1,3,6 /etc/passwd | egrep -s -i ":[1-4][0-9]{3}")
    $found = 0

    foreach ($user in $userlist) {
        if ($user.split(":")[2] -match "home") {
            $better_finding = $(find $user.split(":")[2] -xdev -type f -name ".*") | Where-Object {$_ -match "bash_profile|bashrc|profile|bash_login"}
            $filelist = $better_finding | ForEach-Object { ls -Al $_ }

            Foreach ($file in $filelist) {
                if ((ConvertModeStringtoDigits $file.split(" ")[0]) -gt 740) {
                    $finding = $file
                    $FindingDetails += $(FormatFinding $finding) | Out-String
                    $found++
                }
            }
        }
        else {
            $finding = $user
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $finding = "$user was skipped due to non-standard home directory path.  Manual verification required."
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "All local initialization files have a mode of '0740' or less permissive."
    }
    else {
        $Status = "Open"
        $FindingMessage = "All local initialization files do not have a mode of '0740' or less permissive."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204477 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204477
        STIG ID    : RHEL-07-020720
        Rule ID    : SV-204477r792828_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all local interactive user initialization files executable search paths contain only paths that resolve to the users home directory.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $userlist = $(cut -d: -f 1,3,6 /etc/passwd | egrep -s -i ":[1-4][0-9]{3}")
    $found = 0

    foreach ($user in $userlist) {
        $better_finding = $(find $user.split(":")[2] -xdev -maxdepth 1 -type f -name ".*") | Where-Object {$_ -match "bash_profile|bashrc|profile|bash_login"}
        $filelist = $better_finding | ForEach-Object { grep -s -i "path=" $_ }

        if ($filelist) {
            $paths = ((($filelist.replace("PATH=","")).split(":")).replace('"','')).Trim()
            $paths.replace("$", "") | ForEach-Object {
                if (!(($_.ToUpper()).Startswith("HOME") -or ($_.ToUpper()).StartsWith("PATH"))) {
                    $finding = $_
                    $FindingDetails += $finding | Out-String
                    $found++
                }
            }
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "All local interactive user initialization files' executable search path statements do not contain statements that will reference a working directory other than the users' home directory."
    }
    else {
        $Status = "Open"
        $FindingMessage = "All local interactive user initialization files' executable search path statements contain statements that will reference a working directory other than the users' home directory."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204478 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204478
        STIG ID    : RHEL-07-020730
        Rule ID    : SV-204478r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that local initialization files do not execute world-writable programs.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
df -Tl | awk '(NR>1 && $2!="devtmpfs" && $2!="tmpfs" ){print $7}' | xargs -I% find "%" -xdev -not -path "/sys/*" -not -path "/proc/*" -not -path "/run/*" -perm -002 -type f -exec ls -ld {} \;
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $filelist = $(sh $temp_file)
        Remove-Item $temp_file
        $found = 0
    }
    else {
        $filelist = "Unable to create temp file to process check."
        $finding = $filelist
        $FindingDetails += $(FormatFinding $finding) | Out-String
        $found = 1
    }

    if ($filelist.count -eq 0) {
        $found = 0
        $FindingDetails += "Check text: No results found."
        $FindingDetails += "`r`n"
    }

    $filelist | ForEach-Object {
        $finding = $_
        $FindingDetails += $(FormatFinding $finding) | Out-String

        if (grep -s $_ /home/*/.* --directories=skip) {
            $found++
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "Local initialization files do not execute world-writable programs."
    }
    else {
        $Status = "Open"
        $FindingMessage = "Local initialization files execute world-writable programs."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204479 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204479
        STIG ID    : RHEL-07-020900
        Rule ID    : SV-204479r853899_rule
        CCI ID     : CCI-000318, CCI-000368, CCI-001812, CCI-001813, CCI-001814
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all system device files are correctly labeled to prevent unauthorized modification.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command_1 = @'
find /dev -xdev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n"
'@
    $command_2 = @'
find /dev -xdev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n"
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command_1 > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command_2 > $temp_file
        $finding_2 = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding_2 = "Unable to create temp file to process check."
    }

    If ($Finding -or $finding_2) {
        $Status = "Open"
        $FindingMessage = "All system device files are not correctly labeled to prevent unauthorized modification."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "All system device files are correctly labeled to prevent unauthorized modification."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204480 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204480
        STIG ID    : RHEL-07-021000
        Rule ID    : SV-204480r603838_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that file systems containing user home directories are mounted to prevent files with the setuid and setgid bit set from being executed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $userlist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $userlist = "Unable to create temp file to process check."
        $finding = $userlist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    if ($userlist[0].GetType().Name -eq "Char"){
        $finding = $(grep -s ($userlist.split("/")[1]) /etc/fstab | grep -s -i "^/dev\|^UUID")
    }
    else{
        $finding = $(grep -s ($userlist[0].split("/")[1]) /etc/fstab | grep -s -i "^/dev\|^UUID")
    }
    $finding ?? $($finding = "Check text: No results found.")

    If ($Finding -match "nosuid") {
        $Status = "NotAFinding"
        $FindingMessage = "File systems that contain user home directories are mounted with the 'nosuid' option."
    }
    Elseif (!($finding)) {
        $Status = "NotAFinding"
        $FindingMessage = "File systems does not have a separate mount for home directories."
    }
    else {
        $Status = "Open"
        $FindingMessage = "File systems that contain user home directories are not mounted with the 'nosuid' option."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204481 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204481
        STIG ID    : RHEL-07-021010
        Rule ID    : SV-204481r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $fstab = $(cat /etc/fstab)
    $removabledrives = $(lsblk -o NAME,RM,MOUNTPOINT | grep -s -w 1 | grep -s -vE "sr|loop" | awk '{if ($3) print $3;}')
    $found = 0

    if ($removabledrives.count -gt 0) {
        foreach ($removabledrive in $removabledrives) {
            foreach ($line in $fstab) {
                $finding = $line
                $FindingDetails += $(FormatFinding $finding) | Out-String
                if (($line -match "nosuid") -and ($line | Select-String $removabledrive)) {
                    $found++
                }
            }
        }
    }

    If ($found -eq $removabledrives.count) {
        $Status = "NotAFinding"
        $FindingMessage = "File systems that are used for removable media are mounted with the 'nosuid' option."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "File systems that are used for removable media are not mounted with the 'nosuid' option."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204482 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204482
        STIG ID    : RHEL-07-021020
        Rule ID    : SV-204482r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must prevent files with the setuid and setgid bit set from being executed on file systems that are being imported via Network File System (NFS).
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $fstab = $(grep -s nfs /etc/fstab | grep -v "^#")
    $found = 0

    foreach ($line in $fstab) {
        $finding = $line
        $FindingDetails += $(FormatFinding $finding) | Out-String
        if ($line -match "nosuid") {
            $found++
        }
    }

    If ($found -ne $fstab.count) {
        $Status = "Open"
        $FindingMessage = "File systems that are being NFS imported are not configured with the 'nosuid' option."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "File systems that are being NFS imported are configured with the 'nosuid' option."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204483 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204483
        STIG ID    : RHEL-07-021021
        Rule ID    : SV-204483r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must prevent binary files from being executed on file systems that are being imported via Network File System (NFS).
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $fstab = $(grep -s nfs /etc/fstab | grep -v "^#")
    $found = 0

    foreach ($line in $fstab) {
        $finding = $line
        $FindingDetails += $(FormatFinding $finding) | Out-String
        if ($line -match "noexec") {
            $found++
        }
    }

    If ($found -ne $fstab.count) {
        $Status = "Open"
        $FindingMessage = "File systems that are being NFS imported are not configured with the 'noexec' option."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "File systems that are being NFS imported are configured with the 'noexec' option."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204486 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204486
        STIG ID    : RHEL-07-021024
        Rule ID    : SV-204486r853900_rule
        CCI ID     : CCI-001764
        Rule Name  : SRG-OS-000368-GPOS-00154
        Rule Title : The Red Hat Enterprise Linux operating system must mount /dev/shm with secure options.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $fstab = $(cat /etc/fstab | grep -s /dev/shm | grep -v "^#")
    $found = 0

    if ($fstab) {
        foreach ($line in $fstab) {
            $finding = $line
            if (($line -match "nodev") -and ($line -match "nosuid") -and ($line -match "noexec")) {
                $found++
            }
            else {
                $FindingDetails += $(FormatFinding $finding) | Out-String
            }
        }

        If ($found -eq 0) {
            $Status = "Open"
            $FindingMessage = "The 'nodev','nosuid', and 'noexec' options are not configured for /dev/shm."
        }
        Else {
            $Status = "NotAFinding"
            $FindingMessage = "The 'nodev','nosuid', and 'noexec' options are configured for /dev/shm."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "'/dev/shm' is not listed in /etc/fstab."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204487 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204487
        STIG ID    : RHEL-07-021030
        Rule ID    : SV-204487r744106_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all world-writable directories are group-owned by root, sys, bin, or an application group.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $partitions = $(lsblk -o MOUNTPOINT | awk '{if ($1) print $1;}' | grep -s -v MOUNTPOINT)

    $partitions | ForEach-Object {
        $finding = $(find $_ -xdev -type d -perm -0002 -gid +999 -print)
        if ($finding) {
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    If ($found -gt 0) {
        $Status = "Open"
        $FindingMessage = "All world-writable directories are not group-owned by root, sys, bin, or an application group."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "All world-writable directories are group-owned by root, sys, bin, or an application group."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204488 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204488
        STIG ID    : RHEL-07-021040
        Rule ID    : SV-204488r861006_rule
        CCI ID     : CCI-000318, CCI-000368, CCI-001812, CCI-001813, CCI-001814
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must set the umask value to 077 for all local interactive user accounts.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $userlist = $(cut -d: -f 1,3,6 /etc/passwd | egrep -s -i ":[1-4][0-9]{3}")
    $found = 0

    $userlist | ForEach-Object {
        if ($_.split(":")[2] -match "home") {
            $better_finding = $(find $_.split(":")[2] -xdev -type f -name ".*")
            $finding = $better_finding | ForEach-Object { grep -s -i umask $_ | grep -v '.bash_history' }

            $finding | ForEach-Object {
                if (($_ | awk '{$2=$2};1').split(" ")[1] -lt 077 ) {
                    $FindingDetails += $(FormatFinding $finding) | Out-String
                    $found++
                }
            }
        }
        else {
            $finding = $_
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $finding = "$_ was skipped due to non-standard home directory path.  Manual verification required."
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    If ($found -gt 0) {
        $Status = "Open"
        $FindingMessage = "The default umask for all local interactive users is less permissive than '077'."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The default umask for all local interactive users is '077'."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204489 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204489
        STIG ID    : RHEL-07-021100
        Rule ID    : SV-204489r744109_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must have cron logging implemented.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf)
    $finding ?? $($finding = "Check text: No results found.")
    $finding_2 = $(grep -s messages /etc/rsyslog.conf /etc/rsyslog.d/*.conf)

    If (($finding -match "/var/log/cron.log") -or ($finding -match "/var/log/messages") -or ((($finding_2 | awk '{$2=$2};1').replace(" ", "")) -eq "*.*/var/log/messages")) {
        $Status = "NotAFinding"
        $FindingMessage = "'rsyslog' is configured to log cron events."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "'rsyslog' is not configured to log cron events."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204490 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204490
        STIG ID    : RHEL-07-021110
        Rule ID    : SV-204490r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the cron.allow file, if it exists, is owned by root.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(ls -al /etc/cron.allow)
    if ($Finding) {
        If (($finding | awk '{$2=$2};1').split(" ")[2] -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The 'cron.allow' file is owned by root."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The 'cron.allow' file is not owned by root."
        }
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The 'cron.allow' file does not exist."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204491 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204491
        STIG ID    : RHEL-07-021120
        Rule ID    : SV-204491r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the cron.allow file, if it exists, is group-owned by root.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(ls -al /etc/cron.allow)
    if ($finding) {
        If (($finding | awk '{$2=$2};1').split(" ")[3] -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The 'cron.allow' file is owned by root."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The 'cron.allow' file is not owned by root."
        }
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The 'cron.allow' file does not exist."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204492 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204492
        STIG ID    : RHEL-07-021300
        Rule ID    : SV-204492r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must disable Kernel core dumps unless needed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl | grep kdump.service && systemctl status kdump.service)

    If ($finding -match "Active: active") {
        $Status = "Open"
        $FindingMessage = "Kernel core dumps are not disabled."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "Kernel core dumps are disabled."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204493 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204493
        STIG ID    : RHEL-07-021310
        Rule ID    : SV-204493r603840_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that a separate file system is used for user home directories (such as /home or an equivalent).
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6,$7}' /etc/passwd
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $userlist = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $userlist = "Unable to create temp file to process check."
        $finding = $userlist
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }

    $finding = $(grep -s (($userlist | awk '{$2=$2};1').split(" ")[2].split("/")[1]) /etc/fstab)

    if ($finding) {
        $Status = "NotAFinding"
        $FindingMessage = "A separate file system/partition has been created for non-privileged local interactive user home directories."
    }
    else {
        $Status = "Open"
        $FindingMessage = "A separate file system/partition has not been created for non-privileged local interactive user home directories."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204494 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204494
        STIG ID    : RHEL-07-021320
        Rule ID    : SV-204494r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must use a separate file system for /var.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s /var /etc/fstab | grep -v "^#")

    if ($finding) {
        $Status = "NotAFinding"
        $FindingMessage = "A separate file system/partition has been created for '/var'."
    }
    else {
        $Status = "Open"
        $FindingMessage = "A separate file system/partition has not been created for '/var'."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204495 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204495
        STIG ID    : RHEL-07-021330
        Rule ID    : SV-204495r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must use a separate file system for the system audit data path.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s /var/log/audit /etc/fstab | grep -v "^#")

    if ($finding) {
        $Status = "NotAFinding"
        $FindingMessage = "A separate file system/partition has been created for '/var/log/audit'."
    }
    else {
        $Status = "Open"
        $FindingMessage = "A separate file system/partition has not been created for '/var/log/audit'."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204496 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204496
        STIG ID    : RHEL-07-021340
        Rule ID    : SV-204496r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must use a separate file system for /tmp (or equivalent).
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl is-enabled tmp.mount)
    $finding_2 = $(grep -s -i [[:blank:]]/tmp /etc/fstab | grep -v "^#")

    if ($finding -or $finding_2) {
        $Status = "NotAFinding"
        $FindingMessage = "A separate file system/partition has been created for '/tmp'."
    }
    else {
        $Status = "Open"
        $FindingMessage = "A separate file system/partition has not been created for '/tmp'."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204497 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204497
        STIG ID    : RHEL-07-021350
        Rule ID    : SV-204497r877398_rule
        CCI ID     : CCI-000068, CCI-001199, CCI-002450, CCI-002476
        Rule Name  : SRG-OS-000033-GPOS-00014
        Rule Title : The Red Hat Enterprise Linux operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa dracut-fips)
    $finding_2 = ""
    $finding_3 = ""
    $finding_4 = ""

    if ($finding) {
        if (Test-Path /boot/grub2/grub.cfg) {
            $finding_2 = $(grep -s fips /boot/grub2/grub.cfg)
        }
        else {
            $finding_2 = $(grep -s fips /boot/efi/EFI/centos/grub.cfg)
        }

        if ($finding_2 -match "fips") {
            $finding_3 = $(cat /proc/sys/crypto/fips_enabled)

            if ($finding_3 -eq 1) {
                $finding_4 = (ls -l /etc/system-fips)

                if ($finding_4) {
                    $Status = "NotAFinding"
                    $FindingMessage = "The operating system implements DoD-approved encryption to protect the confidentiality of remote access sessions."
                }
                else {
                    $Status = "Open"
                    $FindingMessage = "The operating system does not implement DoD-approved encryption to protect the confidentiality of remote access sessions due to missing /etc/system-fips file."
                }
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not implement DoD-approved encryption to protect the confidentiality of remote access sessions due to fips not being enabled in /proc/sys/crypto."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not implement DoD-approved encryption to protect the confidentiality of remote access sessions due to missing kernel command line entry."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not implement DoD-approved encryption to protect the confidentiality of remote access sessions due to dracut-fips not being installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_4
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204498 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204498
        STIG ID    : RHEL-07-021600
        Rule ID    : SV-204498r880856_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the file integrity tool is configured to verify Access Control Lists (ACLs).
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa aide)
    $finding_2 = ""

    if ($finding) {
        $finding_2 = $(grep -s -i acl /etc/aide.conf || $(cat $(df -Tl | awk '(NR>1 && $2!="devtmpfs" && $2!="tmpfs" ){print $7}' | xargs -I% find "%" -xdev -not -path "/sys/*" -not -path "/proc/*" -not -path "/run/*" -name aide.conf) | grep -s -i acl))

        $Status = "Not_Reviewed"
        $FindingMessage = "Check the 'aide.conf' file to determine if the 'acl' rule has been added to the rule list being applied to the files and directories selection lists."
    }
    else {
        $Status = "Not_Reviewed"
        $FindingMessage = "AIDE is not installed, ask the SA how file integrity checks are performed on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204499 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204499
        STIG ID    : RHEL-07-021610
        Rule ID    : SV-204499r880858_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the file integrity tool is configured to verify extended attributes.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa aide)
    $finding_2 = ""

    if ($finding) {
        $finding_2 = $(grep -s -i xattrs /etc/aide.conf || $(cat $(df -Tl | awk '(NR>1 && $2!="devtmpfs" && $2!="tmpfs" ){print $7}' | xargs -I% find "%" -xdev -not -path "/sys/*" -not -path "/proc/*" -not -path "/run/*" -name aide.conf) | grep -s -i xattrs))

        $Status = "Not_Reviewed"
        $FindingMessage = "Check the 'aide.conf' file to determine if the 'xattrs' rule has been added to the rule list being applied to the files and directories selection lists."
    }
    else {
        $Status = "Not_Reviewed"
        $FindingMessage = "AIDE is not installed, ask the SA how file integrity checks are performed on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204500 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204500
        STIG ID    : RHEL-07-021620
        Rule ID    : SV-204500r880860_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must use a file integrity tool that is configured to use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa aide)
    $finding_2 = ""

    if ($finding) {
        $finding_2 = $(grep -s -i sha512 /etc/aide.conf || $(cat $(df -Tl | awk '(NR>1 && $2!="devtmpfs" && $2!="tmpfs" ){print $7}' | xargs -I% find "%" -xdev -not -path "/sys/*" -not -path "/proc/*" -not -path "/run/*" -name aide.conf) | grep -s -i sha512))

        $Status = "Not_Reviewed"
        $FindingMessage = "Check the 'aide.conf' file to determine if the 'sha512' rule has been added to the rule list being applied to the files and directories selection lists."
    }
    else {
        $Status = "Not_Reviewed"
        $FindingMessage = "AIDE is not installed, ask the SA how file integrity checks are performed on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204501 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204501
        STIG ID    : RHEL-07-021700
        Rule ID    : SV-204501r861008_rule
        CCI ID     : CCI-000318, CCI-000368, CCI-001812, CCI-001813, CCI-001814
        Rule Name  : SRG-OS-000364-GPOS-00151
        Rule Title : The Red Hat Enterprise Linux operating system must not allow removable media to be used as the boot loader unless approved.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(find /boot /boot/efi -xdev -name grub.cfg)
    $finding ?? $($finding = "Check text: No results found.")
    $finding_2 = ""
    $set_root_count = 0

    if (($finding -match "/boot/grub2/") -or ($finding -match "/boot/efi/EFI/centos/")) {
        $finding_2 = $(awk '/menuentry /,/}/ { print }' $finding)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        1..$($finding_2 | grep -s -c ^menuentry $_) | ForEach-Object { if (((((get-content $finding -raw) -split "menuentry ")[$_]) -split "}")[0] | grep -s -i "set root") { $set_root_count++ } }

        if ($set_root_count -eq $(grep -s -c ^menuentry $finding)) {
            $Status = "NotAFinding"
            $FindingMessage = "The system is not configured to use a boot loader on removable media."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system is configured to use a boot loader on removable media."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The system is configured to use a boot loader on removable media."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204502 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204502
        STIG ID    : RHEL-07-021710
        Rule ID    : SV-204502r603261_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095-GPOS-00049
        Rule Title : The Red Hat Enterprise Linux operating system must not have the telnet-server package installed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa telnet-server)

    If ($Finding) {
        $Status = "Open"
        $FindingMessage = "The telnet-server package is installed."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The telnet-server package is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204503 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204503
        STIG ID    : RHEL-07-030000
        Rule ID    : SV-204503r603261_rule
        CCI ID     : CCI-000126, CCI-000131
        Rule Name  : SRG-OS-000038-GPOS-00016
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that auditing is configured to produce records containing information to establish what type of events occurred, where the events occurred, the source of the events, and the outcome of the events. These audit records must also identify individual identities of group account users.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl is-active auditd.service)

    If ($Finding -eq "active") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system produces audit records containing information to establish when (date and time) the events occurred."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not produce audit records containing information to establish when (date and time) the events occurred."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204504 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204504
        STIG ID    : RHEL-07-030010
        Rule ID    : SV-204504r880761_rule
        CCI ID     : CCI-000139
        Rule Name  : SRG-OS-000046-GPOS-00022
        Rule Title : The Red Hat Enterprise Linux operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(auditctl -s | grep -s -i "fail")
    if (!($Finding)) {
        $Finding = "Check text: No results found."
        $Severity = "CAT_I"
    }

    If ($Finding.split(" ")[1] -in 1..2) {
        $Status = "NotAFinding"
        if ($Finding.split(" ")[1] -eq 1) {
            $FindingMessage = "The system is configured to only send information to the kernel log regarding the failure."
        }
        else {
            $FindingMessage = "The system is configured to panic (shut down) in the event of an auditing failure."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The system is not correctly configured for the event of an auditing failure."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204506 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204506
        STIG ID    : RHEL-07-030201
        Rule ID    : SV-204506r877390_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : The Red Hat Enterprise Linux operating system must be configured to off-load audit logs onto a different system or storage media from the system being audited.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /etc/audisp/plugins.d/au-remote.conf | grep -s -v "^\s*#")
    $finding ?? $($finding = "Check text: No results found.")

    If ((($Finding | awk '{$2=$2};1') -match "active = yes") -and
        (($Finding | awk '{$2=$2};1') -match "direction = out") -and
        (($Finding | awk '{$2=$2};1') -match "path = /sbin/audisp-remote") -and
        (($Finding | awk '{$2=$2};1') -match "type = always")) {
        $Status = "NotAFinding"
        $FindingMessage = "The 'au-remote' plugin is configured to always off-load audit logs using the audisp-remote daemon."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The 'au-remote' plugin is not configured to always off-load audit logs using the audisp-remote daemon."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204507 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204507
        STIG ID    : RHEL-07-030210
        Rule ID    : SV-204507r877390_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : The Red Hat Enterprise Linux operating system must take appropriate action when the remote logging buffer is full.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*overflow_action /etc/audisp/audispd.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1].ToLower() -in "syslog", "single", "halt") {
        $Status = "NotAFinding"
        $FindingMessage = "The audisp daemon is configured to take an appropriate action when the internal queue is full."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audisp daemon is not configured to take an appropriate action when the internal queue is full."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204508 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204508
        STIG ID    : RHEL-07-030211
        Rule ID    : SV-204508r877390_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : The Red Hat Enterprise Linux operating system must label all off-loaded audit logs before sending them to the central log server.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*name_format /etc/audisp/audispd.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1].ToLower() -in "hostname", "fqd", "numeric") {
        $Status = "NotAFinding"
        $FindingMessage = "The audisp daemon is configured to take an appropriate action when the internal queue is full."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audisp daemon is not configured to take an appropriate action when the internal queue is full."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204509 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204509
        STIG ID    : RHEL-07-030300
        Rule ID    : SV-204509r877390_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : The Red Hat Enterprise Linux operating system must off-load audit records onto a different system or media from the system being audited.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*remote_server /etc/audisp/audisp-remote.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If ((($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]) -as [ipaddress]) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system off-loads audit records onto a different system or media from the system being audited."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not off-load audit records onto a different system or media from the system being audited."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204510 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204510
        STIG ID    : RHEL-07-030310
        Rule ID    : SV-204510r877390_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : The Red Hat Enterprise Linux operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*enable_krb5 /etc/audisp/audisp-remote.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If (($Finding.ToLower() | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq "yes") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system encrypts audit records off-loaded onto a different system or media from the system being audited."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not encrypt audit records off-loaded onto a different system or media from the system being audited."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204511 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204511
        STIG ID    : RHEL-07-030320
        Rule ID    : SV-204511r877390_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the audit system takes appropriate action when the audit storage volume is full.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*disk_full_action /etc/audisp/audisp-remote.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If (($Finding.ToLower() | awk '{$2=$2};1').replace(" ", "").split("=")[1] -in "syslog", "single", "halt") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system takes an appropriate action if the disk the audit records are written to becomes full."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not take an appropriate action if the disk the audit records are written to becomes full."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204512 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204512
        STIG ID    : RHEL-07-030321
        Rule ID    : SV-204512r877390_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the audit system takes appropriate action when there is an error sending audit records to a remote system.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*network_failure_action /etc/audisp/audisp-remote.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If (($Finding.ToLower() | awk '{$2=$2};1').replace(" ", "").split("=")[1] -in "syslog", "single", "halt") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system takes an appropriate action if there is an error sending audit records to a remote system."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not take an appropriate action if there is an error sending audit records to a remote system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204513 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204513
        STIG ID    : RHEL-07-030330
        Rule ID    : SV-204513r877389_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-OS-000343-GPOS-00134
        Rule Title : The Red Hat Enterprise Linux operating system must initiate an action to notify the System Administrator (SA) and Information System Security Officer ISSO, at a minimum, when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iw log_file /etc/audit/auditd.conf)
    $finding_2 = ""
    $finding_3 = ""

    If ($finding) {
        $logpath = (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]).split("/")
        $partition = ([string]$logpath[0..($logpath.count - 2)]).replace(" ", "/")
        $finding_2 = $(df -h $partition)
        $partition_size = (($(df $partition)[1]) | awk '{print $2}') / 1KB
        $finding_3 = $(grep -s -iw space_left /etc/audit/auditd.conf)
        $better_finding_3 = $(grep -s -iw ^space_left /etc/audit/auditd.conf)
        if ($better_Finding_3) {
            $space_left = (($better_Finding_3 | awk '{$2=$2};1').replace(" ", "").split("=")[1])

            If ($space_left -match '\d+%') {
                If ($space_left -eq '25%') {
                    $Status = "NotAFinding"
                    $FindingMessage = "The operating system initiates an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
                }
                Else {
                    $Status = "Open"
                    $FindingMessage = "The operating system does not initiate an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
                    $FindingMessage += "`r`n"
                    $FindingMessage += "The configured percentage is $space_left"
                }
            }
            elseif ($space_left / $partition_size -ge .75) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system initiates an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not initiate an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
                $FindingMessage += "`r`n"
                $FindingMessage += "The configured percentage is $(($space_left/$partition_size).tostring("P"))"
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not initiate an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit records are not being written to a log file."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204514 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204514
        STIG ID    : RHEL-07-030340
        Rule ID    : SV-204514r877389_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-OS-000343-GPOS-00134
        Rule Title : The Red Hat Enterprise Linux operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*space_left_action /etc/audit/auditd.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If ((($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1].ToLower() -eq "email")) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system immediately notifies the SA and ISSO (at a minimum) via email when the allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not immediately notify the SA and ISSO (at a minimum) via email when the allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204515 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204515
        STIG ID    : RHEL-07-030350
        Rule ID    : SV-204515r877389_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-OS-000343-GPOS-00134
        Rule Title : The Red Hat Enterprise Linux operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*action_mail_acct /etc/audit/auditd.conf)
    $finding ?? $($finding = "Check text: No results found.")

    If (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1].ToLower() -eq "root") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system immediately notifies the SA and ISSO (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not immediately notify the SA and ISSO (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204516 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204516
        STIG ID    : RHEL-07-030360
        Rule ID    : SV-204516r853914_rule
        CCI ID     : CCI-002234
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : The Red Hat Enterprise Linux operating system must audit all executions of privileged functions.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw execve /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        $not_commented = 0
        $line = 0
        ($finding | grep -s -i " execve ") | ForEach-Object {
            $line++
            if ((($_ | awk '{$2=$2};1').StartsWith("-a")) -and (($_ | awk '{$2=$2};1') -match " execve ")) {
                $not_commented++
            }
        }

        if ($not_commented -eq $line) {
            if ((($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b32[\s]+)(?:(-S[\s]+execve[\s]))(?:-C[\s]+uid!=euid[\s]+)(?:-F[\s]+euid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b64[\s]+)(?:(-S[\s]+execve[\s]))(?:-C[\s]+uid!=euid[\s]+)(?:-F[\s]+euid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and
                (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b32[\s]+)(?:(-S[\s]+execve[\s]))(?:-C[\s]+gid!=egid[\s]+)(?:-F[\s]+egid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b64[\s]+)(?:(-S[\s]+execve[\s]))(?:-C[\s]+gid!=egid[\s]+)(?:-F[\s]+egid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$')) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system audits the execution of privileged functions."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not audit the execution of privileged functions."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not audit the execution of privileged functions."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204517 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204517
        STIG ID    : RHEL-07-030370
        Rule ID    : SV-204517r809570_rule
        CCI ID     : CCI-000126, CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the chown, fchown, fchownat, and lchown syscalls.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i chown /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (
            (
            ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+chown[\s]+|([\s]+|[,])chown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            ) -and (
            ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+chown[\s]+|([\s]+|[,])chown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            ) -and (
            ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fchown[\s]+|([\s]+|[,])fchown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            ) -and (
            ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fchown[\s]+|([\s]+|[,])fchown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            ) -and (
            ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+lchown[\s]+|([\s]+|[,])lchown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            ) -and (
            ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+lchown[\s]+|([\s]+|[,])lchown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            ) -and (
            ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fchownat[\s]+|([\s]+|[,])fchownat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            ) -and (
            ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fchownat[\s]+|([\s]+|[,])fchownat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'chown,fchown,fchownat,lchown' syscalls occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'chown,fchown,fchownat,lchown' syscalls occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204521 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204521
        STIG ID    : RHEL-07-030410
        Rule ID    : SV-204521r809772_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000458-GPOS-00203
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the chmod, fchmod, and fchmodat syscalls.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw chmod /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+chmod[\s]+|([\s]+|[,])chmod([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+chmod[\s]+|([\s]+|[,])chmod([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fchmod[\s]+|([\s]+|[,])fchmod([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fchmod[\s]+|([\s]+|[,])fchmod([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fchmodat[\s]+|([\s]+|[,])fchmodat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fchmodat[\s]+|([\s]+|[,])fchmodat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'chmod,fchmod,fchmodat' syscalls occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'chmod,fchmod,fchmodat' syscalls occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204524 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204524
        STIG ID    : RHEL-07-030440
        Rule ID    : SV-204524r809775_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000458-GPOS-00203
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr syscalls.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i xattr /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+setxattr[\s]+|([\s]+|[,])setxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+setxattr[\s]+|([\s]+|[,])setxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fsetxattr[\s]+|([\s]+|[,])fsetxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fsetxattr[\s]+|([\s]+|[,])fsetxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+lsetxattr[\s]+|([\s]+|[,])lsetxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+lsetxattr[\s]+|([\s]+|[,])lsetxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+removexattr[\s]+|([\s]+|[,])removexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+removexattr[\s]+|([\s]+|[,])removexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fremovexattr[\s]+|([\s]+|[,])fremovexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fremovexattr[\s]+|([\s]+|[,])fremovexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+lremovexattr[\s]+|([\s]+|[,])lremovexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+lremovexattr[\s]+|([\s]+|[,])lremovexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr' syscalls occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr' syscalls occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204531 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204531
        STIG ID    : RHEL-07-030510
        Rule ID    : SV-204531r853917_rule
        CCI ID     : CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate syscalls.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s 'open\|truncate\|creat' /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+creat[\s]+|([\s]+|[,])creat([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+creat[\s]+|([\s]+|[,])creat([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+creat[\s]+|([\s]+|[,])creat([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+creat[\s]+|([\s]+|[,])creat([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+open[\s]+|([\s]+|[,])open([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+open[\s]+|([\s]+|[,])open([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+open[\s]+|([\s]+|[,])open([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+open[\s]+|([\s]+|[,])open([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+openat[\s]+|([\s]+|[,])openat([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+openat[\s]+|([\s]+|[,])openat([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+openat[\s]+|([\s]+|[,])openat([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+openat[\s]+|([\s]+|[,])openat([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+open_by_handle_at[\s]+|([\s]+|[,])open_by_handle_at([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+open_by_handle_at[\s]+|([\s]+|[,])open_by_handle_at([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+open_by_handle_at[\s]+|([\s]+|[,])open_by_handle_at([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+open_by_handle_at[\s]+|([\s]+|[,])open_by_handle_at([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+truncate[\s]+|([\s]+|[,])truncate([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+truncate[\s]+|([\s]+|[,])truncate([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+truncate[\s]+|([\s]+|[,])truncate([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+truncate[\s]+|([\s]+|[,])truncate([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+ftruncate[\s]+|([\s]+|[,])ftruncate([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+ftruncate[\s]+|([\s]+|[,])ftruncate([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+ftruncate[\s]+|([\s]+|[,])ftruncate([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+ftruncate[\s]+|([\s]+|[,])ftruncate([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'creat,open,openat,open_by_handle_at,truncate,ftruncate' syscalls occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'creat,open,openat,open_by_handle_at,truncate,ftruncate' syscalls occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204536 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204536
        STIG ID    : RHEL-07-030560
        Rule ID    : SV-204536r861014_rule
        CCI ID     : CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000392-GPOS-00172
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the semanage command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i /usr/sbin/semanage /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/sbin\/semanage[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'semanage' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'semanage' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'semanage' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204537 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204537
        STIG ID    : RHEL-07-030570
        Rule ID    : SV-204537r861017_rule
        CCI ID     : CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000392-GPOS-00172
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the setsebool command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i /usr/sbin/setsebool /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/sbin\/setsebool[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'setsebool' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'setsebool' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'setsebool' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204538 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204538
        STIG ID    : RHEL-07-030580
        Rule ID    : SV-204538r861020_rule
        CCI ID     : CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000392-GPOS-00172
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the chcon command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i /usr/bin/chcon /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/bin\/chcon[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'chcon' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'chcon' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'chcon' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204539 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204539
        STIG ID    : RHEL-07-030590
        Rule ID    : SV-204539r861023_rule
        CCI ID     : CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000392-GPOS-00172
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the setfiles command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw /usr/sbin/setfiles /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/sbin\/setfiles[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'setfiles' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'setfiles' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'setfiles' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204540 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204540
        STIG ID    : RHEL-07-030610
        Rule ID    : SV-204540r853930_rule
        CCI ID     : CCI-000126, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000392-GPOS-00172
        Rule Title : The Red Hat Enterprise Linux operating system must generate audit records for all unsuccessful account access events.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i /var/run/faillock /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/run\/faillock((\/\w+)+|\/?)[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when unsuccessful account access events occur. "
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system generates audit records when unsuccessful account access events occur. "
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system generates audit records when unsuccessful account access events occur. "
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204541 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204541
        STIG ID    : RHEL-07-030620
        Rule ID    : SV-204541r853931_rule
        CCI ID     : CCI-000126, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000392-GPOS-00172
        Rule Title : The Red Hat Enterprise Linux operating system must generate audit records for all successful account access events.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i /var/log/lastlog /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/lastlog[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when unsuccessful account access events occur. "
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system generates audit records when unsuccessful account access events occur. "
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system generates audit records when unsuccessful account access events occur. "
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204542 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204542
        STIG ID    : RHEL-07-030630
        Rule ID    : SV-204542r861026_rule
        CCI ID     : CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000042-GPOS-00020
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the passwd command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i /usr/bin/passwd /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/bin\/passwd[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'passwd' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'passwd' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'passwd' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204543 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204543
        STIG ID    : RHEL-07-030640
        Rule ID    : SV-204543r861029_rule
        CCI ID     : CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000042-GPOS-00020
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the unix_chkpwd command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw /usr/sbin/unix_chkpwd /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/sbin\/unix_chkpwd[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'unix_chkpwd' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'unix_chkpwd' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'unix_chkpwd' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204544 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204544
        STIG ID    : RHEL-07-030650
        Rule ID    : SV-204544r861032_rule
        CCI ID     : CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000042-GPOS-00020
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the gpasswd command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i /usr/bin/gpasswd /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/bin\/gpasswd[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'gpasswd' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'gpasswd' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'gpasswd' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204545 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204545
        STIG ID    : RHEL-07-030660
        Rule ID    : SV-204545r861035_rule
        CCI ID     : CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000042-GPOS-00020
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the chage command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i /usr/bin/chage /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/bin\/chage[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'chage' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'chage' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'chage' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204546 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204546
        STIG ID    : RHEL-07-030670
        Rule ID    : SV-204546r861038_rule
        CCI ID     : CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000042-GPOS-00020
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the userhelper command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i /usr/sbin/userhelper /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/sbin\/userhelper[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'userhelper' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'userhelper' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'userhelper' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204547 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204547
        STIG ID    : RHEL-07-030680
        Rule ID    : SV-204547r861041_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the su command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw /usr/bin/su /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/bin\/su[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'su' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'su' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'su' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204548 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204548
        STIG ID    : RHEL-07-030690
        Rule ID    : SV-204548r861044_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the sudo command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw /usr/bin/sudo /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/bin\/sudo[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'sudo' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'sudo' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'sudo' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204549 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204549
        STIG ID    : RHEL-07-030700
        Rule ID    : SV-204549r853953_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the sudoers file and all files in the /etc/sudoers.d/ directory.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i "/etc/sudoers " /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")
        $finding_2 = $(grep -s -i "/etc/sudoers.d" /etc/audit/audit.rules)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding | awk '{$2=$2};1').StartsWith("-w")) -and (($finding_2 | awk '{$2=$2};1').StartsWith("-w"))) {
            if ((($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/sudoers[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and (($finding_2 | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/sudoers.d\/[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$')) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to access the '/etc/sudoers' file and files in the '/etc/sudoers.d/' directory."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to access the '/etc/sudoers' file and/or files in the '/etc/sudoers.d/' directory."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to access the '/etc/sudoers' file and/or files in the '/etc/sudoers.d/' directory."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204550 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204550
        STIG ID    : RHEL-07-030710
        Rule ID    : SV-204550r861047_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the newgrp command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i /usr/bin/newgrp /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/bin\/newgrp[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'newgrp' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'newgrp' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'newgrp' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204551 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204551
        STIG ID    : RHEL-07-030720
        Rule ID    : SV-204551r861050_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the chsh command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i /usr/bin/chsh /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/bin\/chsh[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'chsh' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'chsh' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'chsh' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204552 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204552
        STIG ID    : RHEL-07-030740
        Rule ID    : SV-204552r861053_rule
        CCI ID     : CCI-000135, CCI-002884
        Rule Name  : SRG-OS-000042-GPOS-00020
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the mount command and syscall.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw "mount" /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        $not_commented = 0
        $line = 0
        ($finding | grep -s ' mount\|/mount') | ForEach-Object {
            $line++
            if (($_ | awk '{$2=$2};1').StartsWith("-a")) {
                $not_commented++
            }
        }

        if ($not_commented -eq $line) {
            if ((($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b32[\s]+)(?:(-S[\s]+mount[\s]))(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+arch=b64[\s]+)(?:(-S[\s]+mount[\s]))(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/bin\/mount[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$')) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'mount' command and syscall occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'mount' command and syscall occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'mount' command and syscall occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204553 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204553
        STIG ID    : RHEL-07-030750
        Rule ID    : SV-204553r861056_rule
        CCI ID     : CCI-000135, CCI-002884
        Rule Name  : SRG-OS-000042-GPOS-00020
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the umount command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -i /usr/bin/umount /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/bin\/umount[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'umount' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'umount' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'umount' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204554 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204554
        STIG ID    : RHEL-07-030760
        Rule ID    : SV-204554r861059_rule
        CCI ID     : CCI-000135, CCI-002884
        Rule Name  : SRG-OS-000042-GPOS-00020
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the postdrop command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw /usr/sbin/postdrop /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/sbin\/postdrop[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'postdrop' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'postdrop' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'postdrop' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204555 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204555
        STIG ID    : RHEL-07-030770
        Rule ID    : SV-204555r861062_rule
        CCI ID     : CCI-000135, CCI-002884
        Rule Name  : SRG-OS-000042-GPOS-00020
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the postqueue command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw /usr/sbin/postqueue /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/sbin\/postqueue[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'postqueue' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'postqueue' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'postqueue' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204556 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204556
        STIG ID    : RHEL-07-030780
        Rule ID    : SV-204556r861065_rule
        CCI ID     : CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000042-GPOS-00020
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the ssh-keysign command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw /usr/libexec/openssh/ssh-keysign /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/libexec\/openssh\/ssh-keysign[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'ssh-keysign' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'ssh-keysign' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'ssh-keysign' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204557 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204557
        STIG ID    : RHEL-07-030800
        Rule ID    : SV-204557r861068_rule
        CCI ID     : CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000042-GPOS-00020
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the crontab command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw /usr/bin/crontab /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/bin\/crontab[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'crontab' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'crontab' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'crontab' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204558 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204558
        STIG ID    : RHEL-07-030810
        Rule ID    : SV-204558r833166_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000471-GPOS-00215
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the pam_timestamp_check command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw "/usr/sbin/pam_timestamp_check" /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/sbin\/pam_timestamp_check[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'pam_timestamp_check' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'pam_timestamp_check' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'pam_timestamp_check' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204559 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204559
        STIG ID    : RHEL-07-030819
        Rule ID    : SV-204559r833169_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000471-GPOS-00216
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the create_module syscall.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw create_module /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        $not_commented = 0
        $line = 0
        ($finding | grep -s -i " create_module ") | ForEach-Object {
            $line++
            if ((($_ | awk '{$2=$2};1').StartsWith("-a")) -and (($_ | awk '{$2=$2};1') -match " create_module ")) {
                $not_commented++
            }
        }

        if ($not_commented -eq $line) {
            if (
                (
                    ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+create_module[\s]+|([\s]+|[,])create_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                    ) -and (
                    ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+create_module[\s]+|([\s]+|[,])create_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                )
            ) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'create_module' syscall occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'create_module' syscall occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'create_module' syscall occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204560 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204560
        STIG ID    : RHEL-07-030820
        Rule ID    : SV-204560r833172_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000471-GPOS-00216
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the init_module and finit_module syscalls.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw init_module /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+init_module[\s]+|([\s]+|[,])init_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+init_module[\s]+|([\s]+|[,])init_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+finit_module[\s]+|([\s]+|[,])finit_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+finit_module[\s]+|([\s]+|[,])finit_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'init_module,finit_module' syscalls occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'init_module,finit_module' syscalls occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204562 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204562
        STIG ID    : RHEL-07-030830
        Rule ID    : SV-204562r833175_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000471-GPOS-00216
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the delete_module syscall.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw delete_module /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        $not_commented = 0
        $line = 0
        ($finding | grep -s -i " delete_module ") | ForEach-Object {
            $line++
            if ((($_ | awk '{$2=$2};1').StartsWith("-a")) -and (($_ | awk '{$2=$2};1') -match " delete_module ")) {
                $not_commented++
            }
        }

        if ($not_commented -eq $line) {
            if (
                (
                    ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+delete_module[\s]+|([\s]+|[,])delete_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                    ) -and (
                    ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+delete_module[\s]+|([\s]+|[,])delete_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                )
            ) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'delete_module' syscall occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'delete_module' syscall occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'delete_module' syscall occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204563 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204563
        STIG ID    : RHEL-07-030840
        Rule ID    : SV-204563r858498_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000471-GPOS-00216
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the kmod command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw kmod /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-F[\s]+path=\/usr\/bin\/kmod[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'kmod' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'kmod' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'kmod' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204564 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204564
        STIG ID    : RHEL-07-030870
        Rule ID    : SV-204564r853978_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s /etc/passwd /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/passwd[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/passwd'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/passwd'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/passwd'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204565 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204565
        STIG ID    : RHEL-07-030871
        Rule ID    : SV-204565r853979_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s /etc/group /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/group[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/group'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/group'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/group'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204566 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204566
        STIG ID    : RHEL-07-030872
        Rule ID    : SV-204566r853980_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s /etc/gshadow /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/gshadow[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/gshadow'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/gshadow'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/gshadow'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204567 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204567
        STIG ID    : RHEL-07-030873
        Rule ID    : SV-204567r853981_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s /etc/shadow /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/shadow[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/shadow'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/shadow'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/shadow'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204568 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204568
        STIG ID    : RHEL-07-030874
        Rule ID    : SV-204568r853982_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/security/opasswd.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s /etc/security/opasswd /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/security\/opasswd[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|key=[\s])[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/security/opasswd'."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/security/opasswd'."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect '/etc/security/opasswd'."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204572 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204572
        STIG ID    : RHEL-07-030910
        Rule ID    : SV-204572r853985_rule
        CCI ID     : CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000466-GPOS-00210
        Rule Title : The Red Hat Enterprise Linux operating system must audit all uses of the unlink, unlinkat, rename, renameat, and rmdir syscalls.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa audit)

    if ($finding) {
        $finding = $(grep -s -iw unlink /etc/audit/audit.rules)
        $finding ?? $($finding = "Check text: No results found.")

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+rename[\s]+|([\s]+|[,])rename([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+rename[\s]+|([\s]+|[,])rename([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+renameat[\s]+|([\s]+|[,])renameat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+renameat[\s]+|([\s]+|[,])renameat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+rmdir[\s]+|([\s]+|[,])rmdir([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+rmdir[\s]+|([\s]+|[,])rmdir([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+unlink[\s]+|([\s]+|[,])unlink([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+unlink[\s]+|([\s]+|[,])unlink([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+unlinkat[\s]+|([\s]+|[,])unlinkat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+unlinkat[\s]+|([\s]+|[,])unlinkat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system generates audit records when successful/unsuccessful attempts to use the 'unlink,unlinkat,rename,renameat,rmdir' syscalls occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not generate audit records when successful/unsuccessful attempts to use the 'unlink,unlinkat,rename,renameat,rmdir' syscalls occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204574 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204574
        STIG ID    : RHEL-07-031000
        Rule ID    : SV-204574r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must send rsyslog output to a log aggregation server.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -r -v "^\s*#" /etc/rsyslog.conf /etc/rsyslog.d/*.conf | grep -s '@')

    if ($finding) {
        if ($finding -match "\*\.\*") {
            $Status = "NotAFinding"
            $FindingMessage = "'rsyslog' is configured to send all messages to a log aggregation server."
        }
        else {
            $Status = "Open"
            $FindingMessage = "'rsyslog' is not configured to send all messages to a log aggregation server."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "'rsyslog' is not configured to send all messages to a log aggregation server."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204575 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204575
        STIG ID    : RHEL-07-031010
        Rule ID    : SV-204575r853986_rule
        CCI ID     : CCI-000318, CCI-000368, CCI-001812, CCI-001813, CCI-001814
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s imtcp /etc/rsyslog.conf)
    $finding_2 = $(grep -s imudp /etc/rsyslog.conf)
    $finding_3 = $(grep -s imrelp /etc/rsyslog.conf)

    if (($finding -eq '$ModLoad imtcp') -or ($finding_2 -eq '$ModLoad imudp') -or ($finding_2 -eq '$ModLoad imrelp')) {
        $Status = "Open"
        $FindingMessage = "The system is accepting 'rsyslog' messages from other systems."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system is not accepting 'rsyslog' messages from other systems."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204576 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204576
        STIG ID    : RHEL-07-040000
        Rule ID    : SV-204576r877399_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-OS-000027-GPOS-00008
        Rule Title : The Red Hat Enterprise Linux operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -r -v "^\s*#" /etc/security/limits.conf /etc/security/limits.d/*.conf | grep -s -i "maxlogins")

    if ($finding) {
        if ((($finding | awk '{$2=$2};1').split(":")[1]).split(" ")[-1] -le 10) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system limits the number of concurrent sessions to '10' for all accounts and/or account types."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not limit the number of concurrent sessions to '10' for all accounts and/or account types."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not limit the number of concurrent sessions to '10' for all accounts and/or account types."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204577 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204577
        STIG ID    : RHEL-07-040100
        Rule ID    : SV-204577r861069_rule
        CCI ID     : CCI-000382, CCI-002314
        Rule Name  : SRG-OS-000096-GPOS-00050
        Rule Title : The Red Hat Enterprise Linux operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA) and vulnerability assessments.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(firewall-cmd --list-all)

    $Status = "Not_Reviewed"
    $FindingMessage = "Inspect the firewall configuration and running services to verify that it is configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204578 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204578
        STIG ID    : RHEL-07-040110
        Rule ID    : SV-204578r877398_rule
        CCI ID     : CCI-000068, CCI-000366, CCI-000803
        Rule Name  : SRG-OS-000033-GPOS-00014
        Rule Title : The Red Hat Enterprise Linux 7 operating system must implement DoD-approved encryption to protect the confidentiality of SSH connections.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa dracut-fips)

    if ($finding) {
        if (Test-Path /boot/grub2/grub.cfg) {
            $finding = $(grep -s fips /boot/grub2/grub.cfg)
        }
        else {
            $finding = $(grep -s fips /boot/efi/EFI/centos/grub.cfg)
        }

        if ($finding -match "fips") {
            $finding = $(cat /proc/sys/crypto/fips_enabled)

            if ($finding -eq 1) {
                $finding = (ls -l /etc/system-fips)

                if ($finding) {
                    $finding = $(grep -s -i ^[[:blank:]]*ciphers /etc/ssh/sshd_config)
                    $finding ?? $($finding = "Check text: No results found.")

                    if ((($finding | awk '{$2=$2};1').replace(" ", "")).ToLower() -eq "ciphersaes256-ctr,aes192-ctr,aes128-ctr") {
                        $Status = "NotAFinding"
                        $FindingMessage = "The operating system uses mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module."
                    }
                    else {
                        $Status = "Open"
                        $FindingMessage = "The operating system does not use mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module."
                    }
                }
                else {
                    $Status = "Open"
                    $FindingMessage = "RHEL-07-021350 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes."
                }
            }
            else {
                $Status = "Open"
                $FindingMessage = "RHEL-07-021350 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "RHEL-07-021350 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "RHEL-07-021350 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204579 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204579
        STIG ID    : RHEL-07-040160
        Rule ID    : SV-204579r861070_rule
        CCI ID     : CCI-001133, CCI-002361
        Rule Name  : SRG-OS-000163-GPOS-00072
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all network connections associated with a communication session are terminated at the end of the session or after 15 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -ir tmout /etc/profile /etc/bashrc /etc/profile.d/)
    $correct_message_count = 0

    $finding | ForEach-Object {
       if (($finding | awk '{$2=$2};1' | grep -s -i "=").replace(" ", "").split(":")[1].split("=")[1] ?? 901 -le 900) {
            $correct_message_count++
       }
    }

    If ($correct_message_count -eq $finding.count){
        $Status = "NotAFinding"
        $FindingMessage = "The operating system terminates all network connections associated with a communications session at the end of the session or based on inactivity."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not terminate all network connections associated with a communications session at the end of the session or based on inactivity."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204580 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204580
        STIG ID    : RHEL-07-040170
        Rule ID    : SV-204580r603261_rule
        CCI ID     : CCI-000048, CCI-000050, CCI-001384, CCI-001385, CCI-001386, CCI-001387, CCI-001388
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner immediately prior to, or as part of, remote access logon prompts.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*banner /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")
    $finding_2 = ""

    if ($finding) {
        $banner_loc = ($finding | awk '{$2=$2};1').split(" ")[1]
        $finding_2 = $(cat $banner_loc)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if (((($finding_2 | awk '{$2=$2};1').replace(" ", "").replace('"','')) | tr -d "\n") -eq "YouareaccessingaU.S.Government(USG)InformationSystem(IS)thatisprovidedforUSG-authorizeduseonly.ByusingthisIS(whichincludesanydeviceattachedtothisIS),youconsenttothefollowingconditions:-TheUSGroutinelyinterceptsandmonitorscommunicationsonthisISforpurposesincluding,butnotlimitedto,penetrationtesting,COMSECmonitoring,networkoperationsanddefense,personnelmisconduct(PM),lawenforcement(LE),andcounterintelligence(CI)investigations.-Atanytime,theUSGmayinspectandseizedatastoredonthisIS.-Communicationsusing,ordatastoredon,thisISarenotprivate,aresubjecttoroutinemonitoring,interception,andsearch,andmaybedisclosedorusedforanyUSG-authorizedpurpose.-ThisISincludessecuritymeasures(e.g.,authenticationandaccesscontrols)toprotectUSGinterests--notforyourpersonalbenefitorprivacy.-Notwithstandingtheabove,usingthisISdoesnotconstituteconsenttoPM,LEorCIinvestigativesearchingormonitoringofthecontentofprivilegedcommunications,orworkproduct,relatedtopersonalrepresentationorservicesbyattorneys,psychotherapists,orclergy,andtheirassistants.Suchcommunicationsandworkproductareprivateandconfidential.SeeUserAgreementfordetails.") {
            $Status = "NotAFinding"
            $FindingMessage = "Any publicly accessible connection to the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
        }
        else {
            $Status = "Open"
            $FindingMessage = "Any publicly accessible connection to the operating system does not display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "Any publicly accessible connection to the operating system does not display any banner before granting access to the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204581 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204581
        STIG ID    : RHEL-07-040180
        Rule ID    : SV-204581r877394_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl | grep sssd.service && systemctl status sssd.service || $null)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
    $finding_3 = ""

    if ($finding -match "Active: active") {
        $finding_2 = $(grep -s -i "id_provider" /etc/sssd/sssd.conf)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -eq "ad") {
            $Status = "Not_Applicable"
            $FindingMessage = "The operating system implements cryptography through AD to protect the integrity of remote LDAP authentication sessions."
        }
        else {
            $finding_3 = $(grep -s -i "start_tls" /etc/sssd/sssd.conf)
            $better_finding_3 = $(grep -s -i ^[[:blank:]]*ldap_id_use_start_tls /etc/sssd/sssd.conf)
            if (!($better_finding_3)) { $better_finding_3 = "Check text: No results found." }

            if (($better_finding_3.startswith("ldap_id_use_start_tls")) -and ((($better_finding_3 | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -eq "true")) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system implements cryptography to protect the integrity of remote LDAP authentication sessions."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not implement cryptography to protect the integrity of remote LDAP authentication sessions."
            }
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The operating system does not use LDAP authentication sessions."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204582 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204582
        STIG ID    : RHEL-07-040190
        Rule ID    : SV-204582r877394_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl | grep sssd.service && systemctl status sssd.service || $null)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
    $finding_3 = ""

    if ($finding -match "Active: active") {
        $finding_2 = $(grep -s -i "id_provider" /etc/sssd/sssd.conf)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -eq "ad") {
            $Status = "Not_Applicable"
            $FindingMessage = "The operating system implements cryptography through AD to protect the integrity of remote LDAP authentication sessions."
        }
        else {
            $finding_3 = $(grep -s -i tls_reqcert /etc/sssd/sssd.conf)
            $finding_3 ?? $($finding_3 = "Check text: No results found.")

            if (($finding_3.startswith("ldap_tls_reqcert")) -and ((($finding_3 | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -in "demand", "hard")) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system implements cryptography to protect the integrity of remote LDAP authentication sessions."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not implement cryptography to protect the integrity of remote LDAP authentication sessions."
            }
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The operating system does not use LDAP authentication sessions."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204583 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204583
        STIG ID    : RHEL-07-040200
        Rule ID    : SV-204583r877394_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl | grep sssd.service && systemctl status sssd.service || $null)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
    $finding_3 = ""

    if ($finding -match "Active: active") {
        $finding_2 = $(grep -s -i "id_provider" /etc/sssd/sssd.conf)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -eq "ad") {
            $Status = "Not_Applicable"
            $FindingMessage = "The operating system implements cryptography through AD to protect the integrity of remote LDAP authentication sessions."
        }
        else {
            $finding_3 = $(grep -s -i tls_cacert /etc/sssd/sssd.conf)
            $finding_3 ?? $($finding_3 = "Check text: No results found.")

            if (($finding_3.startswith("ldap_tls_cacert")) -and ((($finding_3 | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -match ".crt")) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system implements cryptography to protect the integrity of remote LDAP authentication sessions."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not implement cryptography to protect the integrity of remote LDAP authentication sessions."
            }
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The operating system does not use LDAP authentication sessions."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204584 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204584
        STIG ID    : RHEL-07-040201
        Rule ID    : SV-204584r880794_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must implement virtual address space randomization.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -ir ^kernel.randomize_va_space /etc/sysctl.conf /etc/sysctl.d/ /run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
    $foundcount = 1

    $finding | Foreach-Object {
    if (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 2) {
        $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $finding_2 = $(/sbin/sysctl -a | grep -s kernel.randomize_va_space)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if (($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 2) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system implements virtual address space randomization."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not implement virtual address space randomization."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not implement virtual address space randomization."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204585 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204585
        STIG ID    : RHEL-07-040300
        Rule ID    : SV-204585r853989_rule
        CCI ID     : CCI-002418, CCI-002420, CCI-002421, CCI-002422
        Rule Name  : SRG-OS-000423-GPOS-00187
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all networked systems have SSH installed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa openssh-server)

    If ($Finding) {
        $Status = "NotAFinding"
        $FindingMessage = "The sshd package is installed."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The sshd package is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204586 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204586
        STIG ID    : RHEL-07-040310
        Rule ID    : SV-204586r861071_rule
        CCI ID     : CCI-002418, CCI-002420, CCI-002421, CCI-002422
        Rule Name  : SRG-OS-000423-GPOS-00187
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all networked systems use SSH for confidentiality and integrity of transmitted and received information as well as information during preparation for transmission.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl | grep sshd && systemctl status sshd)

    if ($finding -match "Active: active \(running\)") {
        $Status = "NotAFinding"
        $FindingMessage = "SSH is loaded and active"
    }
    else {
        $Status = "Open"
        $FindingMessage = "SSH is not loaded and active."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204587 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204587
        STIG ID    : RHEL-07-040320
        Rule ID    : SV-204587r861072_rule
        CCI ID     : CCI-001133, CCI-002361
        Rule Name  : SRG-OS-000163-GPOS-00072
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all network connections associated with SSH traffic are terminated at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*clientaliveinterval /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').split(" ")[1] -ne 0) {
        if (($finding | awk '{$2=$2};1').split(" ")[1] -le 600) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system automatically terminate a user session after inactivity time-outs have expired."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not automatically terminate a user session after inactivity time-outs have expired."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not automatically terminate a user session after inactivity time-outs have expired."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204588 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204588
        STIG ID    : RHEL-07-040330
        Rule ID    : SV-204588r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using RSA rhosts authentication.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /etc/redhat-release)

    if ($finding.split(" ")[3] -ge 7.4) {
        $Status = "Not_Applicable"
        $FindingMessage = "This is only applicable on systems running CentOS 7.4 or older."
    }
    else {
        $finding = $(grep -s -i ^[[:blank:]]*RhostsRSAAuthentication /etc/ssh/sshd_config)
        $finding ?? $($finding = "Check text: No results found.")

        if ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "no") {
            $Status = "NotAFinding"
            $FindingMessage = "The SSH daemon does not allow authentication using RSA rhosts authentication."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The SSH daemon allows authentication using RSA rhosts authentication."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204589 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204589
        STIG ID    : RHEL-07-040340
        Rule ID    : SV-204589r853992_rule
        CCI ID     : CCI-001133, CCI-002361
        Rule Name  : SRG-OS-000163-GPOS-00072
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all network connections associated with SSH traffic terminate after a period of inactivity.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*clientalivecount /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').split(" ")[1] -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system automatically terminates a user session after inactivity time-outs have expired."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not automatically terminates a user session after inactivity time-outs have expired."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204590 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204590
        STIG ID    : RHEL-07-040350
        Rule ID    : SV-204590r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using rhosts authentication.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*IgnoreRhosts /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    if ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "yes") {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon does not allow authentication using known hosts authentication."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon allows authentication using known hosts authentication."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204591 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204591
        STIG ID    : RHEL-07-040360
        Rule ID    : SV-204591r858477_rule
        CCI ID     : CCI-000052
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must display the date and time of the last successful account logon upon an SSH logon.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*printlastlog /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    if ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "yes") {
        $Status = "NotAFinding"
        $FindingMessage = "SSH provides users with feedback on when account accesses last occurred."
    }
    else {
        $Status = "Open"
        $FindingMessage = "SSH does not provide users with feedback on when account accesses last occurred."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204592 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204592
        STIG ID    : RHEL-07-040370
        Rule ID    : SV-204592r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not permit direct logons to the root account using remote access via SSH.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*permitrootlogin /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    if ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "no") {
        $Status = "NotAFinding"
        $FindingMessage = "Remote access using SSH prevents users from logging on directly as root."
    }
    else {
        $Status = "Open"
        $FindingMessage = "Remote access using SSH does not prevent users from logging on directly as root."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204593 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204593
        STIG ID    : RHEL-07-040380
        Rule ID    : SV-204593r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using known hosts authentication.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*IgnoreUserKnownHosts /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    if ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "yes") {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon does not allow authentication using known hosts authentication."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon allows authentication using known hosts authentication."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204594 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204594
        STIG ID    : RHEL-07-040390
        Rule ID    : SV-204594r877396_rule
        CCI ID     : CCI-000197, CCI-000366
        Rule Name  : SRG-OS-000074-GPOS-00042
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon is configured to only use the SSHv2 protocol.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /etc/redhat-release)

    if ($finding.split(" ")[3] -ge 7.4) {
        $Status = "Not_Applicable"
        $FindingMessage = "This is only applicable on systems running CentOS 7.4 or older."
    }
    else {
        $finding = $(grep -s -i ^[[:blank:]]*protocol /etc/ssh/sshd_config)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').split(" ")[1] -eq 2) {
            $Status = "NotAFinding"
            $FindingMessage = "The SSH daemon is configured to only use the SSHv2 protocol."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The SSH daemon is not configured to only use the SSHv2 protocol."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204595 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204595
        STIG ID    : RHEL-07-040400
        Rule ID    : SV-204595r877394_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon is configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa dracut-fips)

    if ($finding) {
        if (Test-Path /boot/grub2/grub.cfg) {
            $finding = $(grep -s fips /boot/grub2/grub.cfg)
        }
        else {
            $finding = $(grep -s fips /boot/efi/EFI/centos/grub.cfg)
        }

        if ($finding -match "fips") {
            $finding = $(cat /proc/sys/crypto/fips_enabled)

            if ($finding -eq 1) {
                $finding = (ls -l /etc/system-fips)

                if ($finding) {
                    $finding = $(grep -s -i ^[[:blank:]]*macs /etc/ssh/sshd_config)
                    $finding ?? $($finding = "Check text: No results found.")

                    if ((($finding | awk '{$2=$2};1').replace(" ", "")).ToLower() -eq "macshmac-sha2-512,hmac-sha2-256") {
                        $Status = "NotAFinding"
                        $FindingMessage = "The SSH daemon is configured to only use MACs employing FIPS 140-2-approved ciphers."
                    }
                    else {
                        $Status = "Open"
                        $FindingMessage = "The SSH daemon is not configured to only use MACs employing FIPS 140-2-approved ciphers."
                    }
                }
                else {
                    $Status = "Open"
                    $FindingMessage = "RHEL-07-021350 is a finding, therefore this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes."
                }
            }
            else {
                $Status = "Open"
                $FindingMessage = "RHEL-07-021350 is a finding, therefore this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "RHEL-07-021350 is a finding, therefore this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "RHEL-07-021350 is a finding, therefore this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204596 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204596
        STIG ID    : RHEL-07-040410
        Rule ID    : SV-204596r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH public host key files have mode 0644 or less permissive.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
find /etc/ssh -xdev -name '*.pub' -exec ls -lL {} \;
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    $incorrect_message_count = 0

    $finding | ForEach-Object {
        if ($_.StartsWith("-")) {
            if ((ConvertModeStringtoDigits $_.split(" ")[0]) -gt 644) {
                $incorrect_message_count++
            }
        }
    }
    if ($incorrect_message_count -gt 0) {
        $Status = "Open"
        $FindingMessage = "The SSH public host key files do not have mode '0644' or less permissive."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH public host key files have mode '0644' or less permissive."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204597 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204597
        STIG ID    : RHEL-07-040420
        Rule ID    : SV-204597r880743_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH private host key files have mode 0640 or less permissive.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
df -Tl | awk '(NR>1 && $2!="devtmpfs" && $2!="tmpfs" ){print $7}' | xargs -I% find "%" -xdev -not -path "/sys/*" -not -path "/proc/*" -not -path "/run/*" -name '*ssh_host*key' | xargs ls -lL
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    $incorrect_message_count = 0

    $finding | ForEach-Object {
        if ($_.StartsWith("-")) {
            if ((ConvertModeStringtoDigits $_.split(" ")[0]) -gt 640) {
                $incorrect_message_count++
            }
        }
    }
    if ($incorrect_message_count -gt 0) {
        $Status = "Open"
        $FindingMessage = "The SSH private host key files do not have mode '0640' or less permissive."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH private host key files have mode '0640' or less permissive."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204598 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204598
        STIG ID    : RHEL-07-040430
        Rule ID    : SV-204598r853993_rule
        CCI ID     : CCI-000318, CCI-000368, CCI-001812, CCI-001813, CCI-001814
        Rule Name  : SRG-OS-000364-GPOS-00151
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*gssapiauth /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    if ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "no") {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon does not permit GSSAPI authentication unless approved."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon permits GSSAPI authentication unless approved."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204599 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204599
        STIG ID    : RHEL-07-040440
        Rule ID    : SV-204599r853994_rule
        CCI ID     : CCI-000318, CCI-000368, CCI-001812, CCI-001813, CCI-001814
        Rule Name  : SRG-OS-000364-GPOS-00151
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Kerberos authentication unless needed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*kerberosauth /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    if ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "no") {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon does not permit Kerberos to authenticate passwords unless approved."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon permits Kerberos to authenticate passwords unless approved."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204600 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204600
        STIG ID    : RHEL-07-040450
        Rule ID    : SV-204600r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon performs strict mode checking of home directory configuration files.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*strictmodes /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    if ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "yes") {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon performs strict mode checking of home directory configuration files."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon does not performs strict mode checking of home directory configuration files."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204601 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204601
        STIG ID    : RHEL-07-040460
        Rule ID    : SV-204601r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon uses privilege separation.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*usepriv /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    if ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -ne "no") {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon performs privilege separation."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon does not perform privilege separation."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204602 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204602
        STIG ID    : RHEL-07-040470
        Rule ID    : SV-204602r880758_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow compression or only allows compression after successful authentication.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /etc/redhat-release)

    if ($finding.split(" ")[3] -ge 7.4) {
        $Status = "Not_Applicable"
        $FindingMessage = "This is only applicable on systems running CentOS 7.4 or older."
    }
    else {
        $finding = $(grep -s -i ^[[:blank:]]*compression /etc/ssh/sshd_config)
        $finding ?? $($finding = "Check text: No results found.")

        if ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -ne "yes") {
            $Status = "NotAFinding"
            $FindingMessage = "The SSH daemon performs compression after a user successfully authenticates."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The SSH daemon does not perform compression after a user successfully authenticates."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204603 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204603
        STIG ID    : RHEL-07-040500
        Rule ID    : SV-204603r877038_rule
        CCI ID     : CCI-001891, CCI-002046
        Rule Name  : SRG-OS-000355-GPOS-00143
        Rule Title : The Red Hat Enterprise Linux operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(Get-Process | grep -s ntp)
    $finding_2 = $(Get-Process | grep -s chronyd)
    $found = 0

    if ($finding) {
        if (Test-Path /etc/ntp.conf) {
            $finding_2 = $(grep -s maxpoll /etc/ntp.conf | grep -v "^#")
            $finding_2 ?? $($finding_2 = "Check text: No results found.")

            $finding_2 | Foreach-Object {
                $maxpoll = $($_ | grep -s -oP '(?<=maxpoll )[^ ]*')
                if (($_.ToLower()).startswith("server") -and ($maxpoll -le "16")) {
                    $found++
                }
            }

            if ($found -eq $finding_2.count) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system, for networked systems, synchronizes clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).  The ntp.conf file exists, but is not configured correctly."
            }
        }
        else {
            $finding_2 = $(grep -s -i "ntpd -q" /etc/cron.daily/*)

            if ($finding_2) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system, for networked systems, synchronizes clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).  A crontab file controlling the execution of the 'ntpd -q' command does not exist."
            }
        }
    }
    elseif ($finding_2) {
        if (Test-Path /etc/chrony.conf) {
            $finding_2 = $(grep -s maxpoll /etc/chrony.conf)
            $finding_2 ?? $($finding_2 = "Check text: No results found.")

            $finding_2 | Foreach-Object {
                $maxpoll = $($_ | grep -s -oP '(?<=maxpoll )[^ ]*')
                if (($_.ToLower()).startswith("server") -and ($maxpoll -ne "17")) {
                    $found++
                }
            }

            if ($found -eq $finding_2.count) {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system, for networked systems, synchronizes clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).  The chrony.conf file exists, but is not configured correctly."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204604 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204604
        STIG ID    : RHEL-07-040520
        Rule ID    : SV-204604r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must enable an application firewall, if available.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa firewalld)
    $finding_2 = ""
    $finding_3 = ""

    if ($finding) {
        $finding_2 = $(systemctl status firewalld)

        if (($finding_2 -match "Loaded: loaded") -and ($finding_2 -match "Active: active")) {
            $finding_3 = $(firewall-cmd --state)

            if ($finding_3 -eq "running") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system enabled an application firewall."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system enabled an application firewall but it is not running."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system enabled an application firewall but the service is not active and/or loaded."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not have an enabled application firewall."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204605 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204605
        STIG ID    : RHEL-07-040530
        Rule ID    : SV-204605r858478_rule
        CCI ID     : CCI-000052
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must display the date and time of the last successful account logon upon logon.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s pam_lastlog /etc/pam.d/postlogin)

    if ($finding) {
        if ($finding -notmatch "silent") {
            $Status = "NotAFinding"
            $FindingMessage = "Users are provided with feedback on when account accesses last occurred."
        }
        else {
            $Status = "Open"
            $FindingMessage = "Users are not provided with feedback on when account accesses last occurred."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "Users are not provided with feedback on when account accesses last occurred."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204606 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204606
        STIG ID    : RHEL-07-040540
        Rule ID    : SV-204606r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not contain .shosts files.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(df -Tl | awk '(NR>1 && $2!="devtmpfs" && $2!="tmpfs" ){print $7}' | xargs -I% find "%" -xdev -not -path "/sys/*" -not -path "/proc/*" -not -path "/run/*" -name '*.shosts')

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "There are '.shosts' files on the system."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "There are no '.shosts' files on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204607 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204607
        STIG ID    : RHEL-07-040550
        Rule ID    : SV-204607r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not contain shosts.equiv files.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(df -Tl | awk '(NR>1 && $2!="devtmpfs" && $2!="tmpfs" ){print $7}' | xargs -I% find "%" -xdev -not -path "/sys/*" -not -path "/proc/*" -not -path "/run/*" -name '*.shosts.equiv')

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "There are '.shosts.equiv' files on the system."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "There are no '.shosts.equiv' files on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204608 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204608
        STIG ID    : RHEL-07-040600
        Rule ID    : SV-204608r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : For Red Hat Enterprise Linux operating systems using DNS resolution, at least two name servers must be configured.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s hosts /etc/nsswitch.conf)
    $finding_2 = ""
    $finding_3 = ""

    if ($finding -match "dns") {
        $finding_2 = $(grep -s nameserver /etc/resolv.conf)

        if ($finding_2.count -ge 2) {
            $finding_3 = $(sudo lsattr /etc/resolv.conf)

            if ($finding_3[4] -eq "i") {
                $Status = "NotAFinding"
                $FindingMessage = "The system is using DNS name resolution."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The system is using DNS name resolution but '/etc/resolv.conf' is not immutable."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system is using DNS name resolution but has less than 2 name servers for DNS resolution."
        }
    }
    else {
        $finding_2 = $(ls -al /etc/resolv.conf)

        if (($finding_2 | awk '{$2=$2};1').split(" ")[4] -eq 0) {
            $Status = "NotAFinding"
            $FindingMessage = "The system is using local name resolution."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system is using local name resolution but '/etc/resolv.conf' is not empty."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204609 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204609
        STIG ID    : RHEL-07-040610
        Rule ID    : SV-204609r880797_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not forward Internet Protocol version 4 (IPv4) source-routed packets.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iR ^net.ipv4.conf.all.accept_source_route /etc/sysctl.conf /etc/sysctl.d/ /run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
	$foundcount = 1

    $finding | Foreach-Object {
    if (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0){
        $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $finding_2 = $(/sbin/sysctl -a | grep -s net.ipv4.conf.all.accept_source_route)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0)) {
            $Status = "NotAFinding"
            $FindingMessage = "The system does not accept IPv4 source-routed packets."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system accepts IPv4 source-routed packets."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The system accepts IPv4 source-routed packets."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204610 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204610
        STIG ID    : RHEL-07-040611
        Rule ID    : SV-204610r880800_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iR ^net.ipv4.conf.all.rp_filter /etc/sysctl.conf /etc/sysctl.d/ /run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
	$foundcount = 1

    $finding | Foreach-Object {
    if (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1){
        $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $finding_2 = $(/sbin/sysctl -a | grep -s net.ipv4.conf.all.rp_filter)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1)) {
            $Status = "NotAFinding"
            $FindingMessage = "The system uses a reverse-path filter for IPv4."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system does not use a reverse-path filter for IPv4."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The system does not use a reverse-path filter for IPv4."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204611 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204611
        STIG ID    : RHEL-07-040612
        Rule ID    : SV-204611r880803_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must use a reverse-path filter for IPv4 network traffic when possible by default.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iR ^net.ipv4.conf.default.rp_filter /etc/sysctl.conf /etc/sysctl.d/ /run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
	$foundcount = 1

    $finding | Foreach-Object {
    if (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1){
        $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $finding_2 = $(/sbin/sysctl -a | grep -s net.ipv4.conf.default.rp_filter)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1)) {
            $Status = "NotAFinding"
            $FindingMessage = "The system uses a reverse-path filter for IPv4."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system does not use a reverse-path filter for IPv4."
        }
    }
    else{
        $finding ?? $($finding = "Check text: No results found.")
        $finding_2 ?? $($finding_2 = "Check text: No results found.")
        $Status = "Open"
        $FindingMessage = "The system does not use a reverse-path filter for IPv4."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204612 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204612
        STIG ID    : RHEL-07-040620
        Rule ID    : SV-204612r880806_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not forward Internet Protocol version 4 (IPv4) source-routed packets by default.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iR ^net.ipv4.conf.default.accept_source_route /etc/sysctl.conf /etc/sysctl.d/ /run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
	$foundcount = 1

    $finding | Foreach-Object {
    if (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0){
        $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $finding_2 = $(/sbin/sysctl -a | grep -s net.ipv4.conf.default.accept_source_route)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0)) {
            $Status = "NotAFinding"
            $FindingMessage = "The system does not accept IPv4 source-routed packets by default."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system accepts IPv4 source-routed packets by default."
        }
    }
    else{
        $finding ?? $($finding = "Check text: No results found.")
        $finding_2 ?? $($finding_2 = "Check text: No results found.")
        $Status = "Open"
        $FindingMessage = "The system accepts IPv4 source-routed packets by default."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204613 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204613
        STIG ID    : RHEL-07-040630
        Rule ID    : SV-204613r880809_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iR ^net.ipv4.icmp_echo_ignore_broadcasts /etc/sysctl.conf /etc/sysctl.d/ /run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
	$foundcount = 1

    $finding | Foreach-Object {
    if (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1){
        $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $finding_2 = $(/sbin/sysctl -a | grep -s net.ipv4.icmp_echo_ignore_broadcasts)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1)) {
            $Status = "NotAFinding"
            $FindingMessage = "The system does not respond to IPv4 ICMP echoes sent to a broadcast address."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system responds to IPv4 ICMP echoes sent to a broadcast address."
        }
    }
    else{
        $finding ?? $($finding = "Check text: No results found.")
        $finding_2 ?? $($finding_2 = "Check text: No results found.")
        $Status = "Open"
        $FindingMessage = "The system responds to IPv4 ICMP echoes sent to a broadcast address."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204614 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204614
        STIG ID    : RHEL-07-040640
        Rule ID    : SV-204614r880812_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must prevent Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages from being accepted.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iR ^net.ipv4.conf.default.accept_redirects /etc/sysctl.conf /etc/sysctl.d/ /run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
	$foundcount = 1

    $finding | Foreach-Object {
    if (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0){
        $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $finding_2 = $(/sbin/sysctl -a | grep -s net.ipv4.conf.default.accept_redirects)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0)) {
            $Status = "NotAFinding"
            $FindingMessage = "The system does not accept IPv4 source-routed packets by default."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system accepts IPv4 source-routed packets by default."
        }
    }
    else {
        $finding ?? $($finding = "Check text: No results found.")
        $finding_2 ?? $($finding_2 = "Check text: No results found.")
        $Status = "Open"
        $FindingMessage = "The system accepts IPv4 source-routed packets by default."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204615 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204615
        STIG ID    : RHEL-07-040641
        Rule ID    : SV-204615r880815_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iR ^net.ipv4.conf.all.accept_redirects /etc/sysctl.conf /etc/sysctl.d/ /run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
	$foundcount = 1

    $finding | Foreach-Object {
    if (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0){
        $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $finding_2 = $(/sbin/sysctl -a | grep -s net.ipv4.conf.all.accept_redirects)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0)) {
            $Status = "NotAFinding"
            $FindingMessage = "The system ignores IPv4 ICMP redirect messages."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system does not ignore IPv4 ICMP redirect messages."
        }
    }
    else{
        $finding ?? $($finding = "Check text: No results found.")
        $finding_2 ?? $($finding_2 = "Check text: No results found.")
        $Status = "Open"
        $FindingMessage = "The system does not ignore IPv4 ICMP redirect messages."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204616 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204616
        STIG ID    : RHEL-07-040650
        Rule ID    : SV-204616r880818_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not allow interfaces to perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects by default.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iR ^net.ipv4.conf.default.send_redirects /etc/sysctl.conf /etc/sysctl.d/ /run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
	$foundcount = 1

    $finding | Foreach-Object {
    if (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0){
        $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $finding_2 = $(/sbin/sysctl -a | grep -s net.ipv4.conf.default.send_redirects)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0)) {
            $Status = "NotAFinding"
            $FindingMessage = "The system does not allow interfaces to perform IPv4 ICMP redirects by default."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system allows interfaces to perform IPv4 ICMP redirects by default."
        }
    }
    else {
        $finding ?? $($finding = "Check text: No results found.")
        $finding_2 ?? $($finding_2 = "Check text: No results found.")
        $Status = "Open"
        $FindingMessage = "The system allows interfaces to perform IPv4 ICMP redirects by default."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204617 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204617
        STIG ID    : RHEL-07-040660
        Rule ID    : SV-204617r880821_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not send Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iR ^net.ipv4.conf.all.send_redirects /etc/sysctl.conf /etc/sysctl.d/ /run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
	$foundcount = 1

    $finding | Foreach-Object {
    if (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0){
        $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $finding_2 = $(/sbin/sysctl -a | grep -s net.ipv4.conf.all.send_redirects)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0)) {
            $Status = "NotAFinding"
            $FindingMessage = "The system does not send IPv4 ICMP redirect messages."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system sends IPv4 ICMP redirect messages."
        }
    }
    else{
        $finding ?? $($finding = "Check text: No results found.")
        $finding_2 ?? $($finding_2 = "Check text: No results found.")
        $Status = "Open"
        $FindingMessage = "The system sends IPv4 ICMP redirect messages."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204618 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204618
        STIG ID    : RHEL-07-040670
        Rule ID    : SV-204618r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Network interfaces configured on the Red Hat Enterprise Linux operating system must not be in promiscuous mode.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(ip link | grep -s -i promisc)

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "Network interfaces are in promiscuous mode."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "network interfaces are not in promiscuous mode."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204619 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204619
        STIG ID    : RHEL-07-040680
        Rule ID    : SV-204619r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured to prevent unrestricted mail relaying.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa postfix)

    if ($finding) {
        $finding = $(grep -s -i ^[[:blank:]]*smtpd_client_restrictions /etc/postfix/main.cf)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').replace(" ", "") -eq "smtpd_client_restrictions=permit_mynetworks,reject") {
            $Status = "NotAFinding"
            $FindingMessage = "The system is configured to prevent unrestricted mail relaying."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system is not configured to prevent unrestricted mail relaying."
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "Postfix is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204620 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204620
        STIG ID    : RHEL-07-040690
        Rule ID    : SV-204620r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not have a File Transfer Protocol (FTP) server package installed unless needed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa vsftpd)

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "An FTP server has been installed on the system."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "An FTP server has not been installed on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204621 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204621
        STIG ID    : RHEL-07-040700
        Rule ID    : SV-204621r853996_rule
        CCI ID     : CCI-000318, CCI-000368, CCI-001812, CCI-001813, CCI-001814
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not have the Trivial File Transfer Protocol (TFTP) server package installed if not required for operational support.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa tftp-server)

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "An TFTP server has been installed on the system."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "An TFTP server has not been installed on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204622 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204622
        STIG ID    : RHEL-07-040710
        Rule ID    : SV-204622r603849_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that remote X connections are disabled except to fulfill documented and validated mission requirements.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i x11forwarding /etc/ssh/sshd_config | grep -s -v "^\s*#")
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').split(" ")[1] -eq "no") {
        $Status = "NotAFinding"
        $FindingMessage = "Remote X connections for interactive users are encrypted."
    }
    else {
        $Status = "Open"
        $FindingMessage = "Remote X connections for interactive users are not encrypted."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204623 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204623
        STIG ID    : RHEL-07-040720
        Rule ID    : SV-204623r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that if the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon is configured to operate in secure mode.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa tftp-server)

    if ($finding) {
        $finding = $(grep -s server_args /etc/xinetd.d/tftp)
        if (($finding.startswith("server_args")) -and ($finding -match "-s") -and ($finding -match "/")) {
            $Status = "NotAFinding"
            $FindingMessage = "The TFTP daemon is configured to operate in secure mode."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The TFTP daemon is not configured to operate in secure mode."
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "An TFTP server has not been installed on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204624 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204624
        STIG ID    : RHEL-07-040730
        Rule ID    : SV-204624r646847_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not have a graphical display manager installed unless approved.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(systemctl get-default)
    $finding_2 = ""

    if ($finding -eq "multi-user.target") {
        $finding_2 = $(rpm -qa | grep -s xorg | grep -s server)

        if ($finding_2) {
            $Status = "Open"
            $FindingMessage = "The system is configured to boot to the command line but does have a graphical user interface installed."
        }
        else {
            $Status = "NotAFinding"
            $FindingMessage = "The system is configured to boot to the command line and does not have a graphical user interface installed."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The system is not configured to boot to the command line."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204625 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204625
        STIG ID    : RHEL-07-040740
        Rule ID    : SV-204625r880824_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not be performing packet forwarding unless the system is a router.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iR ^net.ipv4.ip_forward /etc/sysctl.conf /etc/sysctl.d/ /run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/)
    $finding ?? $($finding = "Check text: No results found.")

    $finding_2 = ""
	$foundcount = 1

    $finding | Foreach-Object {
    if (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0){
        $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $finding_2 = $(/sbin/sysctl -a | grep -s net.ipv4.ip_forward)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0)) {
            $Status = "NotAFinding"
            $FindingMessage = "The system is not performing packet forwarding, unless the system is a router."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system is performing packet forwarding, unless the system is a router."
        }
    }
    else{
        $finding ?? $($finding = "Check text: No results found.")
        $finding_2 ?? $($finding_2 = "Check text: No results found.")
        $Status = "Open"
        $FindingMessage = "The system is performing packet forwarding, unless the system is a router."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204626 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204626
        STIG ID    : RHEL-07-040750
        Rule ID    : SV-204626r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that the Network File System (NFS) is configured to use RPCSEC_GSS.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /etc/fstab | grep -s nfs | grep -v "^#")

    if ($finding) {
        if ($finding -match ("sec")) {
            if (($finding | awk '{$2=$2};1').replace(" ", "") -match "sec=krb5:krb5i:krb5p") {
                $Status = "NotAFinding"
                $FindingMessage = "'AUTH_GSS' is being used to authenticate NFS mounts."
            }
            else {
                $Status = "Open"
                $FindingMessage = "'AUTH_GSS' is not being used to authenticate NFS mounts."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "No security authentication mechanism is being used to authenticate NFS mounts."
        }
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system is not importing an NFS file system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204627 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204627
        STIG ID    : RHEL-07-040800
        Rule ID    : SV-204627r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : SNMP community strings on the Red Hat Enterprise Linux operating system must be changed from the default.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(ls -al /etc/snmp/snmpd.conf)

    if ($finding) {
        $finding = $(egrep -s -i "^[[:blank:]]*public|^[[:blank:]]*private" /etc/snmp/snmpd.conf)
        if ($finding) {
            $Status = "Open"
            $FindingMessage = "The system using SNMP is using default community strings."
        }
        else {
            $Status = "NotAFinding"
            $FindingMessage = "The system using SNMP is not using default community strings."
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The system is not using SNMP."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204628 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204628
        STIG ID    : RHEL-07-040810
        Rule ID    : SV-204628r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system access control program must be configured to grant or deny system access to specific hosts and services.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa firewalld)
    $finding_2 = ""
    $finding_3 = ""

    if ($finding) {
        $finding = $(systemctl status firewalld)

        if ($finding -match "Active: active") {
            $finding_2 = $(firewall-cmd --list-all --zone=$(firewall-cmd --get-default-zone))
            $Status = "Not_Reviewed"
            $FindingMessage = "Check to see if the firewall is configured to grant or deny access to specific hosts or services."
        }
        else {
            $finding_2 = $(ls -al /etc/hosts.allow)
            $finding_3 = $(ls -al /etc/hosts.deny)
            if ((($finding_2 | awk '{$2=$2};1').split(" ")[4] -eq 0) -and (($finding_3 | awk '{$2=$2};1').split(" ")[4] -eq 0)) {
                $Status = "Open"
                $FindingMessage = "The system's access control program is not configured to grant or deny system access to specific hosts."
            }
            else {
                $Status = "NotAFinding"
                $FindingMessage = "The system's access control program is configured to grant or deny system access to specific hosts."
            }
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not have an enabled application firewall."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204629 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204629
        STIG ID    : RHEL-07-040820
        Rule ID    : SV-204629r603261_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not have unauthorized IP tunnels configured.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa libreswan)
    $finding_2 = ""
    $finding_3 = ""

    if ($finding) {
        $finding_2 = $(systemctl status ipsec)
        if ($finding_2 -match "Active: active") {
            $finding_3 = $(grep -s -iw conn /etc/ipsec.conf /etc/ipsec.d/*.conf)
            if ($finding_3) {
                $Status = "Open"
                $FindingMessage = "The system has unauthorized IP tunnels configured."
            }
            else {
                $Status = "NotAFinding"
                $FindingMessage = "The system does not unauthorized IP tunnels configured as no 'conn' parameters are configured."
            }
        }
        else {
            $Status = "NotAFinding"
            $FindingMessage = "The system does not unauthorized IP tunnels configured as IPSec is not active."
        }
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system does not unauthorized IP tunnels configured as libreswan is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204630 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204630
        STIG ID    : RHEL-07-040830
        Rule ID    : SV-204630r880827_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not forward IPv6 source-routed packets.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(cat /sys/module/ipv6/parameters/disable)

    if ($finding -eq "0"){
        $finding = $(grep -s -iR ^net.ipv6.conf.all.accept_source_route /etc/sysctl.conf /etc/sysctl.d/ /run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/)
        $finding ?? $($finding = "Check text: No results found.")

        $finding_2 = ""
        $foundcount = 1

        $finding | Foreach-Object {
        if (($_ | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0){
            $foundcount++
            }
        }

        if ($finding.count -eq $foundcount-1){
            $finding_2 = $(/sbin/sysctl -a | grep -s net.ipv6.conf.all.accept_source_route)
            $finding_2 ?? $($finding_2 = "Check text: No results found.")

            if ((($finding_2 | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0)) {
                $Status = "NotAFinding"
                $FindingMessage = "The system does not accept IPv6 source-routed packets."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The system accepts IPv6 source-routed packets."
            }
        }
        else{
            $Status = "Open"
            $FindingMessage = "The system accepts IPv6 source-routed packets."
        }
        }
        else {
            $Status = "Not_Applicable"
            $FindingMessage = "IPV6 is not enabled."
        }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204631 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204631
        STIG ID    : RHEL-07-041001
        Rule ID    : SV-204631r853997_rule
        CCI ID     : CCI-001948, CCI-001953, CCI-001954
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : The Red Hat Enterprise Linux operating system must have the required packages for multifactor authentication installed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa pam_pkcs11)

    If ($Finding) {
        $Status = "NotAFinding"
        $FindingMessage = "The pam_pkcs11 package is installed."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The pam_pkcs11 package is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204632 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204632
        STIG ID    : RHEL-07-041002
        Rule ID    : SV-204632r853998_rule
        CCI ID     : CCI-001948, CCI-001953, CCI-001954
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : The Red Hat Enterprise Linux operating system must implement multifactor authentication for access to privileged accounts via pluggable authentication modules (PAM).
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s services /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf)
    $correct_message = 0

    $finding | ForEach-Object {
        If ($_ -match "pam") {
            $correct_message++
        }
    }

    if ($correct_message -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system implements multifactor authentication for remote access to privileged accounts via pluggable authentication modules (PAM)."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not implement multifactor authentication for remote access to privileged accounts via pluggable authentication modules (PAM)."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204633 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204633
        STIG ID    : RHEL-07-041003
        Rule ID    : SV-204633r853999_rule
        CCI ID     : CCI-001948, CCI-001953, CCI-001954
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : The Red Hat Enterprise Linux operating system must implement certificate status checking for PKI authentication.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep -s -v "^\s*#")
    $correct_message = 0

    $finding | ForEach-Object {
        If ($_ -match "ocsp_on") {
            $correct_message++
        }
    }

    if ($correct_message -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system implements certificate status checking for PKI authentication."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not implement certificate status checking for PKI authentication."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V204634 {
    <#
    .DESCRIPTION
        Vuln ID    : V-204634
        STIG ID    : RHEL-07-041010
        Rule ID    : SV-204634r877465_rule
        CCI ID     : CCI-001443, CCI-001444, CCI-002418
        Rule Name  : SRG-OS-000424-GPOS-00188
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all wireless network adapters are disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(ip a)
    $wireless = $(lshw -C Network) | Where-Object { $_ -match "wireless" }

    if ($wireless) {
        $Status = "Not_Reviewed"
        $FindingMessage = "A wireless interface is configured and must be documented and approved by the Information System Security Officer (ISSO)"
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "This requirement is Not Applicable for systems that do not have physical wireless network radios."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V214800 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214800
        STIG ID    : RHEL-07-020019
        Rule ID    : SV-214800r854323_rule
        CCI ID     : CCI-000366, CCI-001263
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must implement the Endpoint Security for Linux Threat Prevention tool.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa | grep -s -i mcafeetp)

    if ($finding){
        $finding_2 = $(ps -ef | grep -s -i mfetpd)

        if ($finding_2){
            $Status = "NotAFinding"
            $FindingMessage = "McAfee ENSLTP package is installed and running."
        }
        else{
            $Status = "Open"
            $FindingMessage = "McAfee ENSLTP package is installed but not running."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "McAfee ENSLTP package is not installed."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "Per OPORD 16-0080, the preferred endpoint security tool is McAfee Endpoint Security for Linux (ENSL) in conjunction with SELinux."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V214937 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214937
        STIG ID    : RHEL-07-010062
        Rule ID    : SV-214937r880767_rule
        CCI ID     : CCI-000057
        Rule Name  : SRG-OS-000029-GPOS-00010
        Rule Title : The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)
    $found = $false

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $systemdb = $(grep -s system-db /etc/dconf/profile/user)
        $finding = $systemdb
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $systemdb | ForEach-Object {
            $finding = $(grep -s -ir lock-enabled /etc/dconf/db/$($_.split(":")[1]).d/locks/)
            $finding ?? $($Finding = "Check text did not return results for $($_.split(":")[1]).")

            If ($finding.split(":")[1]) {
                If (($finding.split(":")[1]).startswith("/org/gnome/desktop/screensaver/lock-enabled")) {
                    $found = $True
                }
            }

            $FindingDetails += $(FormatFinding $finding) | Out-String
        }

        If ($found) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system prevents a user from overriding the screensaver lock-enabled setting for the graphical user interface."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface."
        }
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V219059 {
    <#
    .DESCRIPTION
        Vuln ID    : V-219059
        STIG ID    : RHEL-07-020111
        Rule ID    : SV-219059r854002_rule
        CCI ID     : CCI-000366, CCI-000778, CCI-001958
        Rule Name  : SRG-OS-000114-GPOS-00059
        Rule Title : The Red Hat Enterprise Linux operating system must disable the graphical user interface automounter unless required.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)
    $finding_2 = ""
    $lock_found = $false
    $found = $false

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $systemdb = $(grep -s system-db /etc/dconf/profile/user)
        if (!($systemdb)) { $systemdb = "Check text: No results found." }
        $finding = $systemdb
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $systemdb | ForEach-Object {
            $automount_file = $(grep -s -ir automount /etc/dconf/db/$($_.split(":")[1]).d/*)
            $automount_file | ForEach-Object {
                if ($_ -match "locks") {
                    $finding = $(cat $_.split(":")[0] | tr -d '\n')
                    if ($finding -match "/org/gnome/desktop/media-handling/automount/org/gnome/desktop/media-handling/automount-open/org/gnome/desktop/media-handling/autorun-never") {
                        $lock_found = $true
                        $FindingDetails += $(FormatFinding $finding) | Out-String
                    }
                }

                if ($_ -notmatch "locks") {
                    $finding_2 = $(cat $_.split(":")[0] | tr -d '\n')
                    if ($finding_2 -match "\[org/gnome/desktop/media-handling\]automount\=falseautomount-open\=falseautorun-never\=true") {
                        $found = $true
                        $finding = $finding_2
                        $FindingDetails += $(FormatFinding $finding) | Out-String
                    }
                }
            }
        }

        If ($found -and $lock_found) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system disables the ability to automount devices in a graphical user interface."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not disable the ability to automount devices in a graphical user interface."
        }
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V228563 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228563
        STIG ID    : RHEL-07-021031
        Rule ID    : SV-228563r744119_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must be configured so that all world-writable directories are owned by root, sys, bin, or an application user.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $partitions = $(lsblk -o MOUNTPOINT | awk '{if ($1) print $1;}' | grep -s -v MOUNTPOINT)

    $partitions | ForEach-Object {
        $finding = $(find $_ -xdev -type d -perm -0002 -uid +999 -print)
        if ($finding) {
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $found++
        }
    }

    If ($found -gt 0) {
        $Status = "Open"
        $FindingMessage = "All world-writable directories that are not owned by a system account."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "All world-writable directories that are owned by a system account."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V228564 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228564
        STIG ID    : RHEL-07-910055
        Rule ID    : SV-228564r606407_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164, CCI-001314
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : The Red Hat Enterprise Linux operating system must protect audit information from unauthorized read, modification, or deletion.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(ls -la /var/log/audit)
    $better_finding = $(ls -lA /var/log/audit | egrep "^d|^-" | grep -v "^d")
    $found = 0

    $better_finding | ForEach-Object {
        if ((ConvertModeStringtoDigits $_.split(" ")[0]) -gt 600) {
            $found++
        }
    }

    $better_finding | ForEach-Object {
        if (((($_ | awk '{$2=$2};1').split(" ")[2]) -ne "root") -and ((($_ | awk '{$2=$2};1').split(" ")[3]) -ne "root")) {
            $found++
        }
    }

    if ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system audit records have proper permissions and ownership."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system audit records do not have proper permissions and ownership."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V233307 {
    <#
    .DESCRIPTION
        Vuln ID    : V-233307
        STIG ID    : RHEL-07-040711
        Rule ID    : SV-233307r603301_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system SSH daemon must prevent remote hosts from connecting to the proxy display.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*x11uselocalhost /etc/ssh/sshd_config)
    $finding ?? $($finding = "Check text: No results found.")

    if ((($finding | awk '{$2=$2};1').split(" ")[1]).ToLower() -eq "yes") {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon prevents remote hosts from connecting to the proxy display."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon does not prevent remote hosts from connecting to the proxy display."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V237633 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237633
        STIG ID    : RHEL-07-010341
        Rule ID    : SV-237633r646850_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must restrict privilege elevation to authorized personnel.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iwr 'ALL' /etc/sudoers /etc/sudoers.d/)
    $found = 0

    If ($finding) {
        $finding | ForEach-Object {
            If (((($_ | awk '{$2=$2};1').split(":")[1]) -eq "ALL ALL=(ALL) ALL") -or ((($_ | awk '{$2=$2};1').split(":")[1]) -eq "ALL ALL=(ALL:ALL) ALL")) {
                $found++
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The 'sudoers' file restricts sudo access to authorized personnel."
    }

    if ($found -gt 0) {
        $Status = "Open"
        $FindingMessage = "The 'sudoers' file does not restrict sudo access to authorized personnel."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The 'sudoers' file restricts sudo access to authorized personnel."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V237634 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237634
        STIG ID    : RHEL-07-010342
        Rule ID    : SV-237634r880755_rule
        CCI ID     : CCI-002227
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must use the invoking user's password for privilege escalation when using "sudo".
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(egrep -s -iR '(!rootpw|!targetpw|!runaspw)' /etc/sudoers /etc/sudoers.d/ | grep -s -v '#')
    $finding ?? $($finding = "Check text: No results found.")
    $foundtargetpwcount = 0
    $foundrootpwcount = 0
    $foundrunaspwcount = 0

    $finding | ForEach-Object {
        If (($_ | awk '{$2=$2};1') -match "Defaults !targetpw") {
            $foundtargetpwcount++
        }
        If (($_ | awk '{$2=$2};1') -match "Defaults !rootpw") {
            $foundrootpwcount++
        }
        If (($_ | awk '{$2=$2};1') -match "Defaults !runaspw") {
            $foundrunaspwcount++
        }
    }
    if ($foundtargetpwcount -gt 0 -and $foundrootpwcount -gt 0 -and $foundrunaspwcount -gt 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The sudoers security policy is configured to use the invoking user's password for privilege escalation."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The sudoers security policy is not configured to use the invoking user's password for privilege escalation."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V237635 {
    <#
    .DESCRIPTION
        Vuln ID    : V-237635
        STIG ID    : RHEL-07-010343
        Rule ID    : SV-237635r861075_rule
        CCI ID     : CCI-002038
        Rule Name  : SRG-OS-000373-GPOS-00156
        Rule Title : The Red Hat Enterprise Linux operating system must require re-authentication when using the "sudo" command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -iR 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/)
    $finding ?? $($finding = "Check text: No results found.")
    $foundcount = 1

    $finding | Foreach-Object {
        If ((($_.split(":"))[1]).ToLower().StartsWith("defaults") -and ([int]((($_ | awk '{$2=$2};1').replace(" ","").split("="))[1]) -ge 0)) {
            $foundcount++
        }
    }

    if ($finding.count -eq $foundcount-1){
        $Status = "NotAFinding"
        $FindingMessage = "The operating system requires re-authentication when using the 'sudo' command to elevate privileges."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not require re-authentication when using the 'sudo' command to elevate privileges."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V244557 {
    <#
    .DESCRIPTION
        Vuln ID    : V-244557
        STIG ID    : RHEL-07-010483
        Rule ID    : SV-244557r833185_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080-GPOS-00048
        Rule Title : Red Hat Enterprise Linux operating systems version 7.2 or newer booted with a BIOS must have a unique name for the grub superusers account when booting into single-user and maintenance modes.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(Test-Path /boot/efi/EFI/centos/grub.cfg)
    $release = $(cat /etc/redhat-release)

    If ($finding) {
        $Status = "Not_Applicable"
        $FindingMessage = "This is only applicable on systems that use a basic Input/Output System BIOS."
    }
    elseif ($release.split(" ")[6] -le 7.2) {
        $finding = $release
        $Status = "Not_Applicable"
        $FindingMessage = "This is only applicable on systems running RHEL 7.2 or newer."
    }
    Else {
        $finding = $(grep -s -iw -A1 "superusers" /boot/grub2/grub.cfg)

        if($finding){
            $superuser = $(grep -s -iw "password_pbkdf2" /boot/grub2/grub.cfg)
            $superuser ?? $($superuser = "No results found.")
            If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]) {
                if (((($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]).replace('"','')) -eq (($superuser | awk '{$2=$2};1').split(" ")[1])){
                    $Status = "Not_Reviewed"
                    $FindingMessage = "A name is set as the 'superusers' account. Verify it is considered unique. Examples of non-unique superusers names are root, superuser, unlock, etc."
                }
                else{
                    $Status = "Open"
                    $FindingMessage = "The superuser account does not match the password_pbkdf2 account."
                }
            }
            Else {
                $Status = "Open"
                $FindingMessage = "A unique name is not set as the 'superusers' account."
            }
        }
        Else {
            $Status = "Open"
            $FindingMessage = "A unique name is not set as the 'superusers' account."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V244558 {
    <#
    .DESCRIPTION
        Vuln ID    : V-244558
        STIG ID    : RHEL-07-010492
        Rule ID    : SV-244558r833187_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080-GPOS-00048
        Rule Title : Red Hat Enterprise Linux operating systems version 7.2 or newer booted with United Extensible Firmware Interface (UEFI) must have a unique name for the grub superusers account when booting into single-user mode and maintenance.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(Test-Path /boot/efi/EFI/centos/grub.cfg)
    $release = $(cat /etc/redhat-release)

    If ($finding) {
        if ($release.split(" ")[6] -le 7.2) {
            $finding = $release
            $Status = "Not_Applicable"
            $FindingMessage = "This is only applicable on systems running RHEL 7.2 or newer."
        }
        Else {
            $finding = $(grep -s -iw -A1 "superusers" /boot/efi/EFI/centos/grub.cfg)

            if($finding){
                $superuser = $(grep -s -iw "password_pbkdf2" /boot/efi/EFI/centos/grub.cfg)
                $superuser ?? $($superuser = "No results found.")
                If (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]) {
                    if (((($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]).replace('"','')) -eq (($superuser | awk '{$2=$2};1').split(" ")[1])){
                        $Status = "Not_Reviewed"
                        $FindingMessage = "A name is set as the 'superusers' account. Verify it is considered unique. Examples of non-unique superusers names are root, superuser, unlock, etc."
                    }
                    else{
                        $Status = "Open"
                        $FindingMessage = "The superuser account does not match the password_pbkdf2 account."
                    }
                }
                Else {
                    $Status = "Open"
                    $FindingMessage = "A unique name is not set as the 'superusers' account."
                }
            }
            Else {
                $Status = "Open"
                $FindingMessage = "A unique name is not set as the 'superusers' account."
            }
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "This is only applicable on systems that use UEFI."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V250312 {
    <#
    .DESCRIPTION
        Vuln ID    : V-250312
        STIG ID    : RHEL-07-020021
        Rule ID    : SV-250312r877392_rule
        CCI ID     : CCI-002165, CCI-002235
        Rule Name  : SRG-OS-000324-GPOS-00125
        Rule Title : The Red Hat Enterprise Linux operating system must confine SELinux users to roles that conform to least privilege.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(semanage user -l)

    $Status = "Not_Reviewed"
    $FindingMessage = "Verify the operating system confines SELinux users to roles that conform to least privilege."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V250313 {
    <#
    .DESCRIPTION
        Vuln ID    : V-250313
        STIG ID    : RHEL-07-020022
        Rule ID    : SV-250313r877392_rule
        CCI ID     : CCI-002165, CCI-002235
        Rule Name  : SRG-OS-000324-GPOS-00125
        Rule Title : The Red Hat Enterprise Linux operating system must not allow privileged accounts to utilize SSH.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(getsebool ssh_sysadm_login)

    if ($finding){
        If (((($finding | awk '{$2=$2};1').replace(" ","")).split(">")[1]).ToLower() -eq "off") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system prevents privileged accounts from utilizing SSH."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system does not prevent privileged accounts from utilizing SSH."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system does not prevent privileged accounts from utilizing SSH."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V250314 {
    <#
    .DESCRIPTION
        Vuln ID    : V-250314
        STIG ID    : RHEL-07-020023
        Rule ID    : SV-250314r877392_rule
        CCI ID     : CCI-002165, CCI-002235
        Rule Name  : SRG-OS-000324-GPOS-00125
        Rule Title : The Red Hat Enterprise Linux operating system must elevate the SELinux context when an administrator calls the sudo command.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -r sysadm_r /etc/sudoers /etc/sudoers /etc/sudoers.d/ | grep -s -i "%wheel")
    $finding ?? $($finding = "Check text: No results found.")
    $foundcount = 1

    $finding | ForEach-Object {
        if ((($_ | awk '{$2=$2};1').split(":")[1]) -eq "%wheel ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL") {
            $foundcount++
        }
    }

    if ($finding.count -eq $foundcount - 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system elevates the SELinux context when an administrator calls the sudo command."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not elevate the SELinux context when an administrator calls the sudo command."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V251702 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251702
        STIG ID    : RHEL-07-010291
        Rule ID    : SV-251702r809220_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must not have accounts configured with blank or null passwords.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $command = @'
awk -F: '!$2 {print $1}' /etc/shadow
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The '/etc/shadow' file contains account(s) with blank passwords."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The '/etc/shadow' file does not contain account(s) with blank passwords."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V251703 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251703
        STIG ID    : RHEL-07-010339
        Rule ID    : SV-251703r833183_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must specify the default "include" directory for the /etc/sudoers file.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s include /etc/sudoers)
    $finding_2 = $(grep -s -r include /etc/sudoers.d)

    if (($finding -eq "#includedir /etc/sudoers.d") -and ($null -eq $Finding_2)) {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system specifies only the default 'include' directory for the /etc/sudoers file."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not specifies only the default 'include' directory for the /etc/sudoers file."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V251704 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251704
        STIG ID    : RHEL-07-010344
        Rule ID    : SV-251704r854012_rule
        CCI ID     : CCI-002038
        Rule Name  : SRG-OS-000373-GPOS-00156
        Rule Title : The Red Hat Enterprise Linux operating system must not be configured to bypass password requirements for privilege escalation.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s pam_succeed_if /etc/pam.d/sudo)

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The operating system is configured to bypass password requirements for privilege escalation."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system is not configured to bypass password requirements for privilege escalation."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V251705 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251705
        STIG ID    : RHEL-07-020029
        Rule ID    : SV-251705r880854_rule
        CCI ID     : CCI-002696
        Rule Name  : SRG-OS-000445-GPOS-00199
        Rule Title : The Red Hat Enterprise Linux operating system must use a file integrity tool to verify correct operation of all security functions.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa aide)

    if ($finding) {
        $finding_2 = $(/usr/sbin/aide --check)

        if ($finding_2 -eq "Couldn't open file /var/lib/aide/aide.db for reading"){
            $Status = "Open"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is installed but has not been initialized."
        }
        else{
            $Status = "NotAFinding"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is installed."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V255925 {
    <#
    .DESCRIPTION
        Vuln ID    : V-255925
        STIG ID    : RHEL-07-040712
        Rule ID    : SV-255925r880749_rule
        CCI ID     : CCI-001453
        Rule Name  : SRG-OS-000033-GPOS-00014
        Rule Title : The Red Hat Enterprise Linux operating system SSH server must be configured to use only FIPS-validated key exchange algorithms.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep -s -i ^[[:blank:]]*kexalgorithms /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $finding ?? $($finding = "Check text: No results found.")
    $correct_message_count = 0

    $finding | ForEach-Object { if ((($_.split(":")[1] | awk '{$2=$2};1').replace(" ", "")).ToLower() -eq "kexalgorithmsecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256"){
        $correct_message_count++
    } }
    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH server is configured to use only FIPS-validated key exchange algorithms."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH server is not configured to use only FIPS-validated key exchange algorithms."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V255926 {
    <#
    .DESCRIPTION
        Vuln ID    : V-255926
        STIG ID    : RHEL-07-010090
        Rule ID    : SV-255926r880779_rule
        CCI ID     : CCI-000057
        Rule Name  : SRG-OS-000029-GPOS-00010
        Rule Title : The Red Hat Enterprise Linux operating system must have the screen package installed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa screen)

    If ($Finding) {
        $Status = "NotAFinding"
        $FindingMessage = "The screen package is installed."
    }
    Else {
        $finding_2 = $(rpm -qa tmux)

        If ($Finding_2) {
            $Status = "NotAFinding"
            $FindingMessage = "The tmux package is installed."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "Neither the tmux nor screen package is installed."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V255927 {
    <#
    .DESCRIPTION
        Vuln ID    : V-255927
        STIG ID    : RHEL-07-010375
        Rule ID    : SV-255927r880791_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-OS-000138-GPOS-00069
        Rule Title : The Red Hat Enterprise Linux operating system must restrict access to the kernel message buffer.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(sysctl kernel.dmesg_restrict)
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1){
        $finding_2 = $(grep -s -i ^[[:blank:]]*kernel.dmesg_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")
        $foundcount = 1

        $finding_2 | Foreach-Object {
            if ((($_ | awk '{$2=$2};1').replace(" ", "")).split("=")[1] -eq 1) {
                $foundcount++
            }
        }
        if ($finding_2.count -eq $foundcount-1){
            $Status = "NotAFinding"
            $FindingMessage = "The operating system is configured to restrict access to the kernel message buffer."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system is not configured to restrict access to the kernel message buffer."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system is not configured to restrict access to the kernel message buffer."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V255928 {
    <#
    .DESCRIPTION
        Vuln ID    : V-255928
        STIG ID    : RHEL-07-010199
        Rule ID    : SV-255928r902706_rule
        CCI ID     : CCI-000196
        Rule Name  : SRG-OS-000073-GPOS-00041
        Rule Title : The Red Hat Enterprise Linux operating system must be configured to prevent overwriting of custom authentication configuration settings by the authconfig utility.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(ls -l /etc/pam.d/password-auth)
    $finding_2 = $(ls -l /etc/pam.d/system-auth)

    if (($finding -match "/etc/pam.d/password-auth -> /etc/pam.d/password-auth-local") -and ($finding_2 -match "/etc/pam.d/system-auth -> /etc/pam.d/system-auth-local")){
        $Status = "NotAFinding"
        $FindingMessage = "The operating system 'system-auth' and 'password-auth' files are symbolic links pointing to 'system-auth-local' and 'password-auth-local'."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system 'system-auth' or 'password-auth' files are not symbolic links pointing to 'system-auth-local' or 'password-auth-local'."
    }


    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V256969 {
    <#
    .DESCRIPTION
        Vuln ID    : V-256969
        STIG ID    : RHEL-07-010063
        Rule ID    : SV-256969r902690_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Red Hat Enterprise Linux operating system must disable the login screen user list for graphical user interfaces.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa gnome-shell)

    If (!($Finding)) {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have GNOME installed."
    }
    Else {
        $finding = $(grep -s -iR ^disable-user-list /etc/dconf/db/gdm.d/)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').replace(" ", "").split(":")[1] -eq "disable-user-list=true") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system is configured to disable the login screen user list for graphical user interfaces."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The operating system is not configured to disable the login screen user list for graphical user interfaces."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V256970 {
    <#
    .DESCRIPTION
        Vuln ID    : V-256970
        STIG ID    : RHEL-07-020028
        Rule ID    : SV-256970r902696_rule
        CCI ID     : CCI-001744
        Rule Name  : SRG-OS-000363-GPOS-00150
        Rule Title : The Red Hat Enterprise Linux operating system must be configured to allow sending email notifications of configuration changes and adverse events to designated personnel.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(rpm -qa mailx)

    If ($Finding) {
        $Status = "NotAFinding"
        $FindingMessage = "The mailx package is installed."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The mailx package is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBnxqpPoDBJi8k+
# fxYPVjKsdtwIUWvQUSo35ZMTqcWmCKCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBf8JpsING5Nx6P7Uxn/WxkJTHVIz+S
# B9u64d8dC8l2FDANBgkqhkiG9w0BAQEFAASCAQByNu3lpeKTSxhzBC8bSYlQKzd6
# sDZRITVqQP3zOfUc7d6Yh4WbH5m+x3jqF3SCVrmy81JQyEN0AzurYDlkCyyrk/3R
# 09moe34eFndYUfbbpmFGd1nRdVxHm6aVtdc3PK+mSeHyS7E1zZFfZvYrzQZwp4cW
# ezrIaGAnBFxlh805A65KirpGjNQZkBfRV5rvkeS2YEScjNdlejKshHcj0XSKFxvi
# O45/ZoHfdjiuPp3mqK0DrHBpRt8156w0bgAHTPvgFNGRXIXXnMpVGejIgQPt63Wr
# rAeQmZgM47HlCCYWQIV6ds8cWhOiGV/XEtQIrPOrLEjQFMb3wlkSj66XFfSV
# SIG # End signature block
