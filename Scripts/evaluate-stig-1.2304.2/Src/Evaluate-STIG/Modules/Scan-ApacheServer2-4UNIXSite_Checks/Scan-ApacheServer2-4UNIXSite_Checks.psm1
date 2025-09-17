##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Apache Server 2.4 UNIX Site
# Version:  V2R3
# Class:    UNCLASSIFIED
# Updated:  4/25/2023
# Author:   U.S. Army Communications-Electronics Command, Software Engineering Center (CECOM SEC)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V214277 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214277
        STIG ID    : AS24-U2-000020
        Rule ID    : SV-214277r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000002
        Rule Title : The Apache web server must perform server-side session management.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $ApacheModules = @("session_module", "usertrack_module")
    $ExpectedState = "Enabled"

    foreach ($ApacheModule in $ApacheModules) {
        $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModule
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState

        if ($ModuleStatus.Status -eq "Disabled") {
            $ErrorCount++
        }
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
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

Function Get-V214278 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214278
        STIG ID    : AS24-U2-000030
        Rule ID    : SV-214278r881466_rule
        CCI ID     : CCI-000068, CCI-000197, CCI-000213, CCI-000803, CCI-001166, CCI-001453, CCI-002448, CCI-002450, CCI-002452, CCI-002506
        Rule Name  : SRG-APP-000014-WSR-000006
        Rule Title : The Apache web server must use encryption strength in accordance with the categorization of data hosted by the Apache web server when remote connections are provided.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FoundOne = 0
    $ApacheModuleName = "ssl_module"
    $ExpectedValue = "Enabled"
    $ModuleResult = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleResult -ExpectedValue $ExpectedValue

    if ($ModuleResult.Status -eq "Disabled") {
        $ErrorCount++
    }
    else {
        $ExpectedValue = "-ALL +TLSv1.2"
        $Directive = "SSLProtocol"
        $Results = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $Directive
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $Results -ExpectedValue $ExpectedValue
        foreach ($directive in $Results) {
            if ($directive.Status -eq "Not Found") {
                continue
            }

            $ConfigLine = $directive.ConfigFileLine | Select-String -Pattern "\+TLSv1.[2|3]" | Select-String -Pattern "\-ALL"
            if ($null -eq $ConfigLine -or $ConfigLine -eq "") {
                $ErrorCount++
                break
            }
            else {
                $ConfigLine = $ConfigLine -replace "SSLProtocol", "" -replace "\+TLSv1.[2|3]", "" -replace "\-ALL", "" -replace "\-\S+", ""
                if ($ConfigLine.Trim() -ne "") {
                    $ErrorCount++
                    break
                }
                $FoundOne++
            }
        }

        if ($ErrorCount -ge 1) {
            $Status = "Open"
        }
        else {
            if ($FoundOne -ge 1) {
                $Status = "NotAFinding"
            }
            else {
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

Function Get-V214279 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214279
        STIG ID    : AS24-U2-000090
        Rule ID    : SV-214279r881469_rule
        CCI ID     : CCI-000130
        Rule Name  : SRG-APP-000095-WSR-000056
        Rule Title : The Apache web server must produce log records containing sufficient information to establish what type of events occurred.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $ApacheModuleName = "log_config_module"
    $ExpectedValue = "Enabled"

    $ModuleObject = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleObject -ExpectedValue $ExpectedValue
    if ($ModuleObject.Status -eq "Disabled") {
        $ErrorCount++
    }

    $FoundValueCount = 0
    $DirectiveName = "LogFormat"
    $ExpectedValue = '"%a %A %h %H %l %m %s %t %u %U"'
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($directiveLine in $FoundValues) {
        if ($directiveLine.Status -eq "Not Found") {
            continue
        }
        $FoundValueCount++
    }

    if ($FoundValueCount -le 0 -or $ErrorCount -ge 1) {
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

Function Get-V214281 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214281
        STIG ID    : AS24-U2-000300
        Rule ID    : SV-214281r881472_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000081
        Rule Title : The Apache web server must have Multipurpose Internet Mail Extensions (MIME) that invoke operating system shell programs disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FoundCount = 0

    $ApacheModuleName = "ssl_module"
    $ExpectedState = "Enabled"
    $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState


    $Directives = @("AddHandler", "Action") # Directives identified in STIG
    $ExpectedValue = "Directive does not contain '.exe' '.dll' '.com' '.bat' or '.csh' or other shell MIME types."
    foreach ($directive in $Directives) {

        $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $directive
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

        if ($null -ne $DirectiveResults -or $DirectiveResults -ne "") {
            foreach ($foundDirective in $DirectiveResults) {

                if ($foundDirective.Status -eq "Not Found") {
                    continue
                }

                $FoundCount++
                break
            }
        }
    }

    if ($ModuleStatus.Status -eq "Disabled") {
        $Status = "Open"
    }
    else {
        if ($FoundCount -eq 0) {
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

Function Get-V214282 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214282
        STIG ID    : AS24-U2-000310
        Rule ID    : SV-214282r881475_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000082
        Rule Title : The Apache web server must allow mappings to unused and vulnerable scripts to be removed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DirectivesToFind = @('Script', 'ScriptAlias', 'ScriptAliasMatch', 'ScriptInterpreterSource')
    $ExpectedValue = "Must be needed for application operation"
    $NeedsChecking = 0
    foreach ($DirectiveToFind in $DirectivesToFind) {
        $AllDirectiveLines = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveToFind
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $AllDirectiveLines -ExpectedValue $ExpectedValue
        foreach ($line in $AllDirectiveLines) {
            if ($line.status -ne "Not Found") {
                $NeedsChecking++
            }
        }
    }
    if ($NeedsChecking -eq 0) {
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

Function Get-V214283 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214283
        STIG ID    : AS24-U2-000320
        Rule ID    : SV-214283r881478_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000083
        Rule Title : The Apache web server must have resource mappings set to disable the serving of certain file types.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $HasFoundDirectives = $false
    $Directives = @("AddHandler", "Action") # Directives identified in STIG
    $ExpectedValue = "Directive does not contain '.exe' '.dll' '.com' '.bat' or '.csh' MIME types."
    foreach ($directive in $Directives) {
        $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $directive
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue
        foreach ($foundDirective in $DirectiveResults) {
            if ($foundDirective.Status -eq "Not Found") {
                continue
            }

            $HasFoundDirectives = $true
            break
        }
    }

    # We haven't found anything so no need to mark this check as Not_Reviewed
    if ($HasFoundDirectives -eq $false) {
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

Function Get-V214284 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214284
        STIG ID    : AS24-U2-000350
        Rule ID    : SV-214284r881481_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000087
        Rule Title : Users and scripts running on behalf of users must be contained to the document root or home directory tree of the Apache web server.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $RequireFoundCount = 0
    $AllowDenyFoundCount = 0
    $startBlock = "Directory\s+\`"?/\`"?"
    $endBlock = "Directory"
    $DirectiveCheck = 'Require\s+all\s+denied'
    $ExpectedValue = "Require all denied"

    $DirectiveResults = Get-ApacheDirectiveFromBlock -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -BlockStart $startBlock -BlockEnd $endBlock -DirectivePattern $DirectiveCheck
    foreach ($foundDirective in $DirectiveResults) {
        $foundDirective.Name = "Require"
    }
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

    foreach ($foundDirective in $DirectiveResults) {
        if ($foundDirective.Status -eq "Not Found") {
            continue
        }

        $RequireFoundCount++
    }

    $DirectivesToChecks = @("Allow", "Deny")
    $ExpectedValue = "None Found"
    foreach ($directive in $DirectivesToChecks) {

        $DirectiveResults = Get-ApacheDirectiveFromBlock -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -BlockStart $startBlock -BlockEnd $endBlock -DirectivePattern $directive
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

        foreach ($foundDirective in $DirectiveResults) {
            if ($foundDirective.Status -eq "Not Found") {
                continue
            }

            $AllowDenyFoundCount++
        }
    }

    if (($RequireFoundCount -ne 1) -or ($AllowDenyFoundCount -gt 0)) {
        $Status = "Open"
    }
    else {
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

Function Get-V214285 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214285
        STIG ID    : AS24-U2-000360
        Rule ID    : SV-214285r881484_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-WSR-000089
        Rule Title : The Apache web server must be configured to use a specified IP address and port.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $Directive = "^\s*<VirtualHost"
    $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $Directive
    $ExpectedValue = "VirtualHost directives must contain an IP address and port"

    foreach ($foundDirective in $DirectiveResults) {
        $foundDirective.Name = "VirtualHost"
        if ($foundDirective.Status -eq "Not Found") {
            continue
        }

        $Ipv4Pattern = "^\s*<VirtualHost\s([0-9]{1,3}\.?){4}:[0-9]{1,5}"
        $Ipv6Pattern = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\]:\d{1,5}'
        $Test = $foundDirective.ConfigFileLine | Select-String -Pattern $IPv4Pattern, $IPv6Pattern

        if ($null -eq $Test -or $Test -eq "") {
            $ErrorCount++
        }
    }

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

    if ($ErrorCount -ge "1") {
        $Status = "Open"
    }
    else {
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

Function Get-V214286 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214286
        STIG ID    : AS24-U2-000380
        Rule ID    : SV-214286r881487_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175-WSR-000095
        Rule Title : The Apache web server must perform RFC 5280-compliant certification path validation.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $ApacheModuleName = "ssl_module"
    $ExpectedValue = "Enabled"

    $ModuleObject = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleObject -ExpectedValue $ExpectedValue
    if ($ModuleObject.Status -eq "Disabled") {
        $ErrorCount++
    }

    $SSLVerifyClient = "SSLVerifyClient"
    $SSLVerifyDepth = "SSLVerifyDepth"
    $Directives = @($SSLVerifyDepth, $SSLVerifyClient) # Directives identified in STIG
    foreach ($directive in $Directives) {

        if ($directive -eq $SSLVerifyDepth) {
            $Pattern = [regex]('^\s*[0]\s*$')
            $ExpectedValue = "Must exist and must NOT be set to '0'"
        }
        elseif ($directive -eq $SSLVerifyClient) {
            $Pattern = [regex]('require\b')
            $ExpectedValue = "Must be set to 'require'"
        }

        $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $directive
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

        foreach ($foundDirective in $DirectiveResults) {

            if ($foundDirective.Status -eq "Not Found") {
                $ErrorCount++
                continue
            }

            $Test = ($foundDirective.ConfigFileLine.ToString() -split '\s+')[1]
            $Test = $Test | Select-String -Pattern $Pattern

            if ($directive -eq $SSLVerifyClient) {
                if ($null -eq $Test -or $Test -eq "") {
                    $ErrorCount++
                }
            }
            elseif ($directive -eq $SSLVerifyDepth) {
                if ($null -eq $Test -or $Test -eq "") {
                    continue
                }

                $ErrorCount++
            }
        }
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
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

Function Get-V214287 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214287
        STIG ID    : AS24-U2-000390
        Rule ID    : SV-214287r881490_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176-WSR-000096
        Rule Title : Only authenticated system administrators or the designated PKI Sponsor for the Apache web server must have access to the Apache web servers private key.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $WarningCount = 0
    $StandardUsers = @()

    $ApacheModuleName = "ssl_module"
    $ExpectedValue = "Enabled"
    $Result = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $Result -ExpectedValue $ExpectedValue

    if ($Result.Status -eq "Disabled") {
        $ErrorCount++
    }

    $DirectiveName = "SSLCertificateKeyFile"
    $ExpectedValue = "Inaccessible by unauthorized and unauthenticated users."
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    $GetApacheUserLine = "$($ApacheInstance.ExecutablePath) -S"
    $ApacheUserLine = Invoke-Expression $GetApacheUserLine
    $ApacheServiceUser = ( $ApacheUserLine | grep "User:" | sed -e 's/^.*name=\"//' -e 's/\".*$//')

    $LocalUsers = Get-Content /etc/passwd | Select-String -NotMatch "nologin" | ForEach-Object {$_.ToString().Split(":")[0]}

    foreach ( $user in $LocalUsers ) {
        if ( -Not ( "$user" -eq "$ApacheServiceUser" ) ) {
            $Priv = $(sudo -l -U $user)
            if ($null -eq $Priv) {
                continue
            }

            if ( $Priv.Contains("is not allowed to run sudo") ) {
                $StandardUsers += $user
            }
        }
    }

    $FoundCount = 0
    foreach ( $directive in $FoundValues ) {
        if ($directive.Status -eq "Not Found") {
            continue
        }
        $FoundCount++

        $file = $directive.ConfigFileLine.Split(" ")[1]
        $FindingDetails += "Checking File Access Modes: [$($file)]" | Out-String

        $file = $file -replace '"', ''

        if ( -Not (Test-Path -Path $file -PathType Leaf)) {
            $FindingDetails += "`tFile [$($file)] does not exist`n" | Out-String
            $ErrorCount++
            continue
        }

        $firstLine = 1
        foreach ( $user in $StandardUsers ) {

            $HasAccess = $(sudo -u $user test -r $file && echo true || echo false)
            if ( $HasAccess.Contains("true" )) {
                $ErrorCount++
                $FindingDetails += "`tStandard user [$($user)] has read access" | Out-String
                $firstLine = 0
            }
        }
        if ($firstLine -eq 0) {
            $FindingDetails += "" | Out-String
        }

        $AllUsers = Get-Content /etc/passwd | ForEach-Object {$_.ToString().Split(":")[0]}
        $UserFileAccess = $(stat -L -c "%U" $file)
        $FindingDetails += "`tFile owner [$($UserFileAccess)]"
        if ( -not ($AllUsers.Contains($UserFileAccess)) ) {
            $FindingDetails += " is not a local user and has access" | Out-String
            $WarningCount++
        }
        else {
            $FindingDetails += "" | Out-String
        }

        $AllGroups = Get-Content /etc/group | ForEach-Object {$_.ToString().Split(":")[0]}
        $GroupFileAccess = $(stat -L -c "%G" $file)
        $FindingDetails += "`tFile group [$($GroupFileAccess)]"
        if ( -not ($AllGroups.Contains($GroupFileAccess)) ) {
            $FindingDetails += " is not a local group and has access" | Out-String
            $WarningCount++
        }
        else {
            $FindingDetails += "" | Out-String
        }

        $OtherFileAccess = $(stat -L -c "%A" $file | cut -c8-10)
        $FindingDetails += "`tFile others access mode [$($OtherFileAccess)]"
        if ( $OtherFileAccess -match "[rw]" ) {
            $FindingDetails += " grants Others access" | Out-String
            $ErrorCount++
        }

        $FindingDetails += "" | Out-String
    }

    if ($FoundCount -gt 0) {
        if ($ErrorCount -eq 0) {
            if ( $WarningCount -eq 0 ) {
                $Status = "NotAFinding"
            }
        }
        else {
            $Status = "Open"
        }
    }
    else {
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

Function Get-V214288 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214288
        STIG ID    : AS24-U2-000470
        Rule ID    : SV-214288r881493_rule
        CCI ID     : CCI-001664
        Rule Name  : SRG-APP-000223-WSR-000011
        Rule Title : Cookies exchanged between the Apache web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating Apache web server and hosted application.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $DirectiveName = "Header*.*Set-Cookie"
    $ExpectedValue = "Must include 'httpOnly' and 'secure'"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    foreach ($line in $FoundValues) {
        #Format Directive Name
        $line.Name = "Header"
        if ($line.Status -eq "Not Found") {
            continue
        }

        $ContainsHttpOnlySecure = [bool] ($line | Select-String -Pattern "$($DirectiveName)\b\s.*\b(httponly.*secure|secure.*httponly)\b" -Quiet)
        if ($ContainsHttpOnlySecure -eq $true) {
            continue # Our Pattern Matches therefore directive is good end loop.
        }

        #Directive matches but expected value missing exit loop
        $ErrorCount++
        break
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V214290 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214290
        STIG ID    : AS24-U2-000580
        Rule ID    : SV-214290r879643_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233-WSR-000146
        Rule Title : The Apache web server document directory must be in a separate partition from the Apache web servers system files.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $DirectiveName = "DocumentRoot"
    $ExpectedValue = "The DocumentRoot path must NOT be on the same partition as the web server system files or the operating system file systems."

    $RootPartition = ""
    $RootPattern = "^/$"
    $Command = "df -k"
    $FileSystemInfo = @(Invoke-Expression -Command $Command)

    foreach ($line in $FileSystemInfo) {
        $MountedOn = ($line -split '\s+')[5]
        $IsRootLine = $MountedOn | Select-String -Pattern $RootPattern
        if ($null -eq $IsRootLine -or $IsRootLine -eq "") {
            continue
        }

        $RootPartition = ($line -split '\s+')[0]
        break
    }

    $HttpdPartition = ""
    $RootPattern = "^/$"
    $Command = "df -k $($ApacheInstance.HttpdRootPath)"
    $FileSystemInfo = @(Invoke-Expression -Command $Command)

    foreach ($line in $FileSystemInfo) {
        $MountedOn = ($line -split '\s+')[5]
        $IsRootLine = $MountedOn | Select-String -Pattern $RootPattern
        if ($null -eq $IsRootLine -or $IsRootLine -eq "") {
            continue
        }

        $HttpdPartition = ($line -split '\s+')[0]
        break
    }

    $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    foreach ($directiveResult in $DirectiveResults) {

        $FindingDetails += "Directive:`t`t`t`t`t$($directiveResult.Name)" | Out-String
        $FindingDetails += "Expected Value:`t`t`t$($ExpectedValue)" | Out-String
        $FindingDetails += "Detected Value:`t`t`t$($directiveResult.ConfigFileLine)" | Out-String

        if ($directiveResult.Status -ne "Not Found") {
            $DocumentRootPath = (($directiveResult.ConfigFileLine -split '\s+')[1]).Trim()
            $Command = "df -k $($DocumentRootPath)"
            $DirectivePartition = ((((Invoke-Expression -Command $Command)[1]) -split '\s+')[0]).Trim()

            if (($DirectivePartition -eq $RootPartition) -or ($DirectivePartition -eq $HttpdPartition)) {
                $ErrorCount++
            }

            $FindingDetails += "$($DirectiveName) Partition:`t`t$($DirectivePartition)" | Out-String
            $FindingDetails += "Root Partition:`t`t`t`t$($RootPartition)" | Out-String
            $FindingDetails += "Httpd Partition:`t`t`t$($HttpdPartition)" | Out-String
        }

        $FindingDetails += "In File:`t`t`t`t`t$($directiveResult.ConfigFile)" | Out-String
        $FindingDetails += "On Line:`t`t`t`t`t$($directiveResult.LineNumber)" | Out-String

        if ($null -ne $directiveResult.VirtualHost) {
            $FindingDetails += "Config Level:`t`t`t`tVirtual Host" | Out-String
            $FindingDetails += "Site Name:`t`t`t`t$($directiveResult.VirtualHost.SiteName)" | Out-String
        }
        else {
            $FindingDetails += "Config Level:`t`t`t`tGlobal" | Out-String
        }

        $FindingDetails += "" | Out-String
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
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

Function Get-V214291 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214291
        STIG ID    : AS24-U2-000590
        Rule ID    : SV-214291r881496_rule
        CCI ID     : CCI-001094, CCI-002415
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : The Apache web server must be tuned to handle the operational requirements of the hosted application.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $GoodDirective = 0
    $BadDirective = 0
    $DirectiveName = "Timeout"
    $ExpectedValue = "10 or Less"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($directive in $FoundValues) {
        if ($directive.Status -eq "Not Found") {
            continue
        }
        $MaxTimeout = $directive.ConfigFileLine.ToString().Split()[1] -as [int]
        if ($MaxTimeout -le 10) {
            $GoodDirective++
            continue
        }
        $BadDirective++
        break
    }

    if ($GoodDirective -gt 0 -and $BadDirective -eq 0) {
        $Status = "NotAFinding"
    }
    else {
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

Function Get-V214292 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214292
        STIG ID    : AS24-U2-000620
        Rule ID    : SV-214292r881498_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000142
        Rule Title : The Apache web server must display a default hosted application web page, not a directory listing, when a requested web page cannot be found.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $DirectiveName = "DocumentRoot"
    $ExpectedValue = "'DocumentRoot' directory and subdirectories contain 'index.html' or equivalent default document"
    $DirectoriesChecked = [System.Collections.ArrayList]@()
    $BadDirectories = [System.Collections.ArrayList]@()
    $DocumentRoots = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DocumentRoots -ExpectedValue $ExpectedValue

    $DIDirectiveName = "DirectoryIndex"
    $DirectoryIndexes = [System.Collections.ArrayList]@()
    $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DIDirectiveName

    foreach ($directoryIndex in $DirectiveResults) {
        if ($directoryIndex.Status -eq "Not Found") {
            continue
        }

        [void]$DirectoryIndexes.Add("$($directoryIndex.ConfigFileLine.Split(" ")[1])")
    }

    if ($DirectoryIndexes.Count -ge 1 ) {
        $FindingDetails += "Default Documents: [$($DirectoryIndexes)]`n" | Out-String
    }
    else {
        $FindingDetails += "Default Documents: $($DIDirectiveName) not set.`n" | Out-String
    }

    foreach ($documentRoot in $DocumentRoots) {

        if ($documentRoot.Status -eq "Not Found") {
            continue
        }

        $DirectoryPath = (($documentRoot.ConfigFileLine -replace $DirectiveName, '').Trim() -replace '"', '')
        $DirectoryPath = $DirectoryPath -replace '\\', '\'
        # Did all of that to normalize the path.

        if ($DirectoriesChecked -contains $DirectoryPath) {
            continue
        }

        $FindingDetails += "Checking directory $($DirectoryPath) and subdirectories for 'index.html' and default documents:" | Out-String

        [void]$DirectoriesChecked.Add("$($DirectoryPath)")

        if (Test-Path -Path $DirectoryPath) {
            # True if our directory actually exists.
            $indexHtmlFiles = Get-ChildItem -Path $DirectoryPath -File -Filter "index.htm*"
            if ($null -eq $indexHtmlFiles) {
                # This should take care of the parent directory.
                [void]$BadDirectories.Add("$($DirectoryPath)")
                $ErrorCount ++
            }

            # Recurse through each directory and subdirecto
            $SubDirectories = Get-ChildItem -Path $DirectoryPath -Recurse -Force -Directory
            if ($null -ne $SubDirectories -and $SubDirectories.Count -ge 1) {
                foreach ($subDirectory in $SubDirectories) {
                    $files = Get-ChildItem -Path $subDirectory.FullName -Force

                    $containsDefault = $files | ForEach-Object {$FileName = $_.Name; ($DirectoryIndexes | ForEach-Object {$FileName.contains($_) -or $FileName.Contains('index.htm')}) -contains $true}

                    if (($null -eq $containsDefault) -or (-Not ($containsDefault.Contains($true)))) {
                        [void]$BadDirectories.Add("$($subDirectory.FullName)")
                        $ErrorCount ++
                    }
                }
            }
        }
        else {
            $FindingDetails += "$($DirectoryPath) does not exist." | Out-String
            $ErrorCount ++
        }
    }

    $FindingDetails += "" | Out-String

    if ($ErrorCount -ge 1) {
        $Status = "Not_Reviewed"
        if ($BadDirectories.Count -ge 1) {
            $FindingDetails += "The following directories do not contain an 'index.html' or equivalent default documents file:" | Out-String
            foreach ($directory in $BadDirectories) {
                $FindingDetails += $directory | Out-String
            }
        }
    }
    else {
        $FindingDetails += "'index.html' or equivalent default documents file found." | Out-String
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

Function Get-V214293 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214293
        STIG ID    : AS24-U2-000630
        Rule ID    : SV-214293r881501_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : Warning and error messages displayed to clients must be modified to minimize the identity of the Apache web server, patches, loaded modules, and directory paths.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $GoodDirective = 0
    $ApacheModuleName = "ssl_module"
    $ExpectedValue = "Enabled"
    $Results = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $Results -ExpectedValue $ExpectedValue

    if ($ModuleObject.Status -eq "Disabled") {
        $ErrorCount++
    }
    $DirectiveName = "ErrorDocument"
    $ExpectedValue = "Configured and the error messages must not be too descriptive."
    $DirectiveResults = Get-ApacheDirective -ApacheInstance $Global:ApacheInstance -VirtualHost $Global:VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

    foreach ($foundDirective in $DirectiveResults) {
        if ($foundDirective.Status -eq "Not Found") {
            continue
        }
        $GoodDirective++
        break
    }

    If ($ErrorCount -eq 0 -and $GoodDirective -gt 0) {
        $Status = "Not_Reviewed"
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

Function Get-V214294 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214294
        STIG ID    : AS24-U2-000640
        Rule ID    : SV-214294r881504_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000160
        Rule Title : Debugging and trace information used to diagnose the Apache web server must be disabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $GoodDirective = 0
    $BadDirective = 0
    $DirectiveName = "TraceEnable"
    $ExpectedValue = "Off"
    $DirectivesFound = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $DirectivesFound -ExpectedValue $ExpectedValue

    foreach ($found In $DirectivesFound ) {
        if ($found.Status -eq "Not Found") {
            continue
        }
        $FoundValue = ($found.ConfigFileLine.ToString() -split '\s+')[1]
        $FoundValue = $FoundValue | Select-String -Pattern $ExpectedValue
        if ($ExpectedValue -eq $FoundValue) {
            $GoodDirective++
        }
        else {
            $BadDirective++
        }
    }

    if ($GoodDirective -ge 1 -and $BadDirective -eq 0) {
        $Status = "NotAFinding"
    }
    else {
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

Function Get-V214295 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214295
        STIG ID    : AS24-U2-000650
        Rule ID    : SV-214295r881507_rule
        CCI ID     : CCI-002391
        Rule Name  : SRG-APP-000295-WSR-000012
        Rule Title : The Apache web server must set an absolute timeout for sessions.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FoundCount = 0
    $DirectiveName = "SessionMaxAge"
    $ExpectedValue = "600 or Less"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($directiveValue In $FoundValues ) {
        if ($directiveValue.Status -eq "Not Found") {
            continue
        }

        $FoundCount++

        $MaxAge = ($directiveValue.ConfigFileLine.ToString() -split '\s+')[1] -as [int]
        if ($MaxAge -le "600") {
            continue
        }

        $ErrorCount++
        break
    }

    if ($ErrorCount -ge 1 -or $FoundCount -le 0) {
        $Status = "Open"
    }
    else {
        # All SessionMaxAge Directives found meet the requirements of the STIG.
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

Function Get-V214296 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214296
        STIG ID    : AS24-U2-000660
        Rule ID    : SV-214296r881509_rule
        CCI ID     : CCI-002391
        Rule Name  : SRG-APP-000295-WSR-000134
        Rule Title : The Apache web server must set an inactive timeout for sessions.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FoundCount = 0
    $TimeOutErrorCount = 0
    $Patterns = @('stage\s*=\s*\d+', 'handshake\s*=\s*\d+', 'header\s*=\s*\d+', 'body\s*=\s*\d+', 'maxtimeout\s*=\s*\d+')
    $ApacheModuleName = "reqtimeout_module"
    $ExpectedState = "Enabled"
    $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState

    $DirectiveName = "RequestReadTimeout"
    $ExpectedValue = "Must be explicitly configured"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    if ($ModuleStatus.Status -eq "Disabled") {
        $ErrorCount++
    }
    foreach ($line in $FoundValues) {
        if ($line.Status -eq "Not Found") {
            continue
        }
        #Directive Found
        $FoundCount++
        $LineToTest = ($line.ConfigFileLine.ToString() -split ',')
        #split FoundValues  to parse timeout for pattern test
        #loop for timeout patterns
        Foreach ($timeout in $Patterns) {
            Foreach ($testline in $LineToTest) {
                #match pattern e.g. header with Regex pattern to get int values from timeout patterns
                $TimeoutValue = ($testline | Select-String -Pattern $timeout).Matches.Value -replace "^*.*="
                if ($TimeoutValue -ne "") {
                    #test if timeout value is greater than maximum allowed 20 minutes and warn
                    if ([int]$TimeoutValue -gt 1200 -or [int]$TimeoutValue -eq 0) {
                        $TimeOutErrorCount++
                    }
                }
            }
        }
    }
    if ($ErrorCount -ge 1 -or $FoundCount -le 0 -or $TimeOutErrorCount -ge 1) {
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

Function Get-V214297 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214297
        STIG ID    : AS24-U2-000680
        Rule ID    : SV-214297r881511_rule
        CCI ID     : CCI-002344
        Rule Name  : SRG-APP-000315-WSR-000004
        Rule Title : The Apache web server must restrict inbound connections from nonsecure zones.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $HasFoundAValue = $false
    $startBlock = "RequireAll"
    $endBlock = "RequireAll"
    $DirectiveCheck = "Require"
    $ExpectedValue = "Restrict IPs from nonsecure zones."

    $DirectiveResults = Get-ApacheDirectiveFromBlock -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -BlockStart $startBlock -BlockEnd $endBlock -DirectivePattern $DirectiveCheck
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

    foreach ($foundValue in $DirectiveResults) {
        if ($foundValue.Status -eq "Not Found") {
            continue
        }

        $HasFoundAValue = $true
        break
    }

    if ($HasFoundAValue -eq $false) {
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

Function Get-V214299 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214299
        STIG ID    : AS24-U2-000780
        Rule ID    : SV-214299r879753_rule
        CCI ID     : CCI-001843
        Rule Name  : SRG-APP-000380-WSR-000072
        Rule Title : The Apache web server application, libraries, and configuration files must only be accessible to privileged users.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ShellsExist = Get-Content /etc/shells
    $UsersWithShell = Get-Content /etc/passwd | Select-String -Pattern $ShellsExist | ForEach-Object {$_.ToString().Split(":")[0]}
    $UsersWithSudo = (getent -s files passwd | ForEach-Object {([String]$_).Split(":")[0]} | sudo xargs -L1 sudo -l -U | Out-String -Stream | Select-String -Pattern "may run" -NoEmphasis)
    $FindingDetails += "Users with sudo and shell access:" | Out-String

    Foreach ($User in $UsersWithSudo) {
        $SudoUserList += $User | ForEach-Object { $_.ToString().Trim("> ") -replace '^User ' -replace ' may run*.*' } | Out-String
    }

    $SudoUserList = $SudoUserList.Split()

    Foreach ($User in $UsersWithShell) {
        $TestMatch = [regex]::Match($SudoUserList, $User).Value
        $TestMatch = $TestMatch | Where-Object {$_ -ne ""}
        $FindingDetails += $TestMatch | Out-String
    }
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V214300 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214300
        STIG ID    : AS24-U2-000810
        Rule ID    : SV-214300r881513_rule
        CCI ID     : CCI-002500
        Rule Name  : SRG-APP-000427-WSR-000186
        Rule Title : The Apache web server must only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FoundCert = 0

    $ApacheModuleName = "ssl_module"
    $ExpectedValue = "Enabled"

    $ModuleObject = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleObject -ExpectedValue $ExpectedValue
    if ($ModuleObject.Status -eq "Disabled") {
        $ErrorCount++
    }

    $DirectiveName = "SSLCACertificateFile"
    $ExpectedValue = "Issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs)"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($line In $FoundValues ) {
        if ($line.Status -eq "Not Found") {
            continue
        }

        $caFilePath = $line.ConfigFileLine.ToString().Split(' ')[1]

        $FileFound = $false

        #check unaltered directive path
        $filePath = $caFilePath
        if (Test-Path -Path "$filePath") {
            $FileFound = $true
            $FoundCert++
        }

        #check relative path
        if ($FileFound -ne $true) {
            $filePath = Join-Path -Path $ApacheInstance.HttpdRootPath -ChildPath $caFilePath
            if (Test-Path -Path "$filePath") {
                $FileFound = $true
                $FoundCert++
            }
        }

        if ($FileFound -eq $true) {
            $Command = "find / -type f -name openssl | head -1"
            $opensslPath = @(Invoke-Expression -Command $Command)
            if (Test-Path -Path "$opensslPath") {
                $opensslCommandOutput = & "$opensslPath" x509 -noout -text -purpose -in $filePath | Out-String
                $directiveIndex = $FindingDetails.IndexOf($caFilePath)
                $onLineIndex = $FindingDetails.IndexOf("On Line", $directiveIndex)
                $insertIndex = $FindingDetails.IndexOf("`n", $onLineIndex)
                $FindingDetails = $FindingDetails.Insert($insertIndex, "`n`n$opensslCommandOutput") | Out-String
            }
        }
        else {
            $ErrorCount++
        }
    }

    if (($ErrorCount -ne 0) -or ($FoundCert -eq 0)) {
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

Function Get-V214301 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214301
        STIG ID    : AS24-U2-000870
        Rule ID    : SV-214301r881516_rule
        CCI ID     : CCI-002448
        Rule Name  : SRG-APP-000439-WSR-000153
        Rule Title : The Apache web server cookies, such as session cookies, sent to the client using SSL/TLS must not be compressed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FoundCount = 0

    $ApacheModuleName = "ssl_module"
    $ExpectedValue = "Enabled"
    $ModuleResult = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleResult -ExpectedValue $ExpectedValue

    if ($ModuleResult.Status -eq "Disabled") {
        $ErrorCount++
    }

    $DirectiveName = "SSLCompression"
    $ExpectedValue = "Set to `"Off`""
    $Pattern = "\s*\boff\b\s*"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($line in $FoundValues) {
        if ($line.Status -eq "Not Found") {
            continue
        }

        $FoundCount++

        $DirectiveValue = ($line.ConfigFileLine.ToString() -split '\s+')[1]
        $IsOff = $DirectiveValue | Select-String -Pattern $Pattern
        if ($null -eq $IsOff -or $IsOff -eq "") {
            $ErrorCount++
            break
        }
    }

    If ($ErrorCount -ge 1 -or $FoundCount -le 0) {
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

Function Get-V214302 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214302
        STIG ID    : AS24-U2-000880
        Rule ID    : SV-214302r881518_rule
        CCI ID     : CCI-002448
        Rule Name  : SRG-APP-000439-WSR-000154
        Rule Title : Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to prohibit client-side scripts from reading the cookie data.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $FoundCount = 0
    $DirectiveName = "Session"
    $ExpectedValue = "Set to `"On`""
    $Pattern = "\bon\b"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($line in $FoundValues) {
        if ($line.Status -eq "Not Found") {
            continue
        }

        $FoundCount++

        $DirectiveValue = (($line.ConfigFileLine.ToString() -split '\s+')[1]).Trim()
        $IsOn = [bool] ($DirectiveValue | Select-String -Pattern $Pattern -Quiet)
        if ($IsOn -eq $true) {
            continue
        }

        $ErrorCount++
        break
    }

    if ($FoundCount -le 0) {
        $ErrorCount++
    }

    $FoundCount = 0
    $DirectiveName = "SessionCookieName"
    $ExpectedValue = "Contains 'HttpOnly', 'Secure' and not 'Domain' settings"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($line in $FoundValues) {
        if ($line.Status -eq "Not Found") {
            continue
        }

        $FoundCount++

        $ContainsHttpOnly = [bool] ($line | Select-String -Pattern "$($DirectiveName)\b\s.*;\s*httponly\s*;" -Quiet)
        $ContainsSecure = [bool] ($line | Select-String -Pattern "$($DirectiveName)\b\s.*;\s*secure\s*;" -Quiet)
        if ($ContainsHttpOnly -eq $true -and $ContainsSecure -eq $true) {
            continue
        }

        $ErrorCount++
        break
    }

    if ($FoundCount -le 0) {
        $ErrorCount++
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
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

Function Get-V214303 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214303
        STIG ID    : AS24-U2-000890
        Rule ID    : SV-214303r881521_rule
        CCI ID     : CCI-002448
        Rule Name  : SRG-APP-000439-WSR-000155
        Rule Title : Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to force the encryption of cookies.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0
    $ApacheModuleName = "session_cookie_module"
    $ExpectedState = "Enabled"
    $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState

    if ($ModuleStatus.Status -eq "Disabled") {
        $ErrorCount++
    }

    $FoundCount = 0
    $DirectiveName = "Session"
    $ExpectedValue = "Set to `"On`""
    $Pattern = "\bon\b"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($line in $FoundValues) {
        if ($line.Status -eq "Not Found") {
            continue
        }

        $FoundCount++

        $DirectiveValue = (($line.ConfigFileLine.ToString() -split '\s+')[1]).Trim()
        $IsOn = [bool] ($DirectiveValue | Select-String -Pattern $Pattern -Quiet)
        if ($IsOn -eq $true) {
            continue
        }

        $ErrorCount++
        break
    }

    if ($FoundCount -le 0) {
        $ErrorCount++
    }

    $FoundCount = 0
    $DirectiveName = "SessionCookieName"
    $ExpectedValue = "Contains `"HttpOnly`", `"Secure`" settings"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($line in $FoundValues) {
        if ($line.Status -eq "Not Found") {
            continue
        }

        $FoundCount++

        $ContainsHttpOnly = [bool] ($line | Select-String -Pattern "$($DirectiveName)\b\s.*;\s*httponly\s*;" -Quiet)
        $ContainsSecure = [bool] ($line | Select-String -Pattern "$($DirectiveName)\b\s.*;\s*secure\s*;" -Quiet)
        if ($ContainsHttpOnly -eq $true -and $ContainsSecure -eq $true) {
            continue
        }

        $ErrorCount++
        break
    }

    if ($FoundCount -le 0) {
        $ErrorCount++
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
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

Function Get-V214304 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214304
        STIG ID    : AS24-U2-000960
        Rule ID    : SV-214304r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The Apache web server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ErrorCount = 0

    if ($VirtualHost.Index -eq -1) {
        $DirectiveName = "ServerName"
    }
    else {
        $DirectiveName = "<\s*VirtualHost"
    }

    $ExpectedValue = "Website utilizes IANA well-known ports for HTTP and HTTPS"
    $Patterns = ('\b80\b', '\b443\b', ':80\b', ':443\b')
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    if ($VirtualHost.Index -ne -1) {
        foreach ($foundDirective in $FoundValues) {
            $foundDirective.Name = "VirtualHost"
        }
    }

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($website in $FoundValues) {
        if ($website.Status -eq "Not Found") {
            continue
        }

        $Pattern = ".*:[0-9]{1,5}"
        if ($null -eq ($website | Select-String -Pattern $Pattern | Select-String -Pattern $Patterns)) {
            $ErrorCount++
            break
        }
    }

    if ($ErrorCount -eq 0) {
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDBsdlv8c/XNLZF
# sPxtC8ccLoGHBEAHm5mc6DQeiX8y76CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCkLxxmdtOUVucPrk/6+Tbn9ezPlGGS
# iRj7yvsu76zPezANBgkqhkiG9w0BAQEFAASCAQCDZmBc4nNMZ2U5nQCE4R4nGfiu
# 4d43SNtMQIHYikdz+PcrCPq1FBpuE4Nn84L/J9gDY3qK+HSdyIjna7WeX1q4SmqA
# B9TXzO1wIOILDSK2kutjUsfQHIyarRQLqLt8qbAlmqOIo1CRgsouVUcPFsbxOoE9
# ZOeuIMub5yrxjErENjM6DLowdUuasXixjgGRktCm62Lf9a+xbbapwSm3sw+wKbo3
# yS960sak4W+oq75TolEofzOHb8V+xvEcuex+BiRBUEZum/b9Qx0nJyo9QqRYE9QF
# tOTMjGxuNC1SCOguMn1Qpi2x//CfYpYin5MFJg6GyxmCGsZaxwIRRdSQaipY
# SIG # End signature block
