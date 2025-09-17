##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Oracle Java Runtime Environment (JRE) Version 8 for Windows
# Version:  V2R1
# Class:    UNCLASSIFIED
# Updated:  4/25/2023
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Format-JavaPath {
    # https://en.wikipedia.org/wiki/File_URI_scheme
    # https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("deployment.properties", "exception.sites")]
        [String]$JavaFile
    )

    $Result = New-Object System.Collections.Generic.List[System.Object]
    $Pass = $true

    $WorkingPath = $Path -replace "\\{5,}", "///" -replace "\\{4}", "//" -replace "\\{3}", "/" -replace "\\{2}", "/" -replace "\\{1}", ""

    Switch ($JavaFile) {
        "deployment.properties" {
            # Java variables don't appear to work for deployment.properties path
            If ($WorkingPath -like '*$SYSTEM_HOME*' -or $WorkingPath -like '*$USER_HOME*' -or $WorkingPath -like '*$JAVA_HOME*') {
                $Pass = $false
                $Formatted = "Path to deployment.properites cannot include a variable.`r`nRefer to https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html"
            }
            ElseIf ($WorkingPath -notlike 'file:*') {
                $Pass = $false
                $Formatted = "Path to deployment.properites must start with proper 'file:' format.`r`nRefer to https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html"
            }
            Else {
                Switch -Regex ($WorkingPath) {
                    # Local path patterns
                    "^file:[A-Za-z]:{1}" {
                        # 'file:C:'
                        $Formatted = $WorkingPath -replace "file:", ""
                    }
                    "^file:/{1}[A-Za-z]:{1}" {
                        # 'file:/C:'
                        $Formatted = $WorkingPath -replace "file:/{1}", ""
                    }
                    "^file:/{3}[A-Za-z]:{1}" {
                        # 'file:///C:'
                        $Formatted = $WorkingPath -replace "file:/{3}", ""
                    }
                    # UNC path pattern
                    "^file:/{2}[A-Za-z0-9]" {
                        # 'file://<server>'
                        $Formatted = $WorkingPath -replace "file:", ""
                        If ($Formatted -match ":") {
                            $Pass = $false
                        }
                    }
                    # Dynamic pattern
                    "^file:/{4,}[A-Za-z0-9]" {
                        # 'file:////<server or drive letter>' (4 or more slashes)
                        If ($WorkingPath -match "file:/{4,}[A-Za-z]:") {
                            # Drive letter detected
                            $Formatted = $WorkingPath -replace "file:/{4,}", ""
                        }
                        Else {
                            # No drive letter detected so UNC
                            $Formatted = $WorkingPath -replace "file:/{4,}", "//"
                        }
                    }
                    Default {
                        $Pass = $false
                        $Formatted = "Path to deployment.properites is invalid format.`r`nRefer to https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html"
                    }
                }
            }
        }
        "exception.sites" {
            If ($WorkingPath -like '*$SYSTEM_HOME*') {
                $WorkingPath = $WorkingPath.Replace('$SYSTEM_HOME', $("$($env:SystemRoot.Replace("\","/"))/Sun/Java/Deployment"))
            }
            Switch -Regex ($WorkingPath) {
                # Local path patterns
                "^[A-Za-z]:{1}" {
                    # 'C:'
                    $Formatted = $WorkingPath
                }
                "^/{1}[A-Za-z]:{1}" {
                    # '/C:'
                    $Formatted = $WorkingPath -replace "/{1}", ""
                }
                # Dynamic pattern
                "^/{2,}[A-Za-z0-9]" {
                    # '//<server or drive letter>' (2 or more slashes)
                    If ($WorkingPath -match "/{2,}[A-Za-z]:") {
                        # Drive letter detected
                        $Formatted = $WorkingPath -replace "/{2,}", ""
                    }
                    Else {
                        # No drive letter detected so UNC
                        $Formatted = $WorkingPath -replace "/{2,}", "//"
                    }
                }
                Default {
                    $Pass = $false
                    $Formatted = "Path to exception.sites is an invalid format."
                }
            }
        }
    }

    $NewObj = [PSCustomObject]@{
        Pass       = $Pass
        Configured = $Path
        Working    = $WorkingPath
        Formatted  = $Formatted
    }
    $Result.Add($NewObj)

    Return $Result
}

Function Get-JreInstallPath {
    $JrePath = @()
    If (Test-Path 'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment\1.8') {
        $JrePath += Get-ChildItem HKLM:\SOFTWARE\JavaSoft -Recurse | Where-Object { ($_.Name -match "1.8") -and ($_.Property -match "INSTALLDIR") } | ForEach-Object { Get-ItemPropertyValue -Path $_.PsPath -Name "INSTALLDIR" }
    }
    If (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment\1.8') {
        $JrePath += Get-ChildItem HKLM:\SOFTWARE\WOW6432Node\JavaSoft -Recurse | Where-Object { ($_.Name -match "1.8") -and ($_.Property -match "INSTALLDIR") } | ForEach-Object { Get-ItemPropertyValue -Path $_.PsPath -Name "INSTALLDIR" }
    }

    Return $JrePath
}

Function Get-V234683 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234683
        STIG ID    : JRE8-WN-000010
        Rule ID    : SV-234683r617446_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must have a deployment.config file present.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PathsToEval = @("$env:windir\Sun\Java\Deployment")
    $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
    $ConfigFiles = @()
    ForEach ($Path in $PathsToEval) {
        If (Test-Path $Path) {
            $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
        }
    }

    $Compliant = $true
    If ($ConfigFiles.Count -eq 0) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "The following config files were found:" | Out-String
        $FindingDetails += "" | Out-String
        $i = 0
        ForEach ($File in $ConfigFiles) {
            If (($ConfigFiles | Measure-Object).Count -gt 1) {
                If ($i -eq 0) {
                    $FindingDetails += "$($File.Fullname) (Will be used for further checks)" | Out-String
                }
                Else {
                    $FindingDetails += $File.Fullname | Out-String
                }
                $i++
            }
            Else {
                $FindingDetails += $File.Fullname | Out-String
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

Function Get-V234684 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234684
        STIG ID    : JRE8-WN-000020
        Rule ID    : SV-234684r617446_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 deployment.config file must contain proper keys and values.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PathsToEval = @("$env:windir\Sun\Java\Deployment")
    $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
    $ConfigFiles = @()
    ForEach ($Path in $PathsToEval) {
        If (Test-Path $Path) {
            $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
        }
    }

    $KeysToEval = "deployment.system.config=", `
        "deployment.system.config.mandatory=true"

    $Compliant = $true

    If (-Not($ConfigFiles)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $Option1Set = $false
        $Option2Set = $false
        $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
        $FindingDetails += "" | Out-String
        $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
        If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
            $Compliant = $false
            $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
        }
        Else {
            $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "$($KeysToEval[0])*") {
                    $Option1Set = $true
                    If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                    }
                    If ($PropsPath) {
                        $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                        If ($PropsFile.Pass -ne $true) {
                            $Compliant = $false
                            $FindingDetails += "$Line" | Out-String
                            $FindingDetails += "" | Out-String
                            $FindingDetails += $PropsFile.Configured | Out-String
                        }
                        ElseIf ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "$Line" | Out-String
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                        }
                        Else {
                            $FindingDetails += "$Line is present" | Out-String
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                }
                ElseIf (($Line -Replace "\s", "") -eq $KeysToEval[1]) {
                    $Option2Set = $true
                    $FindingDetails += "$Line is present" | Out-String
                }
            }

            If ($Option1Set -eq $false) {
                $Compliant = $false
                $FindingDetails += "Path to 'deployment.properties' is NOT present" | Out-String
            }
            ElseIf ($Option2Set -eq $false) {
                $Compliant = $false
                $FindingDetails += "deployment.system.config.mandatory=true is NOT present" | Out-String
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

Function Get-V234685 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234685
        STIG ID    : JRE8-WN-000030
        Rule ID    : SV-234685r617446_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must have a deployment.properties file present.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $PathsToEval = @("$env:windir\Sun\Java\Deployment")
    $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
    $ConfigFiles = @()
    ForEach ($Path in $PathsToEval) {
        If (Test-Path $Path) {
            $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
        }
    }

    $Compliant = $true
    If ($ConfigFiles.Count -eq 0) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
        $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
        If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
        }
        Else {
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Configured | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $FindingDetails += "Properties file exists in the path defined." | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V234686 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234686
        STIG ID    : JRE8-WN-000060
        Rule ID    : SV-234686r617446_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must default to the most secure built-in setting.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $KeysToEval = "deployment.security.level=VERY_HIGH", `
        "deployment.security.level.locked"

    $PathsToEval = @("$env:windir\Sun\Java\Deployment")
    $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
    $ConfigFiles = @()
    ForEach ($Path in $PathsToEval) {
        If (Test-Path $Path) {
            $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
        }
    }

    $Compliant = $true
    If ($ConfigFiles.Count -eq 0) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
        $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
        If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
        }
        Else {
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                            If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                $Compliant = $false
                                $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                            }
                            Else {
                                $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                ForEach ($Key in $KeysToEval) {
                                    If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$",".locked")) {
                                        $FindingDetails += "$Key is present" | Out-String
                                    }
                                    Else {
                                        $Compliant = $false
                                        $FindingDetails += "$Key is NOT present" | Out-String
                                    }
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V234687 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234687
        STIG ID    : JRE8-WN-000070
        Rule ID    : SV-234687r617446_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must be set to allow Java Web Start (JWS) applications.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $KeysToEval = "deployment.webjava.enabled=true", `
        "deployment.webjava.enabled.locked"

    $PathsToEval = @("$env:windir\Sun\Java\Deployment")
    $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
    $ConfigFiles = @()
    ForEach ($Path in $PathsToEval) {
        If (Test-Path $Path) {
            $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
        }
    }

    $Compliant = $true
    If ($ConfigFiles.Count -eq 0) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
        $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
        If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
        }
        Else {
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                            If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                $Compliant = $false
                                $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                            }
                            Else {
                                $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                ForEach ($Key in $KeysToEval) {
                                    If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$",".locked")) {
                                        $FindingDetails += "$Key is present" | Out-String
                                    }
                                    Else {
                                        $Compliant = $false
                                        $FindingDetails += "$Key is NOT present" | Out-String
                                    }
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V234688 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234688
        STIG ID    : JRE8-WN-000080
        Rule ID    : SV-234688r617446_rule
        CCI ID     : CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Oracle JRE 8 must disable the dialog enabling users to grant permissions to execute signed content from an untrusted authority.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
        $KeysToEval = "deployment.security.askgrantdialog.notinca=false", `
            "deployment.security.askgrantdialog.notinca.locked"

        $PathsToEval = @("$env:windir\Sun\Java\Deployment")
        $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
        $ConfigFiles = @()
        ForEach ($Path in $PathsToEval) {
            If (Test-Path $Path) {
                $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
            }
        }

        $Compliant = $true
        If ($ConfigFiles.Count -eq 0) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
            If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            Else {
                # Get path to deployment.properties from .config file
                $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
                ForEach ($Line in $ConfigFileContent) {
                    If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                        Break
                    }
                }
                If ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    If ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += $PropsFile.Formatted | Out-String
                    }
                    Else {
                        $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                        $FindingDetails += "" | Out-String
                        If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                        }
                        Else {
                            If (Test-Path $PropsFile.Formatted) {
                                $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                }
                                Else {
                                    $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                    ForEach ($Key in $KeysToEval) {
                                        If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$",".locked")) {
                                            $FindingDetails += "$Key is present" | Out-String
                                        }
                                        Else {
                                            $Compliant = $false
                                            $FindingDetails += "$Key is NOT present" | Out-String
                                        }
                                    }
                                }
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "Properties file not found in the path defined." | Out-String
                            }
                        }
                    }
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V234689 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234689
        STIG ID    : JRE8-WN-000090
        Rule ID    : SV-234689r617446_rule
        CCI ID     : CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Oracle JRE 8 must lock the dialog enabling users to grant permissions to execute signed content from an untrusted authority.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
        $KeysToEval = "deployment.security.askgrantdialog.show=false", `
            "deployment.security.askgrantdialog.show.locked"

        $PathsToEval = @("$env:windir\Sun\Java\Deployment")
        $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
        $ConfigFiles = @()
        ForEach ($Path in $PathsToEval) {
            If (Test-Path $Path) {
                $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
            }
        }

        $Compliant = $true
        If ($ConfigFiles.Count -eq 0) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
            If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            Else {
                # Get path to deployment.properties from .config file
                $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
                ForEach ($Line in $ConfigFileContent) {
                    If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                        Break
                    }
                }
                If ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    If ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += $PropsFile.Formatted | Out-String
                    }
                    Else {
                        $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                        $FindingDetails += "" | Out-String
                        If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                        }
                        Else {
                            If (Test-Path $PropsFile.Formatted) {
                                $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                }
                                Else {
                                    $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                    ForEach ($Key in $KeysToEval) {
                                        If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$",".locked")) {
                                            $FindingDetails += "$Key is present" | Out-String
                                        }
                                        Else {
                                            $Compliant = $false
                                            $FindingDetails += "$Key is NOT present" | Out-String
                                        }
                                    }
                                }
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "Properties file not found in the path defined." | Out-String
                            }
                        }
                    }
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V234690 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234690
        STIG ID    : JRE8-WN-000100
        Rule ID    : SV-234690r617446_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : Oracle JRE 8 must set the option to enable online certificate validation.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
        $KeysToEval = "deployment.security.validation.ocsp=true", `
            "deployment.security.validation.ocsp.locked"

        $PathsToEval = @("$env:windir\Sun\Java\Deployment")
        $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
        $ConfigFiles = @()
        ForEach ($Path in $PathsToEval) {
            If (Test-Path $Path) {
                $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
            }
        }

        $Compliant = $true
        If ($ConfigFiles.Count -eq 0) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
            If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            Else {
                # Get path to deployment.properties from .config file
                $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
                ForEach ($Line in $ConfigFileContent) {
                    If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                        Break
                    }
                }
                If ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    If ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += $PropsFile.Formatted | Out-String
                    }
                    Else {
                        $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                        $FindingDetails += "" | Out-String
                        If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                        }
                        Else {
                            If (Test-Path $PropsFile.Formatted) {
                                $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                }
                                Else {
                                    $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                    ForEach ($Key in $KeysToEval) {
                                        If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$",".locked")) {
                                            $FindingDetails += "$Key is present" | Out-String
                                        }
                                        Else {
                                            $Compliant = $false
                                            $FindingDetails += "$Key is NOT present" | Out-String
                                        }
                                    }
                                }
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "Properties file not found in the path defined." | Out-String
                            }
                        }
                    }
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V234691 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234691
        STIG ID    : JRE8-WN-000110
        Rule ID    : SV-234691r617446_rule
        CCI ID     : CCI-001169
        Rule Name  : SRG-APP-000209
        Rule Title : Oracle JRE 8 must prevent the download of prohibited mobile code.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $KeysToEval = "deployment.security.blacklist.check=true", `
        "deployment.security.blacklist.check.locked"

    $PathsToEval = @("$env:windir\Sun\Java\Deployment")
    $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
    $ConfigFiles = @()
    ForEach ($Path in $PathsToEval) {
        If (Test-Path $Path) {
            $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
        }
    }

    $Compliant = $true
    If ($ConfigFiles.Count -eq 0) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
        $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
        If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
        }
        Else {
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                            If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                $Compliant = $false
                                $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                            }
                            Else {
                                $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                ForEach ($Key in $KeysToEval) {
                                    If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$",".locked")) {
                                        $FindingDetails += "$Key is present" | Out-String
                                    }
                                    Else {
                                        $Compliant = $false
                                        $FindingDetails += "$Key is NOT present" | Out-String
                                    }
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V234692 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234692
        STIG ID    : JRE8-WN-000120
        Rule ID    : SV-234692r617446_rule
        CCI ID     : CCI-001774
        Rule Name  : SRG-APP-000386
        Rule Title : Oracle JRE 8 must enable the option to use an accepted sites list.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $KeysToEval = "deployment.user.security.exception.sites"

    $PathsToEval = @("$env:windir\Sun\Java\Deployment")
    $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
    $ConfigFiles = @()
    ForEach ($Path in $PathsToEval) {
        If (Test-Path $Path) {
            $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
        }
    }

    $Compliant = $true
    If ($ConfigFiles.Count -eq 0) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
        $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
        If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
        }
        Else {
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                            If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                $Compliant = $false
                                $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                            }
                            Else {
                                $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                ForEach ($Key in $KeysToEval) {
                                    If ($DeployFileContent -match $Key) {
                                        ForEach ($Line in $DeployFileContent) {
                                            If ($Line -like "$($KeysToEval)*") {
                                                $ExceptionPath = ($Line.Split("=")[1]).Trim()
                                                Break
                                            }
                                        }
                                        If ($ExceptionPath) {
                                            $ExceptionFile = Format-JavaPath -Path $ExceptionPath -JavaFile exception.sites
                                            If ($ExceptionFile.Pass -ne $true) {
                                                $Compliant = $false
                                                $FindingDetails += "$Line" | Out-String
                                                $FindingDetails += "" | Out-String
                                                $FindingDetails += $ExceptionFile.Formatted | Out-String
                                            }
                                            ElseIf ($ExceptionFile.Formatted.Split("/")[0, -1][1] -ne "exception.sites") {
                                                $Compliant = $false
                                                $FindingDetails += "$Line" | Out-String
                                                $FindingDetails += "" | Out-String
                                                $FindingDetails += "$Key does not point to an 'exception.sites' file." | Out-String
                                            }
                                            Else {
                                                $FindingDetails += "$Line is present" | Out-String
                                            }
                                        }
                                        Else {
                                            $Compliant = $false
                                            $FindingDetails += "$Line" | Out-String
                                            $FindingDetails += "" | Out-String
                                            $FindingDetails += "Path to 'exception.sites' file is not defined in properties file." | Out-String
                                        }
                                    }
                                    Else {
                                        $Compliant = $false
                                        $FindingDetails += "$Key is NOT present" | Out-String
                                    }
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V234693 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234693
        STIG ID    : JRE8-WN-000130
        Rule ID    : SV-234693r617446_rule
        CCI ID     : CCI-001774
        Rule Name  : SRG-APP-000386
        Rule Title : Oracle JRE 8 must have an exception.sites file present.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
        $KeysToEval = "deployment.user.security.exception.sites"

        $PathsToEval = @("$env:windir\Sun\Java\Deployment")
        $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
        $ConfigFiles = @()
        ForEach ($Path in $PathsToEval) {
            If (Test-Path $Path) {
                $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
            }
        }

        $Compliant = $true
        If ($ConfigFiles.Count -eq 0) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
            If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            Else {
                # Get path to deployment.properties from .config file
                $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
                ForEach ($Line in $ConfigFileContent) {
                    If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                        Break
                    }
                }
                If ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    If ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += $PropsFile.Formatted | Out-String
                    }
                    Else {
                        $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                        If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                        }
                        Else {
                            If (Test-Path $PropsFile.Formatted) {
                                $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                    $Compliant = $false
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                }
                                Else {
                                    $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                    ForEach ($Key in $KeysToEval) {
                                        If ($DeployFileContent -match $Key) {
                                            ForEach ($Line in $DeployFileContent) {
                                                If ($Line -like "$($KeysToEval)*") {
                                                    $ExceptionPath = ($Line.Split("=")[1]).Trim()
                                                    Break
                                                }
                                            }
                                            If ($ExceptionPath) {
                                                $ExceptionFile = Format-JavaPath -Path $ExceptionPath -JavaFile exception.sites
                                                If ($ExceptionFile.Pass -ne $true) {
                                                    $Compliant = $false
                                                    $FindingDetails += "" | Out-String
                                                    $FindingDetails += "$Line" | Out-String
                                                    $FindingDetails += "" | Out-String
                                                    $FindingDetails += $ExceptionFile.Formatted | Out-String
                                                }
                                                Else {
                                                    $FindingDetails += "Exception File:`t`t$($ExceptionFile.Configured)" | Out-String
                                                    $FindingDetails += "" | Out-String
                                                    If ($ExceptionFile.Formatted.Split("/")[0, -1][1] -ne "exception.sites") {
                                                        $Compliant = $false
                                                        $FindingDetails += "$Key does not point to an 'exception.sites' file." | Out-String
                                                    }
                                                    Else {
                                                        If (Test-Path $ExceptionFile.Formatted) {
                                                            $FindingDetails += "Exception file exists in the path defined." | Out-String
                                                        }
                                                        Else {
                                                            $Compliant = $false
                                                            $FindingDetails += "Exception file not found in the path defined." | Out-String
                                                        }
                                                    }
                                                }
                                            }
                                            Else {
                                                $Compliant = $false
                                                $FindingDetails += "" | Out-String
                                                $FindingDetails += "Path to 'exception.sites' file is not defined in properties file." | Out-String
                                            }
                                        }
                                        Else {
                                            $Compliant = $false
                                            $FindingDetails += "" | Out-String
                                            $FindingDetails += "$Key is NOT present" | Out-String
                                        }
                                    }
                                }
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "Properties file not found in the path defined." | Out-String
                            }
                        }
                    }
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V234694 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234694
        STIG ID    : JRE8-WN-000150
        Rule ID    : SV-234694r617446_rule
        CCI ID     : CCI-001991
        Rule Name  : SRG-APP-000401
        Rule Title : Oracle JRE 8 must enable the dialog to enable users to check publisher certificates for revocation.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
        $KeysToEval = "deployment.security.validation.crl=true", `
            "deployment.security.validation.crl.locked"

        $PathsToEval = @("$env:windir\Sun\Java\Deployment")
        $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
        $ConfigFiles = @()
        ForEach ($Path in $PathsToEval) {
            If (Test-Path $Path) {
                $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
            }
        }

        $Compliant = $true
        If ($ConfigFiles.Count -eq 0) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
            If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            Else {
                # Get path to deployment.properties from .config file
                $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
                ForEach ($Line in $ConfigFileContent) {
                    If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                        Break
                    }
                }
                If ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    If ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += $PropsFile.Formatted | Out-String
                    }
                    Else {
                        $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                        $FindingDetails += "" | Out-String
                        If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                        }
                        Else {
                            If (Test-Path $PropsFile.Formatted) {
                                $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                }
                                Else {
                                    $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                    ForEach ($Key in $KeysToEval) {
                                        If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$",".locked")) {
                                            $FindingDetails += "$Key is present" | Out-String
                                        }
                                        Else {
                                            $Compliant = $false
                                            $FindingDetails += "$Key is NOT present" | Out-String
                                        }
                                    }
                                }
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "Properties file not found in the path defined." | Out-String
                            }
                        }
                    }
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V234695 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234695
        STIG ID    : JRE8-WN-000160
        Rule ID    : SV-234695r617446_rule
        CCI ID     : CCI-001991
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must lock the option to enable users to check publisher certificates for revocation.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
        $KeysToEval = "deployment.security.revocation.check=ALL_CERTIFICATES", `
            "deployment.security.revocation.check.locked"

        $PathsToEval = @("$env:windir\Sun\Java\Deployment")
        $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
        $ConfigFiles = @()
        ForEach ($Path in $PathsToEval) {
            If (Test-Path $Path) {
                $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
            }
        }

        $Compliant = $true
        If ($ConfigFiles.Count -eq 0) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
            $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
            If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
            }
            Else {
                # Get path to deployment.properties from .config file
                $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
                ForEach ($Line in $ConfigFileContent) {
                    If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                        $PropsPath = ($Line.Split("=")[1]).Trim()
                        Break
                    }
                }
                If ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    If ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += $PropsFile.Formatted | Out-String
                    }
                    Else {
                        $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                        $FindingDetails += "" | Out-String
                        If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                            $Compliant = $false
                            $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                        }
                        Else {
                            If (Test-Path $PropsFile.Formatted) {
                                $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                                If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                    $Compliant = $false
                                    $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                                }
                                Else {
                                    $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                    ForEach ($Key in $KeysToEval) {
                                        If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$",".locked")) {
                                            $FindingDetails += "$Key is present" | Out-String
                                        }
                                        Else {
                                            $Compliant = $false
                                            $FindingDetails += "$Key is NOT present" | Out-String
                                        }
                                    }
                                }
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "Properties file not found in the path defined." | Out-String
                            }
                        }
                    }
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V234696 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234696
        STIG ID    : JRE8-WN-000170
        Rule ID    : SV-234696r617446_rule
        CCI ID     : CCI-002460
        Rule Name  : SRG-APP-000488
        Rule Title : Oracle JRE 8 must prompt the user for action prior to executing mobile code.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $KeysToEval = "deployment.insecure.jres=PROMPT", `
        "deployment.insecure.jres.locked"

    $PathsToEval = @("$env:windir\Sun\Java\Deployment")
    $PathsToEval += Get-JreInstallPath | Select-Object -Unique | ForEach-Object {Return $_ + "Lib\"}
    $ConfigFiles = @()
    ForEach ($Path in $PathsToEval) {
        If (Test-Path $Path) {
            $ConfigFiles += Get-ChildItem -Path $Path | Where-Object Name -EQ "deployment.config"
        }
    }

    $Compliant = $true
    If ($ConfigFiles.Count -eq 0) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFiles[0].FullName)" | Out-String
        $Encoding = Get-FileEncoding -Path $ConfigFiles[0].FullName
        If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Config file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
        }
        Else {
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFiles[0].FullName
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $Encoding = Get-FileEncoding -Path $PropsFile.Formatted
                            If ($Encoding -notin @("ASCII (no BOM)", "UTF-8 with BOM")) {
                                $Compliant = $false
                                $FindingDetails += "Properties file is encoded as '$Encoding' which is not supported by Java JRE8 for Windows.  Please resave as 'ANSI', 'UTF-8', or 'UTF-8 with BOM' encoding." | Out-String
                            }
                            Else {
                                $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                                ForEach ($Key in $KeysToEval) {
                                    If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$",".locked")) {
                                        $FindingDetails += "$Key is present" | Out-String
                                    }
                                    Else {
                                        $Compliant = $false
                                        $FindingDetails += "$Key is NOT present" | Out-String
                                    }
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V234697 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234697
        STIG ID    : JRE8-WN-000180
        Rule ID    : SV-234697r617446_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : The version of Oracle JRE 8 running on the system must be the most current available.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails += "Java version information:`r`n" | Out-String
    $JrePaths = Get-JreInstallPath
    ForEach ($Path in $JrePaths) {
        If (Test-Path $(Join-Path $Path -ChildPath bin | Join-Path -ChildPath java.exe)) {
            $File = Get-ChildItem $(Join-Path $Path -ChildPath bin | Join-Path -ChildPath java.exe)
            $FindingDetails += "Path:`t`t$($File.FullName)" | Out-String
            $FindingDetails += "Version:`t$($File.VersionInfo.ProductVersion)" | Out-String
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

Function Get-V234698 {
    <#
    .DESCRIPTION
        Vuln ID    : V-234698
        STIG ID    : JRE8-WN-000190
        Rule ID    : SV-234698r617446_rule
        CCI ID     : CCI-002617
        Rule Name  : SRG-APP-000454
        Rule Title : Oracle JRE 8 must remove previous versions when the latest version is installed.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $InstalledSoftwareVersions = Get-InstalledSoftware | Where-Object DisplayName -Match "Java 8" | Select-Object DisplayName, DisplayVersion

    If (($InstalledSoftwareVersions.DisplayVersion | Select-Object -Unique).Count -gt 1) {
        $Status = "Open"
        $FindingDetails += "Multiple versions of Java JRE are installed:" | Out-String
        ForEach ($Version in $InstalledSoftwareVersions) {
            $FindingDetails += $Version.Displayname + " ($($Version.DisplayVersion))" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Java JRE version information:`r`n" | Out-String
        ForEach ($Version in $InstalledSoftwareVersions) {
            $FindingDetails += $Version.Displayname + " ($($Version.DisplayVersion))" | Out-String
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCH0R3txVu6vakf
# f6lGNlK3znyXiIRFDW589yqea2qeMqCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBiRcJG4LEwcAJqoc/eoVpecQXrlH+R
# 4bs2ryO5q54tRjANBgkqhkiG9w0BAQEFAASCAQAisyLZSIxTFN0IkfgLO7gqH4DZ
# F1KXbGitzG/eVvKDOUcpWIolwCu6jW+e0vpD0tT8mcKdmLrjPm2Xp3rjrZ76DRsn
# 19GtZuOWxUJPjvCJ0Ls0/WPr/YhmBpE8aBKbeGUoVqhjyisqVs0Cu9MfoImVJfYZ
# XvFM6biFzabx4cqx8Dh7bgscFI15yDbhfsXu/lnONfxcN9xaSLTIxjmsTFHxwGkz
# NEolGH2ILMXcg6NLxJLWP3L6ZEvWq48BcPYDchSqL9gMl3pXHRbS3KeDkSe5DoYr
# 6F4inXH6i0TA6LdBapshuAlOgWyJyTMINwNl22MSOo4MO6caqfK6wa0xFUU9
# SIG # End signature block
