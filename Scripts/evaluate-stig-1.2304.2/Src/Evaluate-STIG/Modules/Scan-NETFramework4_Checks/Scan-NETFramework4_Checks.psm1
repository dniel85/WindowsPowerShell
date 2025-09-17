##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft DotNet Framework 4.0
# Version:  V2R2
# Class:    UNCLASSIFIED
# Updated:  4/25/2023
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V225223 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225223
        STIG ID    : APPNET0031
        Rule ID    : SV-225223r615940_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : Digital signatures assigned to strongly named assemblies must be verified.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Values = ""
    $Path = "HKLM:\SOFTWARE\Microsoft\StrongName\Verification"
    If (Test-Path $Path) {
        ForEach ($Item in (Get-Item $Path)) {
            If ($Item.Property) {
                $Values += "Path:`t`t`t$($Item.Name)" | Out-String
                $Values += "ValueName:`t$($Item.Property)" | Out-String
                $Values += "" | Out-String
            }
        }
        ForEach ($ChildItem in (Get-ChildItem $Path -Recurse)) {
            If ($ChildItem.Property) {
                $Values += "Path:`t`t`t$($ChildItem.Name)" | Out-String
                $Values += "ValueName:`t$($ChildItem.Property)" | Out-String
                $Values += "" | Out-String
            }
        }

        If (-Not($Values)) {
            $Status = "NotAFinding"
            $FindingDetails += "HKLM:\SOFTWARE\Microsoft\StrongName\Verification exists but no values were found within." | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "HKLM:\SOFTWARE\Microsoft\StrongName\Verification contains the following values:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $Values
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "HKLM:\SOFTWARE\Microsoft\StrongName\Verification does not exist" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V225224 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225224
        STIG ID    : APPNET0046
        Rule ID    : SV-225224r615940_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : The Trust Providers Software Publishing State must be set to 0x23C00.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -in @("Classified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA." | Out-String
    }
    Else {
        $Compliant = $true

        $ProfileList = New-Object System.Collections.Generic.List[System.Object]
        $UserProfiles = Get-CimInstance Win32_UserProfile | Where-Object LocalPath -NotLike "$($env:Windir)*" | Select-Object SID, LocalPath, LastuseTime
        ForEach ($Profile in $UserProfiles) {
            $ErrorActionPreference = "SilentlyContinue"
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($Profile.SID)
            $Username = ""
            Try {
                $Username = ($objSID.Translate([System.Security.Principal.NTAccount])).Value
            }
            Catch {
                { Write-Error } | Out-Null
            }
            $NewObj = [PSCustomObject]@{
                Username  = $Username
                SID       = $objSID.Value
                LocalPath = $Profile.LocalPath
            }
            $ProfileList.Add($NewObj)
            $ErrorActionPreference = "Continue"
        }

        $RegistryValueName = "State"
        ForEach ($User in $ProfileList) {
            $ProcessProfile = $false
            If (Test-Path -Path Registry::HKU\$($User.SID)) {
                $ProcessProfile = $true

                # User is logged in so check registry direcly
                $RegistryPathToCheck = "Registry::HKEY_USERS\$($User.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
                $RegistryResult = Get-RegistryResult -Path $RegistryPathToCheck -ValueName $RegistryValueName
                $RegistryResult.Value = "0x{0:x8}" -f $RegistryResult.Value # Convert to hex and fomat to 0x00000000
            }
            ElseIf (Test-Path -Path "$($User.LocalPath)\NTUSER.DAT") {
                $ES_Hive_Tasks = @("Eval-STIG_LoadHive", "Eval-STIG_UnloadHive") # Potential scheduled tasks for user hive actions
                $ProcessProfile = $true

                # Load NTUSER.DAT to HKU:\ES_TEMP_(SID)
                $NTUSER_DAT = [Char]34 + "$($User.LocalPath)\NTUSER.DAT" + [Char]34
                Try {
                    $Result = Start-Process -FilePath REG -ArgumentList "LOAD HKU\ES_TEMP_$($User.SID) $($NTUSER_DAT)" -Wait -PassThru -WindowStyle Hidden
                    If ($Result.ExitCode -ne 0) {
                        Throw
                    }
                }
                Catch {
                    # REG command failed so attempt to do as SYSTEM
                    Try {
                        $Result = Invoke-TaskAsSYSTEM -TaskName $ES_Hive_Tasks[0] -FilePath REG -ArgumentList "LOAD HKU\ES_TEMP_$($User.SID) $($NTUSER_DAT)" -MaxRunInMinutes 1
                        If ($Result.LastTaskResult -ne 0) {
                            Throw "Failed to load user hive."
                        }
                    }
                    Catch {
                        Throw $_.Exception.Message
                    }
                }

                $RegistryPathToCheck = "Registry::HKEY_USERS\ES_TEMP_$($User.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
                $RegistryResult = Get-RegistryResult -Path $RegistryPathToCheck -ValueName $RegistryValueName
                If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
                    $RegistryResult.Value = "0x{0:x8}" -f $RegistryResult.Value # Convert to hex and fomat to 0x00000000
                }

                # Unload HKU:\ES_TEMP_(SID)
                [System.GC]::Collect() # garbage collection to help unload the hive
                Try {
                    $Result = Start-Process -FilePath REG -ArgumentList "UNLOAD HKU\ES_TEMP_$($User.SID)" -Wait -PassThru -WindowStyle Hidden
                    If ($Result.ExitCode -ne 0) {
                        Throw
                    }
                }
                Catch {
                    # REG command failed so attempt to do as SYSTEM
                    Try {
                        $Result = Invoke-TaskAsSYSTEM -TaskName $ES_Hive_Tasks[1] -FilePath REG -ArgumentList "UNLOAD HKU\ES_TEMP_$($User.SID)" -MaxRunInMinutes 1
                        If ($Result.LastTaskResult -ne 0) {
                            Throw "Failed to unload user hive."
                        }
                    }
                    Catch {
                        Throw $_.Exception.Message
                    }
                }
            }

            If ($ProcessProfile -eq $true) {
                If (-Not($RegistryResult.Value -eq "0x00023c00" -and $RegistryResult.Type -eq "REG_DWORD")) {
                    $Compliant = $false
                    $FindingDetails += "Username:`t$($User.Username)" | Out-String
                    $FindingDetails += "User SID:`t`t$($User.SID)" | Out-String
                    $FindingDetails += "Profile Path:`t$($User.LocalPath)" | Out-String
                    $FindingDetails += "Value Name:`t$($RegistryResult.ValueName)" | Out-String
                    $FindingDetails += "Value:`t`t$($RegistryResult.Value)" | Out-String
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
        }

        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails = "All user profiles have State configured to 0x00023c00"
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

Function Get-V225225 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225225
        STIG ID    : APPNET0048
        Rule ID    : SV-225225r615940_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : Developer certificates used with the .NET Publisher Membership Condition must be approved by the IAO.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    Switch ((Get-CimInstance win32_operatingsystem).OSArchitecture) {
        "32-bit" {
            $FrameworkPath = "$Env:SYSTEMROOT\Microsoft.NET\Framework\v4.0.30319"
        }
        "64-bit" {
            $FrameworkPath = "$Env:SYSTEMROOT\Microsoft.NET\Framework64\v4.0.30319"
        }
    }

    # Execute CASPOL command and trim header lines
    $CaspolCommand = "$FrameworkPath\caspol.exe -m -lg"
    [System.Collections.ArrayList]$CaspolOutput = Invoke-Expression -Command $CaspolCommand
    $i = 0
    ForEach ($Line in $CaspolOutput) {
        If ($Line -like "Please see http:*") {
            $CaspolOutput.RemoveRange(0, ($i + 1))
            Break
        }
        $i++
    }
    $CaspolOutput = $CaspolOutput | Where-Object { $_ } # Remove empty lines from array

    $IsMatching = $CaspolOutput | Select-String -Pattern '1.6.' -SimpleMatch
    If ($IsMatching) {
        $Status = 'Not_Reviewed'
        $FindingDetails += "Review the code groups below for FullTrust and publisher keys in section 1.6." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Status = 'NotAFinding'
        $FindingDetails += "Section 1.6 Publisher section does not exist.  No Publisher Membership Conditions are configured." | Out-String
        $FindingDetails += "" | Out-String
    }

    $FindingDetails += "Executed: $CaspolCommand" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += $CaspolOutput.Trim() | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V225226 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225226
        STIG ID    : APPNET0052
        Rule ID    : SV-225226r615940_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176
        Rule Title : Encryption keys used for the .NET Strong Name Membership Condition must be protected.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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

    Switch ((Get-CimInstance win32_operatingsystem).OSArchitecture) {
        "32-bit" {
            $FrameworkPath = "$Env:SYSTEMROOT\Microsoft.NET\Framework\v4.0.30319"
        }
        "64-bit" {
            $FrameworkPath = "$Env:SYSTEMROOT\Microsoft.NET\Framework64\v4.0.30319"
        }
    }

    # Execute CASPOL command and trim header lines
    $CaspolCommand = "$FrameworkPath\caspol.exe -all -lg"
    [System.Collections.ArrayList]$CaspolOutput = Invoke-Expression -Command $CaspolCommand
    $i = 0
    ForEach ($Line in $CaspolOutput) {
        If ($Line -like "Please see http:*") {
            $CaspolOutput.RemoveRange(0, ($i + 1))
            Break
        }
        $i++
    }
    $CaspolOutput = $CaspolOutput | Where-Object { $_ } # Remove empty lines from array

    $DefaultKeys = @("002400000480000094000000060200000024000052534131000400000100010007D1FA57C4AED9F0A32E84AA0FAEFD0DE9E8FD6AEC8F87FB03766C834C99921EB23BE79AD9D5DCC1DD9AD236132102900B723CF980957FC4E177108FC607774F29E8320E92EA05ECE4E821C0A5EFE8F1645C4C0C93C1AB99285D622CAA652C1DFAD63D745D6F2DE5F17E5EAF0FC4963D261C8A12436518206DC093344D5AD293", "00000000000000000400000000000000")
    $StrongNameValues = $CaspolOutput | Select-String "StrongName"
    $BetweenPattern = "StrongName - (.*?):"
    ForEach ($Line in $StrongNameValues) {
        $Result = [regex]::Match($Line, $BetweenPattern).Groups[1].Value
        If ($Result -notin $DefaultKeys) {
            $Compliant = $false
        }
    }

    If ($Compliant -eq $true) {
        $Status = "Not_Applicable"
        $FindingDetails += "Only operating system (COTS) default code groups have Strong Name Membership Conditions so this requirement is NA." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Status = "Not_Reviewed"
        $FindingDetails += "Strong Name Membership Condition detected for a not-default code group.  If the application(s) is COTS, this finding should be marked as Not Applicable.  Otherwise, ask the Systems Programmer how the private keys are protected."
        $FindingDetails += "" | Out-String
    }

    $FindingDetails += "Executed: $CaspolCommand" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += $caspolOutput.Trim() | Out-String
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V225228 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225228
        STIG ID    : APPNET0060
        Rule ID    : SV-225228r615940_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219
        Rule Title : Remoting Services HTTP channels must utilize authentication and encryption.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $XmlElement = "channel"
    $XmlAttributeName = "ref"
    $XmlAttributeValue = "http server"
    $Compliant = $true # Set initial compliance for this STIG item to true.

    If (Test-Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt) {
        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt
    }
    Else {
        # Get .Net 4 Framework machine.config files
        $frameworkMachineConfig = "$env:SYSTEMROOT\Microsoft.NET\Framework\v4.0.30319\Config\machine.config"
        $framework64MachineConfig = "$env:SYSTEMROOT\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"

        # Get hard disk drive letters
        $driveLetters = (Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -EQ 3)

        # Get configuration files
        $allConfigFiles = @()
        $allConfigFiles += (Get-ChildItem $frameworkMachineConfig).FullName
        $allConfigFiles += (Get-ChildItem $framework64MachineConfig).FullName
        $allConfigFiles += (ForEach-Object -InputObject $driveLetters { (Get-ChildItem ($_.DeviceID + "\") -Recurse -Filter *.exe.config -ErrorAction SilentlyContinue | Where-Object { ($_.FullName -NotLike "*Windows\CSC\*") -and ($_.FullName -NotLike "*Windows\WinSxS\*") }).FullName })
    }

    ForEach ($File in $allConfigFiles) {
        If (Test-Path $File) {
            $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
            If ($XML) {
                $Node = ($XML | Select-Xml -XPath "//$($XmlElement)" | Select-Object -ExpandProperty "Node" | Where-Object $XmlAttributeName -EQ $XmlAttributeValue | Select-Object *)
                If ($Node) {
                    If ($Node.Port -ne "443") {
                        $Compliant = $false # Change compliance for this STIG item to false.
                        $FindingDetails += $File | Out-String
                        $FindingDetails += "Channel:`t$($XmlAttributeValue)" | Out-String
                        $FindingDetails += "Port:`t`t$($Node.Port)" | Out-String
                        $FindingDetails += "Confirm that this port is TLS encrypted."
                        $FindingDetails += "`r`n"
                    }
                }
            }
        }
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "No misconfigured machine.config or *.exe.config files detected."
    }
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V225229 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225229
        STIG ID    : APPNET0061
        Rule ID    : SV-225229r615940_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : .Net Framework versions installed on the system must be supported.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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
    Try {
        $NetFx3 = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop).State -eq "Enabled"
        $NetFx4 = (((Get-WindowsOptionalFeature -Online -FeatureName NetFx4 -ErrorAction Stop).State -eq "Enabled") -or ((Get-WindowsOptionalFeature -Online -FeatureName NetFx4-AdvSrvs -ErrorAction Stop).State -eq "Enabled") -or (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-NetFx4-US-OC-Package -ErrorAction Stop).State -eq "Enabled")
    }
    Catch {
        $NetFx3 = (Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object Name -EQ "NetFx3").InstallState -eq 1
        $NetFx4 = (((Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object Name -EQ "NetFx4").InstallState -eq 1) -or ((Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object Name -EQ "NetFx4-AdvSrvs").InstallState -eq 1) -or (Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object Name -EQ "Microsoft-Windows-NetFx4-US-OC-Package").InstallState -eq 1)
    }

    # Get .Net Frameworks' mscorlib.dll
    $FrameworksPath = "$Env:SYSTEMROOT\Microsoft.NET\Framework*\v*"
    $LibraryFiles = Get-ChildItem -Path $FrameworksPath -Recurse -Include mscorlib.dll

    If ($LibraryFiles) {
        ForEach ($File in $LibraryFiles) {
            $FindingDetails += "File Path:`t`t`t$($File.VersionInfo.Filename)" | Out-String
            $FindingDetails += "Version:`t`t`t$($File.VersionInfo.ProductVersion)" | Out-String
            If ($File.VersionInfo.ProductVersion -like "2.*" -and $NetFx3) {
                $FindingDetails += "OS Component:`t$true`r`n" | Out-String
            }
            ElseIf ($File.VersionInfo.ProductVersion -like "4.*" -and $NetFx4) {
                $FindingDetails += "OS Component:`t$true`r`n" | Out-String
            }
            Else {
                $FindingDetails += "OS Component:`t$false`r`n" | Out-String
                $Compliant = $false
            }
        }

        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "All .NET versions are built-in to the OS and supported." | Out-String
        }
        Else {
            $Status = "Not_Reviewed"
            $FindingDetails += "Verify any .NET versions that are not OS components are supported by the vendor." | Out-String
            $FindingDetails += "Support can be verified at <https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/versions-and-dependencies>." | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails = "A .Net Framework was not found."
    }
    #---=== End Custom Code ===---#

    If ($AnswerFile) {
        $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey -UserSID $UserSID)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -Severity $([String]$Severity)
}

Function Get-V225230 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225230
        STIG ID    : APPNET0062
        Rule ID    : SV-225230r849747_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000635
        Rule Title : The .NET CLR must be configured to use FIPS approved encryption modules.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $XmlElement = "enforceFIPSPolicy"
    $XmlAttributeName = "enabled"
    $XmlAttributeValue = "false" # Non-compliant setting
    $Compliant = $true # Set initial compliance for this STIG item to true.

    If (Test-Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt) {
        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt
    }
    Else {
        # Get .Net 4 Framework machine.config files
        $frameworkMachineConfig = "$env:SYSTEMROOT\Microsoft.NET\Framework\v4.0.30319\Config\machine.config"
        $framework64MachineConfig = "$env:SYSTEMROOT\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"

        # Get hard disk drive letters
        $driveLetters = (Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -EQ 3)

        # Get configuration files
        $allConfigFiles = @()
        $allConfigFiles += (Get-ChildItem $frameworkMachineConfig).FullName
        $allConfigFiles += (Get-ChildItem $framework64MachineConfig).FullName
        $allConfigFiles += (ForEach-Object -InputObject $driveLetters { (Get-ChildItem ($_.DeviceID + "\") -Recurse -Filter *.exe.config -ErrorAction SilentlyContinue | Where-Object { ($_.FullName -NotLike "*Windows\CSC\*") -and ($_.FullName -NotLike "*Windows\WinSxS\*") }).FullName })
    }

    ForEach ($File in $allConfigFiles) {
        If (Test-Path $File) {
            $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
            If ($XML) {
                $Node = ($XML | Select-Xml -XPath "//$($XmlElement)" | Select-Object -ExpandProperty "Node" | Where-Object $XmlAttributeName -EQ $XmlAttributeValue | Select-Object *)
                If ($Node) {
                    $Compliant = $false # Change compliance for this STIG item to false.
                    $FindingDetails += $File | Out-String
                    $FindingDetails += "Name:`t$($XmlElement)" | Out-String
                    $FindingDetails += "Enabled:`t$($Node.Enabled)" | Out-String
                    $FindingDetails += "`r`n"
                }
            }
        }
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "No machine.config or *.exe.config files found with 'enforceFIPSPolicy enabled=false'."
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

Function Get-V225231 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225231
        STIG ID    : APPNET0063
        Rule ID    : SV-225231r615940_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : .NET must be configured to validate strong names on full-trust assemblies.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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

    Switch ((Get-CimInstance win32_operatingsystem).OSArchitecture) {
        "32-bit" {
            $RegistryPaths = @("HKLM:\SOFTWARE\Microsoft\.NETFramework")
            $RegistryValueName = "AllowStrongNameBypass"

            ForEach ($RegistryPath in $RegistryPaths) {
                $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
                $FindingDetails += "Registry Path:`t$($RegistryResult.Key)" | Out-String
                $FindingDetails += "Value Name:`t$($RegistryResult.ValueName)" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResult.Value)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                $FindingDetails += "`r`n"
                If (($RegistryResult.Type -ne "REG_DWORD") -or ($RegistryResult.Value -ne 0)) {
                    $Compliant = $false
                }
            }
        }
        "64-bit" {
            $RegistryPaths = @("HKLM:\SOFTWARE\Microsoft\.NETFramework", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework")
            $RegistryValueName = "AllowStrongNameBypass"

            ForEach ($RegistryPath in $RegistryPaths) {
                $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
                $FindingDetails += "Registry Path:`t$($RegistryPath)" | Out-String
                $FindingDetails += "Value Name:`t$($RegistryValueName)" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResult.Value)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                $FindingDetails += "`r`n"
                If (($RegistryResult.Type -ne "REG_DWORD") -or ($RegistryResult.Value -ne 0)) {
                    $Compliant = $false
                }
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

Function Get-V225232 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225232
        STIG ID    : APPNET0064
        Rule ID    : SV-225232r615940_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : .Net applications that invoke NetFx40_LegacySecurityPolicy must apply previous versions of .NET STIG guidance.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $XmlElement = "NetFx40_LegacySecurityPolicy"
    $XmlAttributeName = "enabled"
    $XmlAttributeValue = "true" # Non-compliant setting
    $Compliant = $true # Set initial compliance for this STIG item to true.

    If (Test-Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt) {
        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt
    }
    Else {
        # Get hard disk drive letters
        $driveLetters = (Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -EQ 3)

        # Get configuration files
        $allConfigFiles = @()
        $allConfigFiles += (ForEach-Object -InputObject $driveLetters { (Get-ChildItem ($_.DeviceID + "\") -Recurse -Filter *.exe.config -ErrorAction SilentlyContinue | Where-Object { ($_.FullName -NotLike "*Windows\CSC\*") -and ($_.FullName -NotLike "*Windows\WinSxS\*") }).FullName })
    }

    ForEach ($File in $allConfigFiles) {
        If ($File -like "*.exe.config" -and $File -notlike "$env:windir*" -and (Test-Path $File)) {
            $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
            If ($XML) {
                $Node = ($XML | Select-Xml -XPath "//$($XmlElement)" | Select-Object -ExpandProperty "Node" | Where-Object $XmlAttributeName -EQ $XmlAttributeValue | Select-Object *)
                If ($Node) {
                    $Compliant = $false # Change compliance for this STIG item to false.
                    $FindingDetails += $File | Out-String
                    $FindingDetails += "Name:`t$($XmlElement)" | Out-String
                    $FindingDetails += "Enabled:`t$($Node.Enabled)" | Out-String
                    $FindingDetails += "`r`n"
                }
            }
        }
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "No *.exe.config files found with 'NetFx40_LegacySecurityPolicy enabled=true'."
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

Function Get-V225233 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225233
        STIG ID    : APPNET0065
        Rule ID    : SV-225233r849748_rule
        CCI ID     : CCI-002530
        Rule Name  : SRG-APP-000431
        Rule Title : Trust must be established prior to enabling the loading of remote code in .Net 4.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $XmlElement = "loadFromRemoteSources"
    $XmlAttributeName = "enabled"
    $XmlAttributeValue = "true" # Non-compliant setting
    $Compliant = $true # Set initial compliance for this STIG item to true.

    If (Test-Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt) {
        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt
    }
    Else {
        # Get hard disk drive letters
        $driveLetters = (Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -EQ 3)

        # Get configuration files
        $allConfigFiles = @()
        $allConfigFiles += (ForEach-Object -InputObject $driveLetters { (Get-ChildItem ($_.DeviceID + "\") -Recurse -Filter *.exe.config -ErrorAction SilentlyContinue | Where-Object { ($_.FullName -NotLike "*Windows\CSC\*") -and ($_.FullName -NotLike "*Windows\WinSxS\*") }).FullName })
    }

    ForEach ($File in $allConfigFiles) {
        If ($File -like "*.exe.config" -and (Test-Path $File)) {
            $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
            If ($XML) {
                $Node = ($XML | Select-Xml -XPath "//$($XmlElement)" | Select-Object -ExpandProperty "Node" | Where-Object $XmlAttributeName -EQ $XmlAttributeValue | Select-Object *)
                If ($Node) {
                    $Compliant = $false # Change compliance for this STIG item to false.
                    $FindingDetails += $File | Out-String
                    $FindingDetails += "Name:`t$($XmlElement)" | Out-String
                    $FindingDetails += "Enabled:`t$($Node.Enabled)" | Out-String
                    $FindingDetails += "`r`n"
                }
            }
        }
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "No *.exe.config files found with 'loadFromRemoteSources enabled=true'."
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

Function Get-V225234 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225234
        STIG ID    : APPNET0066
        Rule ID    : SV-225234r864037_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : .NET default proxy settings must be reviewed and approved.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Compliant = $true # Set initial compliance for this STIG item to true.

    If (Test-Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt) {
        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt
    }
    Else {
        # Get .Net 4 Framework machine.config files
        $frameworkMachineConfig = "$env:SYSTEMROOT\Microsoft.NET\Framework\v4.0.30319\Config\machine.config"
        $framework64MachineConfig = "$env:SYSTEMROOT\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"

        # Get hard disk drive letters
        $driveLetters = (Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -EQ 3)

        # Get configuration files
        $allConfigFiles = @()
        $allConfigFiles += (Get-ChildItem $frameworkMachineConfig).FullName
        $allConfigFiles += (Get-ChildItem $framework64MachineConfig).FullName
        $allConfigFiles += (ForEach-Object -InputObject $driveLetters { (Get-ChildItem ($_.DeviceID + "\") -Recurse -Filter *.exe.config -ErrorAction SilentlyContinue | Where-Object { ($_.FullName -NotLike "*Windows\CSC\*") -and ($_.FullName -NotLike "*Windows\WinSxS\*") }).FullName })
    }

    ForEach ($File in $allConfigFiles) {
        If (Test-Path $File) {
            $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
            If ($XML) {
                $DefaultProxy = ($XML | Select-Xml -XPath "//defaultProxy" | Select-Object -ExpandProperty "Node" | Select-Object *)
                $BypassList = ($XML | Select-Xml -XPath "//defaultProxy/bypasslist" | Select-Object -ExpandProperty "Node" | Select-Object *)
                $Module = ($XML | Select-Xml -XPath "//defaultProxy/module" | Select-Object -ExpandProperty "Node" | Select-Object *)
                $Proxy = ($XML | Select-Xml -XPath "//defaultProxy/proxy" | Select-Object -ExpandProperty "Node" | Select-Object *)
                If (-Not((($DefaultProxy.enabled -eq $true) -or ($DefaultProxy.IsEmpty -eq $true -and $DefaultProxy.HasAttributes -eq $true)) -or ((($DefaultProxy.ChildNodes | Where-Object name -NE "#Whitespace") | Measure-Object).Count -eq 0) -or $Proxy.useSystemDefault -eq $true)) {
                    If ($DefaultProxy.enabled -eq $false -or $BypassList -or $Module -or $Proxy) {
                        $FindingDetails += $File | Out-String
                        If ($DefaultProxy.enabled -eq $false) {
                            $Compliant = $false
                            $FindingDetails += "Enabled:`t`t$($DefaultProxy.enabled)" | Out-String
                        }
                        If ($BypassList) {
                            $Compliant = $false
                            $FindingDetails += "BypassList:`tNOT CLEARED" | Out-String
                        }
                        If ($Module) {
                            $Compliant = $false
                            $FindingDetails += "Module:`t`tNOT CLEARED" | Out-String
                        }
                        If ($Proxy -and $Proxy.useSystemDefault -ne $true) {
                            $Compliant = $false
                            $FindingDetails += "Proxy:`t`tNOT CLEARED and 'useSystemDefault' is NOT True" | Out-String
                        }
                        $FindingDetails += "" | Out-String
                    }
                }
            }
        }
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "No machine.config or *.exe.config files found with 'defaultProxy enabled=false' or with 'bypasslist', 'module', or 'proxy' elements."
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

Function Get-V225235 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225235
        STIG ID    : APPNET0067
        Rule ID    : SV-225235r615940_rule
        CCI ID     : CCI-000130
        Rule Name  : SRG-APP-000095
        Rule Title : Event tracing for Windows (ETW) for Common Language Runtime events must be enabled.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $XmlElement = "etwEnable"
    $XmlAttributeName = "enabled"
    $XmlAttributeValue = "false" # Non-compliant setting
    $Compliant = $true # Set initial compliance for this STIG item to true.

    If (Test-Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt) {
        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt
    }
    Else {
        # Get .Net 4 Framework machine.config files
        $frameworkMachineConfig = "$env:SYSTEMROOT\Microsoft.NET\Framework\v4.0.30319\Config\machine.config"
        $framework64MachineConfig = "$env:SYSTEMROOT\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"

        # Get hard disk drive letters
        $driveLetters = (Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -EQ 3)

        # Get configuration files
        $allConfigFiles = @()
        $allConfigFiles += (Get-ChildItem $frameworkMachineConfig).FullName
        $allConfigFiles += (Get-ChildItem $framework64MachineConfig).FullName
        $allConfigFiles += (ForEach-Object -InputObject $driveLetters { (Get-ChildItem ($_.DeviceID + "\") -Recurse -Filter *.exe.config -ErrorAction SilentlyContinue | Where-Object { ($_.FullName -NotLike "*Windows\CSC\*") -and ($_.FullName -NotLike "*Windows\WinSxS\*") }).FullName })
    }

    ForEach ($File in $allConfigFiles) {
        If (Test-Path $File) {
            $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
            If ($XML) {
                $Node = ($XML | Select-Xml -XPath "//$($XmlElement)" | Select-Object -ExpandProperty "Node" | Where-Object $XmlAttributeName -EQ $XmlAttributeValue | Select-Object *)
                If ($Node) {
                    $Compliant = $false # Change compliance for this STIG item to false.
                    $FindingDetails += $File | Out-String
                    $FindingDetails += "Name:`t$($XmlElement)" | Out-String
                    $FindingDetails += "Enabled:`t$($Node.Enabled)" | Out-String
                    $FindingDetails += "`r`n"
                }
            }
        }
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "No machine.config or *.exe.config files found with 'etwEnable enabled=false'."
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

Function Get-V225237 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225237
        STIG ID    : APPNET0071
        Rule ID    : SV-225237r615940_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219
        Rule Title : Remoting Services TCP channels must utilize authentication and encryption.
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $Severity = "" #acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $XmlElement = "channel"
    $XmlAttributeName = "ref"
    $XmlAttributeValue = "tcp"
    $Compliant = $true # Set initial compliance for this STIG item to true.

    If (Test-Path $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt) {
        $allConfigFiles = Get-Content $env:windir\Temp\Evaluate-STIG\Evaluate-STIG_Net4FileList.txt
    }
    Else {
        # Get .Net 4 Framework machine.config files
        $frameworkMachineConfig = "$env:SYSTEMROOT\Microsoft.NET\Framework\v4.0.30319\Config\machine.config"
        $framework64MachineConfig = "$env:SYSTEMROOT\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"

        # Get hard disk drive letters
        $driveLetters = (Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -EQ 3)

        # Get configuration files
        $allConfigFiles = @()
        $allConfigFiles += (Get-ChildItem $frameworkMachineConfig).FullName
        $allConfigFiles += (Get-ChildItem $framework64MachineConfig).FullName
        $allConfigFiles += (ForEach-Object -InputObject $driveLetters { (Get-ChildItem ($_.DeviceID + "\") -Recurse -Filter *.exe.config -ErrorAction SilentlyContinue | Where-Object { ($_.FullName -NotLike "*Windows\CSC\*") -and ($_.FullName -NotLike "*Windows\WinSxS\*") }).FullName })
    }

    ForEach ($File in $allConfigFiles) {
        If (Test-Path $File) {
            $XML = (Select-Xml -Path $File / -ErrorAction SilentlyContinue).Node
            If ($XML) {
                $Node = ($XML | Select-Xml -XPath "//$($XmlElement)" | Select-Object -ExpandProperty "Node" | Where-Object $XmlAttributeName -EQ $XmlAttributeValue | Select-Object *)
                If ($Node) {
                    If ($Node.Secure -ne $true) {
                        If (-Not($Node.Secure)) {
                            $Secure = "(NOT CONFIGURED)"
                        }
                        Else {
                            $Secure = $Node.Secure
                        }
                        $Compliant = $false # Change compliance for this STIG item to false.
                        $FindingDetails += $File | Out-String
                        $FindingDetails += "Channel:`t$($XmlAttributeValue)" | Out-String
                        $FindingDetails += "Secure:`t$Secure" | Out-String
                        $FindingDetails += "`r`n"
                    }
                }
            }
        }
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "No misconfigured *.exe.config files detected."
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

Function Get-V225238 {
    <#
    .DESCRIPTION
        Vuln ID    : V-225238
        STIG ID    : APPNET0075
        Rule ID    : SV-225238r849750_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383
        Rule Title : Disable TLS RC4 cipher in .Net
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

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

    Switch ((Get-CimInstance win32_operatingsystem).OSArchitecture) {
        "32-bit" {
            $RegistryPaths = @("HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319")
            $RegistryValueName = "SchUseStrongCrypto"

            ForEach ($RegistryPath in $RegistryPaths) {
                $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
                $FindingDetails += "Registry Path:`t$($RegistryResult.Key)" | Out-String
                $FindingDetails += "Value Name:`t$($RegistryResult.ValueName)" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResult.Value)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                $FindingDetails += "`r`n"
                If (($RegistryResult.Type -ne "REG_DWORD") -and ($RegistryResult.Value -ne 1)) {
                    $Compliant = $false
                }
            }
        }
        "64-bit" {
            $RegistryPaths = @("HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319")
            $RegistryValueName = "SchUseStrongCrypto"

            ForEach ($RegistryPath in $RegistryPaths) {
                $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
                $FindingDetails += "Registry Path:`t$($RegistryPath)" | Out-String
                $FindingDetails += "Value Name:`t$($RegistryValueName)" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResult.Value)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                $FindingDetails += "`r`n"
                If (($RegistryResult.Type -ne "REG_DWORD") -and ($RegistryResult.Value -ne 1)) {
                    $Compliant = $false
                }
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDcyEQN6b8JYDrw
# KoERo5veFwxlb70utrSLMEqGg0Vy6aCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCzgM2hTkhC0eLoj6pEGQjZ3+CjT6H6
# rkl/We6jx/SK9TANBgkqhkiG9w0BAQEFAASCAQAt+JN7fgviBFQJqfen/wZ6EQI8
# qUEQIrzSzcuZHTo3JCbRR4z7W4ZmTLcRVs09zrcxR/tqKKDpRLopbJ9tLNC9b4qG
# 9LgsQx5oONvLyhbp1D99GUYrMb9mLEwanijUqjd6BAMKP83UEozxgKpk9Ly1V+rN
# LVra7ChYku8kjCjP4fNb921hrXzc6b9Lit8OmxyzwKk7lz8gC0LiqvdEKMvesSRn
# bH0MF6yTkXwgSogUn439EkViOAYViyoKcbtG+7TNrX3Bhz2JFrkDt2C7on0/4jU6
# JYI7vDlXdW/54wkjwrpimQBhZu2dRoc4cbbdcDzU+UDcwQby54sqKNasWvmh
# SIG # End signature block
