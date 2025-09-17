Function Get-CiscoShowTechData {
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$ShowTech,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Inventory", "RunningConfig", "Version")]
        [String]$DataType
    )

    Try {
        Switch ($DataType) {
            "Inventory" {
                #This pulls show inventory section from show tech config file
                $startSTR = "^-{18} show inventory -{18}"
                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
            "RunningConfig" {
                #This pulls show running-config section from show tech config file
                $startSTR = "^-{18} show running-config -{18}"
                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
            "Version" {
                #This pulls show version section from show tech config file
                Switch -Regex ($ShowTech) {
                    "^-{18} show version -{18}" {
                        $startSTR = "^-{18} show version -{18}"
                    }
                    # Maybe ASA here one day? {}
                }

                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
        }

        Return $Result
    }
    Catch {
        Return "Unable to find 'show version' section"
    }
}

Function Get-CiscoDeviceInfo {
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$ShowTech
    )

    Try {
        $Result = New-Object System.Collections.Generic.List[System.Object]

        # Get software information from Version data
        $ShowVersion = Get-CiscoShowTechData -ShowTech $ShowTech -DataType Version
        If ($ShowVersion) {
            Switch -Regex ($ShowVersion) {
                "^Cisco IOS XE Software," {
                    $StartLine = ($ShowVersion | Select-String "^Cisco IOS XE Software,").LineNumber - 1
                    $DeviceSoftwareInfo = ($ShowVersion[$($StartLine + 1)].Split(",")).Trim()
                    $CiscoOS = ($ShowVersion[$($StartLine)].Split(",")).Trim()[0]
                    $CiscoOSVer = $DeviceSoftwareInfo[2].Replace("Version ", "").Trim()
                    $CiscoSoftware = $DeviceSoftwareInfo[1]
                }
                "^Cisco IOS Software," {
                    $StartLine = ($ShowVersion | Select-String "^Cisco IOS Software,").LineNumber - 1
                    $DeviceSoftwareInfo = ($ShowVersion[$($StartLine)].Split(",")).Trim()
                    $CiscoOS = $DeviceSoftwareInfo[1].Trim()
                    $CiscoOSVer = $DeviceSoftwareInfo[3].Replace("Version ", "").Trim()
                    $CiscoSoftware = $DeviceSoftwareInfo[2].Trim()
                }
            }
            Switch -WildCard ($CiscoSoftware) {
                {($_ -like "*Switch*Software*")} {
                    $DeviceType = "Switch"
                }
                {($_ -like "*ASR*Software*") -or ($_ -like "*CSR*Software*") -or ($_ -like "*ISR*Software*")} {
                    $DeviceType = "Router"
                }
                Default {
                    Throw
                }
            }
        }
        Else {
            Throw
        }

        # Get the serial number from Inventory data
        $Inventory = Get-CiscoShowTechData -ShowTech $ShowTech -DataType Inventory
        If ($Inventory) {
            Switch -Regex ($Inventory) {
                "Name: `"{1}Chassis`"{1}," {
                    $Model = ((($Inventory[($Inventory | Select-String "Name: `"{1}Chassis`"{1},").LineNumber]) -Split "PID:")[1] -split ",")[0].Trim()
                    $SerialNumber = (($Inventory[($Inventory | Select-String "Name: `"{1}Chassis`"{1},").LineNumber]) -Split "SN:")[1].Trim()
                }
                "Name: `"{1}Switch System`"{1}," {
                    $Model = ((($Inventory[($Inventory | Select-String "Name: `"{1}Switch System`"{1},").LineNumber]) -Split "PID:")[1] -split ",")[0].Trim()
                    $SerialNumber = (($Inventory[($Inventory | Select-String "Name: `"{1}Switch System`"{1},").LineNumber]) -Split "SN:")[1].Trim()
                }
                "Name: `"{1}\w{1,} Stack`"{1}" {
                    $Model = ((($Inventory[($Inventory | Select-String "Name: `"{1}\w{1,} Stack`"{1}").LineNumber]) -Split "PID:")[1] -split ",")[0].Trim()
                    $SerialNumber = (($Inventory[($Inventory | Select-String "Name: `"{1}\w{1,} Stack`"{1}").LineNumber]) -Split "SN:")[1].Trim()
                }
            }
        }
        Else {
            Throw
        }

        # Get hostname
        $Hostname = ((Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig | Select-String -Pattern "^hostname" | Out-String).Replace("hostname", "")).Trim()
        If (-Not($Hostname)) {
            # If 'hostname' not found, try Device Name in Show Version
            $Hostname = ((Get-CiscoShowTechData -ShowTech $ShowTech -DataType Version | Select-String -Pattern "^\s*Device name:" | Out-String).Replace("Device name:", "")).Trim()
        }
        If (-Not($Hostname)) {
            # If 'hostname'STILL empty set static
            $Hostname = "NameNotFound"
        }

        # Get domain
        $DomainName = ((Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig | Select-String -Pattern "^ip domain-name" | Out-String).Replace("ip domain-name", "")).Trim()

        # Get MAC (if available)
        $MACAddress = ((Get-CiscoShowTechData -ShowTech $ShowTech -DataType Version | Select-String -Pattern "^Base Ethernet MAC Address\s*:" | Out-String) -Replace "Base Ethernet MAC Address\s*:", "").Trim()

        # Put found data into an object and return it
        $NewObj = [PSCustomObject]@{
            Hostname      = $Hostname
            DomainName    = $DomainName
            MACAddress    = $MACAddress
            DeviceInfo    = $DeviceSoftwareInfo
            CiscoOS       = $CiscoOS
            CiscoOSVer    = $CiscoOSVer
            CiscoSoftware = $CiscoSoftware
            SerialNumber  = $SerialNumber
            Model         = $Model
            DeviceType    = $DeviceType
        }
        $Result.Add($NewObj)

        Return $Result
    }
    Catch {
        Return "Unable to determine device info"
    }
}

Function Get-Section {
    param(
        [String[]] $configData,
        [String] $sectionName
    )

    $pattern = '(?:^(!)\s*$)|(?:^[\s]+(.+)$)'
    $inSection = $false
    ForEach ($line in $configData) {
        # Skip empty lines
        If ($line -match '^\s*$') {
            Continue
        }
        If ($line -eq $sectionName) {
            $inSection = $true
            Continue
        }
        If ($inSection) {
            If ($line -match $pattern) {
                [Regex]::Matches($line, $pattern) | ForEach-Object {
                    If ($_.Groups[1].Success) {
                        $_.Groups[1].Value
                    }
                    Else {
                        $_.Groups[2].Value
                    }
                }
            }
            Else {
                $inSection = $false
            }
            If (-not($inSection)) {
                Break
            }
        }
    }
}

Function Invoke-ConfigFileScan {
    Param (
        # Evaluate-STIG parameters
        [Parameter(Mandatory = $true)]
        [String[]]$CiscoConfig,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Unclassified", "Classified")]
        [String]$ScanType = "Unclassified",

        [Parameter(Mandatory = $false)]
        [String]$Marking,

        [Parameter(Mandatory = $false)]
        [Int]$VulnTimeout = 15,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]$AFPath,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey = "DEFAULT",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]$OutputPath,

        [Parameter(Mandatory = $false)]
        [Switch]$NoPrevious,

        [Parameter(Mandatory = $false)]
        [Array]$SelectSTIG,

        [Parameter(Mandatory = $false)]
        [Array]$SelectVuln,

        [Parameter(Mandatory = $false)]
        [Array]$ExcludeVuln,

        [Parameter(Mandatory = $false)]
        [Array]$ExcludeSTIG,

        [Parameter(Mandatory = $false)]
        [Int]$ThrottleLimit = 10,

        # Config file scan parameters
        [Parameter(Mandatory = $true)]
        [String]$ESVersion,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String] $ES_Path,

        [Parameter(Mandatory = $true)]
        [String] $PowerShellVersion,

        [Parameter(Mandatory = $true)]
        [String] $CiscoScanDir,

        [Parameter(Mandatory = $true)]
        [String] $CiscoWorkingDir
    )

    Try {
        $ConfigEvalStart = Get-Date
        $ProgressId = 1
        $ProgressActivity = "Evaluate-STIG (Version: $ESVersion | Scan Type: $ScanType | Answer Key: $AnswerKey)"

        # Reconstruct command line for logging purposes
        $ParamsNotForLog = @("ESVersion","LogComponent","OSPlatform","ES_Path","PowerShellVersion") # Parameters not be be written to log
        $BoundParams = $PSBoundParameters # Collect called parameters
        ForEach ($Item in $ParamsNotForLog) {
            # Remove parameter from collection so that it will not be logged
            $BoundParams.Remove($Item) | Out-Null
        }
        $CommandLine = "Evaluate-STIG.ps1"
        ForEach ($Item in $BoundParams.Keys) {
            Switch ($BoundParams.$Item.GetType().Name) {
                {($_ -in @("String[]","Object[]"))} {
                    $CommandLine += " -$($Item) $($BoundParams[$Item] -join ',')"
                }
                "SwitchParameter" {
                    $CommandLine += " -$($Item)"
                }
                DEFAULT {
                    $CommandLine += " -$($Item) $($BoundParams[$Item])"
                }
            }
        }

        $STIGLog_Cisco = Join-Path -Path $CiscoScanDir -ChildPath "Evaluate-STIG_Cisco.log"
        If (Test-Path $STIGLog_Cisco) {
            Remove-Item $STIGLog_Cisco -Force
        }

        # Begin logging
        Write-Log $STIGLog_Cisco "Executing: $($CommandLine)" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Cisco "----------------------------------" $LogComponent "Info" -OSPlatform $OSPlatform

        # Verify Evaluate-STIG files integrity
        $Verified = $true
        Write-Log $STIGLog_Cisco "Verifying Evaluate-STIG file integrity..." $LogComponent "Info" -OSPlatform $OSPlatform
        If (Test-Path (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")) {
            [XML]$FileListXML = Get-Content -Path (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")
            If ((Test-XmlSignature -checkxml $FileListXML -Force) -ne $true) {
                Write-Log $STIGLog_Cisco "'FileList.xml' failed authenticity check.  Unable to verify content integrity." $LogComponent "Error" -OSPlatform $OSPlatform
                Write-Host "ERROR: 'FileList.xml' failed authenticity check.  Unable to verify content integrity." -ForegroundColor Red
                ForEach ($File in $FileListXML.FileList.File) {
                    If ($File.ScanReq -eq "Required") {
                        Write-Log $STIGLog_Cisco "'$($File.Name)' is a required file but not found.  Scan results may be incomplete." $LogComponent "Error" -OSPlatform $OSPlatform
                        Write-Host "'$($File.Name)' is a required file but not found.  Scan results may be incomplete." -ForegroundColor Red
                    }
                }
            }
            Else {
                ForEach ($File in $FileListXML.FileList.File) {
                    $Path = (Join-Path -Path $ES_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                    If (Test-Path $Path) {
                        If ((Get-FileHash -Path $Path -Algorithm SHA256).Hash -ne $File.SHA256Hash) {
                            $Verified = $false
                            Write-Log $STIGLog_Cisco "'$($Path)' failed integrity check." $LogComponent "Warning" -OSPlatform $OSPlatform
                        }
                    }
                    Else {
                        If ($File.ScanReq -eq "Required") {
                            $Verified = $false
                            Write-Log $STIGLog_Cisco "'$($File.Name)' is a required file but not found.  Scan results may be incomplete." $LogComponent "Error" -OSPlatform $OSPlatform
                            Write-Host "'$($File.Name)' is a required file but not found.  Scan results may be incomplete." -ForegroundColor Red
                        }
                    }
                }
                If ($Verified -eq $true) {
                    Write-Log $STIGLog_Cisco "Evaluate-STIG file integrity check passed." $LogComponent "Info" -OSPlatform $OSPlatform
                }
                Else {
                    Write-Host "WARNING: One or more Evaluate-STIG files failed integrity check." -ForegroundColor Yellow
                }
            }
        }
        Else {
            Throw "'FileList.xml' not found."
        }

        # XML Schema Files
            $STIGList_xsd = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "Schema_STIGList.xsd"
            $AnswerFile_xsd = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "Schema_AnswerFile.xsd"
            $Checklist_xsd = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "U_Checklist_Schema_V2.xsd"
            If (-Not(Test-Path $STIGList_xsd)) {
                Throw "'$STIGList_xsd' - file not found."
            }
            ElseIf (-Not(Test-Path $AnswerFile_xsd)) {
                Throw "'$AnswerFile_xsd' - file not found."
            }
            ElseIf (-Not(Test-Path $Checklist_xsd)) {
                Throw "'$Checklist_xsd' - file not found."
            }

            # STIGList.xml validation
            $XmlFile = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml"
            If (-Not(Test-Path $XmlFile)) {
                Throw "'$XmlFile' - file not found."
            }
            Else {
                $Result = Test-XmlValidation -XmlFile $XmlFile -SchemaFile $STIGList_xsd
                If ($Result -ne $true) {
                    ForEach ($Item in $Result.Message) {
                        Write-Log $STIGLog_Cisco $Item $LogComponent "Error" -OSPlatform $OSPlatform
                        Write-Host $Item -ForegroundColor Yellow
                    }
                    Throw "'$($XmlFile)' failed XML validation"
                }
            }

        Write-Log $STIGLog_Cisco "Evaluate-STIG Version: $ESVersion" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Cisco "Launching User: $([Environment]::Username)" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Cisco "OS Platform: $OSPlatform" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Cisco "PS Version: $PowerShellVersion" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Cisco "Scan Type: $ScanType" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Cisco "Answer Key: $AnswerKey" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Cisco "Answer File Path: $AFPath" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Cisco "Output Path: $OutputPath" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Cisco "----------------------------------" $LogComponent "Info" -OSPlatform $OSPlatform

        # ++++++++++++++++++++++ Begin processing ++++++++++++++++++++++
        Write-Progress -Id $ProgressId -Activity $ProgressActivity -Status "Initializing and generating list of required STIGs"

        # Check if $ExcludeSTIG, $SelectSTIG, $SelectVuln, or $ExcludeVuln contain a comma and if so, split them.  Needs to be in an array.  Can happen when calling Evaluate-STIG from Powershell.exe -File
        If ($ExcludeSTIG -and $ExcludeSTIG -match ",") {
            $ExcludeSTIG = $ExcludeSTIG -Split ","
        }
        If ($SelectSTIG -and $SelectSTIG -match ",") {
            $SelectSTIG = $SelectSTIG -Split ","
        }
        If ($SelectVuln -and $SelectVuln -match ",") {
            $SelectVuln = $SelectVuln -Split ","
        }
        If ($ExcludeVuln -and $ExcludeVuln -match ",") {
            $ExcludeVuln = $ExcludeVuln -Split ","
        }

        # --- Begin Answer File validation
        Write-Log $STIGLog_Cisco "Validating answer files..." $LogComponent "Info" -OSPlatform $OSPlatform
        $AnswerFileList = New-Object System.Collections.Generic.List[System.Object]
        $XmlFiles = Get-ChildItem -Path $AFPath | Where-Object Extension -EQ ".xml"
        # Verify answer files for proper format...
        ForEach ($Item in $XmlFiles) {
            $Validation = (Test-XmlValidation -XmlFile $Item.FullName -SchemaFile $AnswerFile_xsd)
            If ($Validation -eq $true) {
                Write-Log $STIGLog_Cisco "$($Item.Name) : Passed" $LogComponent "Info" -OSPlatform $OSPlatform
                [XML]$Content = Get-Content $Item.FullName
                If ($Content.STIGComments.Name) {
                    $NewObj = [PSCustomObject]@{
                        STIG          = $Content.STIGComments.Name
                        AnswerFile    = $Item.Name
                        LastWriteTime = $Item.LastWriteTime
                    }
                    $AnswerFileList.Add($NewObj)
                }
            }
            Else {
                Write-Log $STIGLog_Cisco "$($Item.Name) : Error - Answer file failed schema validation and will be ignored.  Please correct or remove." $LogComponent "Error" -OSPlatform $OSPlatform
                Write-Log $STIGLog_Cisco "$($Validation.Message)" $LogComponent "Error" -OSPlatform $OSPlatform
                Write-Host "ERROR: '$($Item.FullName) failed schema validation and will be ignored.  Please correct or remove." -ForegroundColor Red
                Write-Host "$($Validation.Message)" -ForegroundColor Red
                Write-Host ""
            }
        }
        $AnswerFileList = $AnswerFileList | Sort-Object LastWriteTime -Descending
        Write-Log $STIGLog_Cisco "----------------------------------" $LogComponent "Info" -OSPlatform $OSPlatform
        # --- End Answer File validation

        # Build list of valid configs to scan
        [XML]$STIGList = Get-Content (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml")

        If ($SelectSTIG) {
            $STIGsToDetect = $STIGList.List.STIG | Where-Object {($_.ConfigFileScan -in @("$true", "1") -and $_.ShortName -in $SelectSTIG)}
        }
        Else {
            $STIGsToDetect = $STIGList.List.STIG | Where-Object {($_.ConfigFileScan -in @("$true", "1") -and $_.ShortName -notin $ExcludeSTIG)}
        }
        If (-Not($STIGsToDetect)) {
            Throw "No config file based STIGs selected to scan."
        }

        $ConfigFiles = New-Object System.Collections.Generic.List[System.Object]
        Write-Log $STIGLog_Cisco "Looking for supported Cisco files..." $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Host "Refer to '$((Get-Item $env:temp).FullName)\Evaluate-STIG\Evaluate-STIG_Cisco.log' for info on detected files" -ForegroundColor Gray
        ForEach ($Item in $CiscoConfig) {
            [System.GC]::Collect()
            $CurrentSubStep = 1
            Write-Progress $ProgressId -Activity $ProgressActivity -Status "Looking for supported Cisco files in $Item"
            $Files = Get-ChildItem $Item -Recurse -File
            ForEach ($File in $Files.FullName) {
                $TCLOutput = $false
                Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity " " -Status $File -PercentComplete ($CurrentSubStep / $Files.Count * 100)
                $ShowTech = [System.IO.File]::OpenText($File).ReadToEnd() -split "`r`n" -split "`r" -split "`n"
                # If 'show inventory', 'show running-config', and 'show version' sections do not exist then this file isn't a valid show tech-support file.
                If (-Not(($ShowTech | Select-String "^-{18} show inventory -{18}") -and ($ShowTech | Select-String "^-{18} show running-config -{18}") -and ($ShowTech | Select-String "^-{18} show version -{18}"))) {
                    Write-Log $STIGLog_Cisco "Unsupported file : $($File) [Not an output produced by Get-ESCiscoConfig.tcl or 'show tech-support'.]" $LogComponent "Error" -OSPlatform $OSPlatform
                    Continue
                }

                # If this is an Evaluate-STIG TCL output file, get just the Evaluate-STIG section.
                $startSTR = "^-{18} Show Evaluate-STIG Cisco .* -{18}$"
                $endSTR = "^-{18} End Evaluate-STIG Cisco Configuration -{18}$"
                If (($ShowTech | Select-String $startSTR) -and ($ShowTech | Select-String $endSTR)) {
                    $TCLOutput = $true
                    $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber
                    $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber
                    $ShowTech = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                }

                $DeviceInfo = Get-CiscoDeviceInfo -ShowTech $ShowTech
                If (($DeviceInfo).DeviceType -notin @("Router", "Switch")) {
                    Write-Log $STIGLog_Cisco "Unsupported file : $($File) [File is not from a supported device.  Refer to the supported STIGs list.]" $LogComponent "Error" -OSPlatform $OSPlatform
                }
                Else {
                    If ($File -notin $ConfigFiles.File) {
                        If ($TCLOutput -eq $true) {
                            Write-Log $STIGLog_Cisco "Supported TCL file : $($File)" $LogComponent "Info" -OSPlatform $OSPlatform
                        }
                        Else {
                            Write-Log $STIGLog_Cisco "Supported Non-TCL file : $($File) [Please consider generating output with Get-ESCiscoConfig.tcl for maximum compatibility.]" $LogComponent "Warning" -OSPlatform $OSPlatform
                        }
                        $NewObj = [PSCustomObject]@{
                            ShowTech          = $ShowTech
                            DeviceInfo        = $DeviceInfo
                            ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
                            File              = $File
                        }
                        $ConfigFiles.Add($NewObj)
                    }
                }
                $CurrentSubStep++
                Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity " " -Completed
            }
        }
        Write-Log $STIGLog_Cisco "----------------------------------" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Progress -Id $ProgressId -Activity $ProgressActivity -Completed

        # Create runspace pool to include required modules.
        $runspaces = New-Object System.Collections.ArrayList
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ImportPSModule($(Join-Path -Path $ES_Path -ChildPath Modules | Join-Path -ChildPath Master_Functions))
        $SessionState.ImportPSModule($(Join-Path -Path $ES_Path -ChildPath Modules | Join-Path -ChildPath Cisco_Functions))
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $throttlelimit, $SessionState, $Host)
        $RunspacePool.Open()

        ForEach ($Item in $ConfigFiles) {
            # Build arguments hashtable
            $HashArguments = @{
                ShowTech          = $($Item.ShowTech)
                ShowRunningConfig = $($Item.ShowRunningConfig)
                DeviceInfo        = $($Item.DeviceInfo)
                CiscoConfig       = $($Item.File)
                ScanType          = $($ScanType)
                VulnTimeout       = $($VulnTimeout)
                AFPath            = $($AFPath)
                AnswerKey         = $($AnswerKey)
                OutputPath        = $($OutputPath)
                ESVersion         = $($ESVersion)
                LogComponent      = $($LogComponent)
                OSPlatform        = $($OSPlatform)
                ES_Path           = $($ES_Path)
                PowerShellVersion = $($PowerShellVersion)
                CiscoWorkingDir   = $($CiscoWorkingDir)
                Checklist_xsd     = $($Checklist_xsd)
                STIGsToDetect     = $($STIGsToDetect)
                STIGLog_Cisco     = $($STIGLog_Cisco)
                CiscoConfigLog    = $(Join-Path -Path $CiscoScanDir -ChildPath "Evaluate-STIG_Cisco_$(Split-Path $Item.File -Leaf).log")
            }
            If ($Marking) {
                $HashArguments.Add("Marking", $Marking)
            }
            If ($NoPrevious) {
                $HashArguments.Add("NoPrevious", $true)
            }
            If ($SelectVuln) {
                $HashArguments.Add("SelectVuln", $SelectVuln)
            }
            If ($ExcludeVuln) {
                $HashArguments.Add("ExcludeVuln", $ExcludeVuln)
            }
            If ($AnswerFileList) {
                $HashArguments.Add("AnswerFileList", $AnswerFileList)
            }

            $CiscoBlock = {
                Param (
                    # Evaluate-STIG parameters
                    [Parameter(Mandatory = $true)]
                    [psobject]$ShowTech,

                    [Parameter(Mandatory = $true)]
                    [psobject]$ShowRunningConfig,

                    [Parameter(Mandatory = $true)]
                    [psobject]$DeviceInfo,

                    [Parameter(Mandatory = $false)]
                    [ValidateSet("Unclassified", "Classified")]
                    [String]$ScanType = "Unclassified",

                    [Parameter(Mandatory = $false)]
                    [String]$Marking,

                    [Parameter(Mandatory = $false)]
                    [Int]$VulnTimeout = 15,

                    [Parameter(Mandatory = $false)]
                    [ValidateNotNullOrEmpty()]
                    [String]$AFPath,

                    [Parameter(Mandatory = $false)]
                    [String]$AnswerKey = "DEFAULT",

                    [Parameter(Mandatory = $false)]
                    [ValidateNotNullOrEmpty()]
                    [String]$OutputPath,

                    [Parameter(Mandatory = $false)]
                    [Switch]$NoPrevious,

                    [Parameter(Mandatory = $false)]
                    [Array]$SelectVuln,

                    [Parameter(Mandatory = $false)]
                    [Array]$ExcludeVuln,

                    [Parameter(Mandatory = $false)]
                    [Int]$ThrottleLimit = 10,

                    # Config file scan parameters
                    [Parameter(Mandatory = $true)]
                    [String]$ESVersion,

                    [Parameter(Mandatory = $true)]
                    [String]$LogComponent,

                    [Parameter(Mandatory = $true)]
                    [String]$OSPlatform,

                    [Parameter(Mandatory = $true)]
                    [String] $ES_Path,

                    [Parameter(Mandatory = $true)]
                    [String] $PowerShellVersion,

                    [Parameter(Mandatory = $true)]
                    [String] $Checklist_xsd,

                    [Parameter(Mandatory = $true)]
                    [String] $CiscoWorkingDir,

                    [Parameter(Mandatory = $true)]
                    [String] $CiscoConfigLog,

                    [Parameter(Mandatory = $true)]
                    [String] $STIGLog_Cisco,

                    [Parameter(Mandatory = $true)]
                    [String] $CiscoConfig,

                    [Parameter(Mandatory = $true)]
                    [psobject] $STIGsToDetect,

                    [Parameter(Mandatory = $false)]
                    [psobject] $AnswerFileList
                )

                Try {
                    $EvalStart = Get-Date
                    $ScanStartDate = (Get-Date -Format "MM/dd/yyyy")
                    If (Test-Path $CiscoConfigLog) {
                        Remove-Item $CiscoConfigLog -Force
                    }
                    Write-Log $CiscoConfigLog "==========[Begin Config File Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform

                    $ProgressPreference = "SilentlyContinue"
                    [int]$TotalMainSteps = 1
                    [int]$CurrentMainStep = 1

                    $STIGsToProcess = New-Object System.Collections.Generic.List[System.Object]
                    ForEach ($Node in $STIGsToDetect) {
                        If ($Node.DetectionCode -and (Invoke-Expression $Node.DetectionCode) -eq $true) {
                            If ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName -or $_.STIG -eq $Node.Name)}) {
                                $AFtoUse = (($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName -or $_.STIG -eq $Node.Name)})[0]).AnswerFile
                            }
                            Else {
                                $AFtoUse = ""
                            }
                            $NewObj = [PSCustomObject]@{
                                Name           = $Node.Name
                                Shortname      = $Node.ShortName
                                Template       = $Node.Template
                                AnswerFile     = $AFtoUse
                                PsModule       = $Node.PsModule
                                PsModuleVer    = $Node.PsModuleVer
                                Classification = $Node.Classification
                            }
                            $STIGsToProcess.Add($NewObj)
                        }
                    }
                    $CurrentSubStep++

                    [int]$TotalMainSteps = $TotalMainSteps + $STIGsToProcess.Count

                    $MachineName = $DeviceInfo.Hostname
                    $WorkingDir = Join-Path -Path $CiscoWorkingDir -ChildPath $MachineName
                    If (Test-Path $WorkingDir) {
                        Remove-Item $WorkingDir -Recurse -Force
                    }
                    $null = New-Item -Path $WorkingDir -ItemType Directory -ErrorAction Stop

                    If ($SelectVuln) {
                        $ResultsPath = Join-Path -Path $OutputPath -ChildPath "_Partial_$MachineName"
                    }
                    Else {
                        $ResultsPath = Join-Path -Path $OutputPath -ChildPath $MachineName
                    }

                    Write-Log $CiscoConfigLog "Hostname: $MachineName" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $CiscoConfigLog "File: $($CiscoConfig)" $LogComponent "Info" -OSPlatform $OSPlatform

                    $STIGLog = Join-Path -Path $WorkingDir -ChildPath "Evaluate-STIG.log"
                    If ($Marking) {
                        Write-Log $STIGLog "                                                                                          $Marking                                                                                          " $LogComponent "Info" -OSPlatform $OSPlatform
                    }
                    Write-Log $STIGLog "==========[Begin Local Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "Evaluate-STIG Version: $ESVersion" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "Launching User: $([Environment]::Username)" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "Hostname: $MachineName" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "File: $($CiscoConfig)" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "Cisco OS: $($DeviceInfo.CiscoOS) ($($DeviceInfo.CiscoOSVer))" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "Cisco Software: $($DeviceInfo.CiscoSoftware)" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "Cisco Model: $($DeviceInfo.Model)" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "Device Type: $($DeviceInfo.DeviceType)" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "----------------------------------" $LogComponent "Info" -OSPlatform $OSPlatform

                    # Write list of STIGs that will be evaluated to log
                    Write-Log $STIGLog "The following STIGs will be evaluated:" $LogComponent "Info" -OSPlatform $OSPlatform
                    ForEach ($STIG in $STIGsToProcess) {
                        Write-Log $STIGLog "STIG: $($STIG.Name)  |  AnswerFile: $($STIG.AnswerFile)" $LogComponent "Info" -OSPlatform $OSPlatform
                    }
                    Write-Log $STIGLog "----------------------------------" $LogComponent "Info" -OSPlatform $OSPlatform

                    # If no supported STIGs are applicable, log it and continue
                    If ($STIGsToProcess.Count -ne 0) {
                        Write-Log $STIGLog "Applicable STIGs to process - $($STIGsToProcess.Count)" $LogComponent "Info" -OSPlatform $OSPlatform

                        # Start scan
                        ForEach ($Item in $STIGsToProcess) {
                            Write-Log $STIGLog "----------------------------------" $LogComponent "Info" -OSPlatform $OSPlatform
                            Write-Log $STIGLog "Begin processing: $($Item.Name)" $LogComponent "Info" -OSPlatform $OSPlatform
                            [System.GC]::Collect()

                            $ModError = ""
                            Try {
                                [XML]$CKLData = Get-Content -Path (Join-Path -Path $ES_Path -ChildPath "CKLTemplates" | Join-Path -ChildPath $($Item.Template)) -ErrorAction Stop
                                [int]$TotalSubSteps = ($CKLData.CHECKLIST.STIGS.iSTIG.vuln).Count
                                [int]$CurrentSubStep = 1

                                Write-Log $STIGLog "Importing scan module: $($Item.PsModule)" $LogComponent "Info" -OSPlatform $OSPlatform
                                If ($PowerShellVersion -lt [Version]"7.0") {
                                    Import-Module (Join-Path -Path $ES_Path -ChildPath "Modules" | Join-Path -ChildPath $($Item.PsModule)) -Global -ErrorAction Stop
                                }
                                Else {
                                    Import-Module (Join-Path -Path $ES_Path -ChildPath "Modules" | Join-Path -ChildPath $($Item.PsModule)) -Global -SkipEditionCheck -ErrorAction Stop
                                }
                                $PsModule = (Get-Module $Item.PsModule)
                                Write-Log $STIGLog "Module Version: $($PsModule.Version)" $LogComponent "Info" -OSPlatform $OSPlatform
                            }
                            Catch {
                                $ModError = $_.Exception.Message
                            }

                            If ($ModError) {
                                # If module failed to import, display reason, how to resolve, and continue to next STIG.
                                Write-Log $STIGLog "ERROR: $($ModError)" $LogComponent "Error" -OSPlatform $OSPlatform
                                Switch ($Item.Classification) {
                                    {$_ -in @("UNCLASSIFIED")} {
                                        Write-Log $STIGLog "Please run '.\Evaluate-STIG.ps1 -Update' to restore this module or download the 'Evaluate-STIG_$($EvaluateStigVersion).zip from one of these locations:" $LogComponent "Error" -OSPlatform $OSPlatform
                                        Write-Log $STIGLog "(NIPR) https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig/-/releases" $LogComponent "Error" -OSPlatform $OSPlatform
                                        Write-Log $STIGLog "(NIPR) https://intelshare.intelink.gov/sites/NAVSEA-RMF" $LogComponent "Error" -OSPlatform $OSPlatform
                                        Write-Log $STIGLog "(SIPR) https://intelshare.intelink.sgov.gov/sites/NAVSEA-RMF" $LogComponent "Error" -OSPlatform $OSPlatform
                                        Write-Host "ERROR: $($ModError)" -ForegroundColor Red
                                        Write-Host "Please run '.\Evaluate-STIG.ps1 -Update' to restore this module or download the 'Evaluate-STIG_$($EvaluateStigVersion).zip from one of these locations:" -ForegroundColor Red
                                        Write-Host "-  (NIPR) https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig/-/releases" -ForegroundColor Red
                                        Write-Host "-  (NIPR) https://intelshare.intelink.gov/sites/NAVSEA-RMF" -ForegroundColor Red
                                        Write-Host "-  (SIPR) https://intelshare.intelink.sgov.gov/sites/NAVSEA-RMF" -ForegroundColor Red
                                    }
                                    DEFAULT {
                                        Write-Log $STIGLog "Please this download CUI add-on module from:" $LogComponent "Error" -OSPlatform $OSPlatform
                                        Write-Log $STIGLog "(NIPR) https://intelshare.intelink.gov/sites/NAVSEA-RMF" $LogComponent "Error" -OSPlatform $OSPlatform
                                        Write-Log $STIGLog "(SIPR) https://intelshare.intelink.sgov.gov/sites/NAVSEA-RMF" $LogComponent "Error" -OSPlatform $OSPlatform
                                        Write-Host "ERROR: $($ModError)" -ForegroundColor Red
                                        Write-Host "Please download this CUI add-on module from:" -ForegroundColor Red
                                        Write-Host "-  (NIPR) https://intelshare.intelink.gov/sites/NAVSEA-RMF" -ForegroundColor Red
                                        Write-Host "-  (SIPR) https://intelshare.intelink.sgov.gov/sites/NAVSEA-RMF" -ForegroundColor Red
                                    }
                                }
                            }
                            Else {
                                # Generate Checklist
                                Write-Log $STIGLog "Generating checklist and saving to $ResultsPath" $LogComponent "Info" -OSPlatform $OSPlatform
                                If (-Not(Test-Path -Path (Join-Path -Path $ResultsPath -ChildPath "Checklist"))) {
                                    $null = New-Item -Path $ResultsPath -Name "Checklist" -ItemType Directory
                                }

                                $HashArguments = @{
                                    ShowTech           = $($ShowTech)
                                    ShowRunningConfig  = $($ShowRunningConfig)
                                    DeviceInfo         = $($DeviceInfo)
                                    STIGName           = $($Item.Name)
                                    ShortName          = $($Item.ShortName)
                                    TemplateName       = $($Item.Template)
                                    CklSourcePath      = $(Join-Path -Path $ES_Path -ChildPath "CKLTemplates")
                                    CklDestinationPath = $(Join-Path -Path $ResultsPath -ChildPath "Checklist")
                                    ModulesPath        = $(Join-Path -Path $ES_Path -ChildPath "Modules")
                                    ScanStartDate      = $($ScanStartDate)
                                    ScanType           = $($ScanType)
                                    VulnTimeout        = $($VulnTimeout)
                                    AnswerKey          = $($AnswerKey)
                                    WorkingDir         = $($WorkingDir)
                                    Checklist_xsd      = $($Checklist_xsd)
                                    Username           = "NA"
                                    UserSID            = "NA"
                                    OSPlatform         = $($OSPlatform)
                                    ProgressId         = $($ProgressId)
                                    TotalSubSteps      = $($TotalSubSteps)
                                    CurrentSubStep     = $($CurrentSubStep)
                                }
                                If ($PsModule) {
                                    $HashArguments.Add("PsModule", $($PsModule))
                                }
                                If (($Item.AnswerFile) -and (Test-Path -Path (Join-Path -Path $AFPath -ChildPath $($Item.AnswerFile)))) {
                                    $AnswerFileToPass = (Join-Path -Path $AFPath -ChildPath $($Item.AnswerFile))
                                    $HashArguments.Add("AnswerFile", $($AnswerFileToPass))
                                }
                                If ($Marking) {
                                    $HashArguments.Add("Marking", $Marking)
                                }
                                If ($NoPrevious) {
                                    $HashArguments.Add("NoPrevious", $true)
                                }
                                If ($SelectVuln) {
                                    $HashArguments.Add("SelectVuln", $($SelectVuln))
                                }
                                If ($ExcludeVuln) {
                                    $HashArguments.Add("ExcludeVuln", $($ExcludeVuln))
                                }

                                Write-Ckl @HashArguments | Out-Null
                            }
                            $CurrentMainStep++
                        }

                        # Clean up extraneous previous checklists to preserve disk space
                        If (-Not($NoPrevious)) {
                            Write-Log $STIGLog "Clean up extraneous checklist history" $LogComponent "Info" -OSPlatform $OSPlatform
                            $CklHistory = Get-ChildItem -Path (Join-Path -Path $ResultsPath -ChildPath "Checklist" | Join-Path -ChildPath "Previous") -ErrorAction SilentlyContinue | Where-Object PSIsContainer -EQ $true | Select-Object Name, FullName | Sort-Object Name -Descending
                            If ($CklHistory) {
                                $RecentPrevious = $CklHistory[0]
                                ForEach ($Folder in $CklHistory) {
                                    If ($Folder.Name -ne $RecentPrevious.Name) {
                                        Write-Log $STIGLog "Removing $($Folder.Name)" $LogComponent "Info" -OSPlatform $OSPlatform
                                        Remove-Item $Folder.FullName -Recurse -Force -Confirm:$false
                                    }
                                }
                            }

                            # Move non-applicable files to Previous folder
                            Write-Log $STIGLog "Moving non-applicable files to Previous folder" $LogComponent "Info" -OSPlatform $OSPlatform
                            $PreviousFolder = Get-Date -Format yyyy-MM-dd
                            $PreviousPath = Join-Path -Path $ResultsPath -ChildPath "Checklist" | Join-Path -ChildPath "Previous" | Join-Path -ChildPath $PreviousFolder
                            $AllItems = Get-ChildItem -Path $resultsPath -Recurse | Where-Object {(($_.Name -eq "Evaluate-STIG.log" -or $_.Name -like "SummaryReport.*" -or $_.Extension -eq ".ckl") -and $_.FullName -notlike "*Previous*")}
                            ForEach ($Item in $AllItems) {
                                If ($Item.LastWriteTime -lt $EvalStart) {
                                    If ($SelectSTIG -and $Item.Extension -eq ".ckl") {
                                        # Do nothing.  With -SelectSTIG, we leave existing CKLs where they are.
                                    }
                                    Else {
                                        If (-Not(Test-Path -Path $PreviousPath)) {
                                            $null = New-Item -Path (Join-Path -Path $ResultsPath -ChildPath "Checklist") -Name (Join-Path -Path "Previous" -ChildPath $PreviousFolder) -ItemType Directory
                                        }
                                        Write-Log $STIGLog "Moving $($Item.Name) to $PreviousPath" $LogComponent "Info" -OSPlatform $OSPlatform
                                        Move-Item -Path $Item.FullName -Destination $PreviousPath -Force
                                    }
                                }
                            }
                        }
                        Else {
                            # Remove non-applicable files
                            Write-Log $STIGLog "Removing non-applicable files" $LogComponent "Info" -OSPlatform $OSPlatform
                            $AllItems = Get-ChildItem -Path $resultsPath -Recurse | Where-Object {(($_.Name -eq "Evaluate-STIG.log" -or $_.Name -like "SummaryReport.*" -or $_.Extension -eq ".ckl") -and $_.FullName -notlike "*Previous*")}
                            ForEach ($Item in $AllItems) {
                                If ($Item.LastWriteTime -lt $EvalStart) {
                                    If ($SelectSTIG -and $Item.Extension -eq ".ckl") {
                                        # Do nothing.  With -SelectSTIG, we leave existing CKLs where they are.
                                    }
                                    Else {
                                        Write-Log $STIGLog "Removing $($Item.Name)" $LogComponent "Info" -OSPlatform $OSPlatform
                                        Remove-Item -Path $Item.FullName -Force
                                    }
                                }
                            }
                        }

                        # Create summary report
                        Write-Log $STIGLog "Generating summary report" $LogComponent "Info" -OSPlatform $OSPlatform
                        $CurrentMainStep++
                        If ($Marking) {
                            Write-SummaryReport -CklPath (Join-Path -Path $ResultsPath -ChildPath "Checklist") -OutputPath $ResultsPath -ProcessedUser "NA" -Detail -OSPlatform $OSPlatform -ScanStartDate $ScanStartDate -ScanType $ScanType -DeviceInfo $DeviceInfo -Marking $Marking
                        }
                        Else {
                            Write-SummaryReport -CklPath (Join-Path -Path $ResultsPath -ChildPath "Checklist") -OutputPath $ResultsPath -ProcessedUser "NA" -Detail -OSPlatform $OSPlatform -ScanStartDate $ScanStartDate -ScanType $ScanType -DeviceInfo $DeviceInfo
                        }

                        # Create Summary HTML
                        $SummaryFile = Join-Path -Path $ResultsPath -ChildPath SummaryReport.xml
                        [xml]$TempSR = New-Object xml

                        $null = $TempSR.AppendChild($TempSR.CreateElement('Summaries'))
                        $summary = New-Object xml
                        $Summary.Load($SummaryFile)
                        $ImportedSummary = $TempSR.ImportNode($Summary.DocumentElement, $true)
                        $null = $TempSR.DocumentElement.AppendChild($ImportedSummary)

                        $TempSR.Summaries.Summary.Checklists.Checklist | ForEach-Object {
                            $CurrentScoreNode = $_.AppendChild($TempSR.CreateElement('CurrentScore'))
                            $Currentnode = $_.SelectSingleNode("//Summary/Checklists/Checklist[STIG='$($_.STIG)']")
                            $CurrentScore = ([int]$Currentnode.CAT_I.NotAFinding + [int]$Currentnode.CAT_II.NotAFinding + [int]$Currentnode.CAT_III.NotAFinding + [int]$Currentnode.CAT_I.Not_Applicable + [int]$Currentnode.CAT_II.Not_Applicable + [int]$Currentnode.CAT_III.Not_Applicable) / ([int]$Currentnode.CAT_I.Total + [int]$Currentnode.CAT_II.Total + [int]$Currentnode.CAT_III.Total)
                            $CurrentScoreNode.SetAttribute("Score", $CurrentScore)
                        }

                        If ($PreviousPath) {
                            if (Test-Path $(Join-Path -Path $PreviousPath -ChildPath SummaryReport.xml)) {
                                $PreviousSummaryFile = Join-Path -Path $PreviousPath -ChildPath SummaryReport.xml
                                $PreviousSummary = New-Object xml
                                $PreviousSummary.Load($PreviousSummaryFile)

                                $TempSR.Summaries.Summary.Checklists.Checklist | ForEach-Object {
                                    $Previousnode = $PreviousSummary.SelectSingleNode("//Summary/Checklists/Checklist[STIG='$($_.STIG)']")
                                    if ($Previousnode) {
                                        $PreviousScoreNode = $_.AppendChild($TempSR.CreateElement('PreviousScore'))
                                        $PreviousScore = ([int]$Previousnode.CAT_I.NotAFinding + [int]$Previousnode.CAT_II.NotAFinding + [int]$Previousnode.CAT_III.NotAFinding + [int]$Previousnode.CAT_I.Not_Applicable + [int]$Previousnode.CAT_II.Not_Applicable + [int]$Previousnode.CAT_III.Not_Applicable) / ([int]$Previousnode.CAT_I.Total + [int]$Previousnode.CAT_II.Total + [int]$Previousnode.CAT_III.Total)
                                        $PreviousScoreNode.SetAttribute("Delta", ((([float]($_.CurrentScore.Score) * 100) - ([float]($PreviousScore) * 100))) / 100)
                                    }
                                }
                            }
                        }

                        $TempSR.Save($(Join-Path -Path $WorkingDir -ChildPath TempSR.xml))

                        $SummaryReportXLST = New-Object System.XML.Xsl.XslCompiledTransform
                        $SummaryReportXLST.Load($(Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath SummaryReport.xslt))
                        $SummaryReportXLST.Transform($(Join-Path -Path $WorkingDir -ChildPath TempSR.xml), $(Join-Path -Path $ResultsPath -ChildPath SummaryReport.html))

                        If ($Marking) {
                            #Add Marking Header and Footer
                            $SRHTML = $(Join-Path -Path $ResultsPath -ChildPath SummaryReport.html)
                            (Get-Content $SRHTML) -replace "<body>", "<body>`n    <header align=`"center`">$Marking</header>" | Set-Content $SRHTML

                            Add-Content $(Join-Path -Path $ResultsPath -ChildPath SummaryReport.html) "<footer align=`"center`">$Marking</footer>"
                        }
                    }
                    Else {
                        Write-Log $STIGLog "No Evaluate-STIG supported STIGs are applicable to this system." $LogComponent "Warning" -OSPlatform $OSPlatform
                        If (-Not(Test-Path $ResultsPath)) {
                            $null = New-Item $ResultsPath -ItemType Directory -ErrorAction Stop
                        }
                    }

                    Write-Log $CiscoConfigLog "Scan completed" $LogComponent "Info" -OSPlatform $OSPlatform
                    $TotalCKLs = (Get-ChildItem -Path "$OutputPath\$MachineName\Checklist" | Where-Object Extension -EQ '.ckl' | Measure-Object).Count

                    $TimeToComplete = New-TimeSpan -Start $EvalStart -End (Get-Date)
                    $FormatedTime = "{0:c}" -f $TimeToComplete
                    Write-Log $STIGLog "We're done!" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "Total Time : $($FormatedTime)" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "Total CKLs in Results Directory : $($TotalCKLs)" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "==========[End Local Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform
                    If ($Marking) {
                        Write-Log $STIGLog "                                                                                          $Marking                                                                                          " $LogComponent "Info" -OSPlatform $OSPlatform
                    }
                    Write-Log $CiscoConfigLog "Total CKLs - $($TotalCKLs)" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $CiscoConfigLog "Total Time - $($FormatedTime)" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $CiscoConfigLog "==========[End Config File Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform

                    # Copy Evaluate-STIG.log to results path
                    Copy-Item $STIGLog -Destination $ResultsPath

                    Add-Content -Path $STIGLog_Cisco -Value $(Get-Content $CiscoConfigLog)
                    Remove-Item $CiscoConfigLog

                    # Remove temporary files
                    If (Test-Path $(Join-Path -Path $WorkingDir -ChildPath Bad_CKL)) {
                        $TempFiles = Get-Item -Path $WorkingDir\* -Exclude Evaluate-STIG.log, Bad_CKL
                    }
                    Else {
                        $TempFiles = Get-Item -Path $WorkingDir
                    }
                    If ($TempFiles) {
                        ForEach ($Item in $TempFiles) {
                            Try {
                                $null = Remove-Item -Path $Item.FullName -Recurse -ErrorAction Stop
                            }
                            Catch {
                                Write-Log $STIGLog "$($_.Exception.Message)" $LogComponent "Warning" -OSPlatform $OSPlatform
                                Write-Log $CiscoConfigLog "$($_.Exception.Message)" $LogComponent "Warning" -OSPlatform $OSPlatform
                            }
                        }
                    }

                    $ProgressPreference = "Continue"
                }
                Catch {
                    Write-Log $STIGLog "ERROR: $($_.Exception.Message)" $LogComponent "Error" -OSPlatform $OSPlatform
                    Write-Log $STIGLog "Terminated Processing" $LogComponent "Error" -OSPlatform $OSPlatform
                    Write-Log $CiscoConfigLog "ERROR: $($_.Exception.Message)" $LogComponent "Error" -OSPlatform $OSPlatform
                    Write-Log $CiscoConfigLog "Terminated Processing" $LogComponent "Error" -OSPlatform $OSPlatform
                    Write-Log $CiscoConfigLog "==========[End Config File Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform
                }
            }

            $Job = [powershell]::Create().AddScript($CiscoBlock).AddParameters($HashArguments)
            $Job.Streams.ClearStreams()
            $Job.RunspacePool = $RunspacePool

            # Create a temporary collection for each runspace
            $temp = "" | Select-Object Job, Runspace, Hostname
            $Temp.Hostname = $Item.DeviceInfo.Hostname
            $temp.Job = $Job

            # Save the handle output when calling BeginInvoke() that will be used later to end the runspace
            $temp.Runspace = $Job.BeginInvoke()
            $null = $runspaces.Add($temp)
        }

        if (($runspaces | Measure-Object).count -gt 0) {
            Get-RunspaceData -Runspaces $Runspaces -Wait -Usage Cisco
        }

        $RunspacePool.Close()
        $RunspacePool.Dispose()

        $TimeToComplete = New-TimeSpan -Start $ConfigEvalStart -End (Get-Date)
        $FormatedTime = "{0:c}" -f $TimeToComplete
        Write-Host "Done!" -ForegroundColor Green
        Write-Host "Total Time : $($FormatedTime)" -ForegroundColor Green
        Write-Host ""
        Write-Host "Results saved to " -ForegroundColor Green -NoNewline; Write-Host "$($OutputPath)" -ForegroundColor Cyan
        Write-Host ""

        If ($SelectVuln) {
            $CiscoPathArray = @()
            $ConfigFiles | ForEach-Object { $CiscoPathArray += $(Join-Path $OutputPath -ChildPath "_Partial_$($_.DeviceInfo)") }
            $SelectedCiscoVulns = New-Object System.Collections.Generic.List[System.Object]
            $SelectVuln_CKLs = Get-ChildItem -Path (Join-Path $RemotePathArray -ChildPath "Checklist") | Where-Object { ($_.Extension -eq ".ckl") }

            $SelectVuln_CKLs | ForEach-Object {
                $SelectedVulnContent = (Select-Xml -XPath / -Path $_.FullName).Node
                $SelectedCKL_Hostname = $SelectedVulnContent.CHECKLIST.ASSET.HOST_NAME
                $SelectedCKL_STIGName = ($SelectedVulnContent.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA | Where-Object SID_NAME -EQ stigid).SID_DATA
                ForEach ($vuln in $SelectedVulnContent.CHECKLIST.STIGS.iSTIG.VULN) {
                    If (($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Vuln_Num"]/ATTRIBUTE_DATA').InnerText) -in $SelectVuln) {
                        $NewObj = [PSCustomObject]@{
                            Hostname       = $SelectedCKL_Hostname
                            STIGName       = $SelectedCKL_STIGName
                            VulnID         = $Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Vuln_Num"]/ATTRIBUTE_DATA').InnerText
                            Status         = $Vuln.Status
                            Severity       = $Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Severity"]/ATTRIBUTE_DATA').InnerText
                            FindingDetails = $Vuln.FINDING_DETAILS
                            Comments       = $Vuln.COMMENTS
                        }
                        $SelectedCiscoVulns.Add($NewObj) | Out-Null
                    }
                }
            }
        }
    }
    Catch {
        Write-Log $STIGLog_Cisco "    $($_.Exception.Message)" $LogComponent "Error" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Cisco "    $($_.InvocationInfo.ScriptName)" $LogComponent "Error" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Cisco "    Line: $($_.InvocationInfo.ScriptLineNumber)" $LogComponent "Error" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Cisco "    $(($_.InvocationInfo.Line).Trim())" $LogComponent "Error" -OSPlatform $OSPlatform
        Throw $_
    }
}

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAEJLGZ5pw1+ya+
# JG0BaPmWIyiBiiQ4LPL0P5W9PIVsmKCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDIWGL3hJVFWlG+4nrQ/QjcRqWnoATW
# CSmxjzfJNoSG5jANBgkqhkiG9w0BAQEFAASCAQCTyBS2TwdTyejADK9WHBBqINrj
# niFIRht4kKFJCmwCW4Iy83aMJJkcx9Ud90JmZyzUsLtgbwXXZPuyQmkNJV81/iHT
# fWp6pLs8gsT72Hz/naFlPGg3VT4FWKSbEm2m0TqbE0T24H6R6Xx28uJcMlV21ku+
# vC0LodBZkL4FWv/m+Oa3qdkA7s9BJMiQbMiiVaSu14MgPcOPVVoeU2CsdK9C4PCk
# 5u6IczJDxoA3BWxL2dt38A4z3Lno3sO+xBripB7QxFYw+3BqligXwEHuquvrjxRr
# y1xZjP/9Np6tE1GG+ZfQI3DdE/N0ojnU5gGgyJfcXDCIm/qej2SGdoBYnviu
# SIG # End signature block
